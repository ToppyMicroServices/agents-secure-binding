// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

type memoryRecord struct {
	intent  Intent
	receipt Receipt
	events  []Event
}

// MemoryStore is a concurrency-safe reference outbox. It is not restart
// durable and is not a production database implementation.
type MemoryStore struct {
	directory GrantTransaction
	mu        sync.RWMutex
	records   map[string]memoryRecord
	grantUse  map[string]string
}

var _ Store = (*MemoryStore)(nil)

func NewMemoryStore(directory GrantTransaction) (*MemoryStore, error) {
	if isNilDependency(directory) {
		return nil, ErrMissingDirectory
	}
	return &MemoryStore{
		directory: directory,
		records:   make(map[string]memoryRecord),
		grantUse:  make(map[string]string),
	}, nil
}

// CommitAuthorizedIntent serializes the final active-grant decision with the
// QUEUED intent commit. Exact retries recover the original receipt even after
// the grant is later revoked; they do not create a new operation.
func (s *MemoryStore) CommitAuthorizedIntent(ctx context.Context, commit QueueCommit) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, invalidRequest("context is required")
	}
	if err := validateQueueCommit(commit); err != nil {
		return Receipt{}, err
	}
	queuedEventID, err := relayEventID(StatusQueued, commit.Request.IntentID)
	if err != nil {
		return Receipt{}, err
	}

	s.mu.RLock()
	existing, exists := s.records[commit.Request.IntentID]
	s.mu.RUnlock()
	if exists {
		if sameQueueCommit(existing.intent, commit) && len(existing.events) > 0 &&
			existing.events[0].EventID == queuedEventID &&
			existing.events[0].Status == StatusQueued {
			return existing.receipt, nil
		}
		// Do not reveal that a caller-selected IntentID already exists before
		// the authoritative grant transaction establishes the caller's scope.
		// A valid owner reaches commitIntent and receives ErrIntentConflict;
		// an invalid or foreign grant is collapsed to ErrUnavailable below.
	}

	access := taskcoord.AuthenticatedReachabilityAccess{
		GrantID: commit.Request.GrantID, RequesterParticipantID: commit.Request.RequesterParticipantID,
		Purpose: commit.Request.Purpose, Capability: commit.Request.Capability, Channel: commit.Request.Channel,
		ActorID: commit.Authorization.ActorID, AuthorizationID: commit.Authorization.AuthorizationID,
		ProofID: commit.Authorization.ProofID, VerifierNonce: commit.Authorization.VerifierNonce,
		IssuedAt: commit.Authorization.IssuedAt, ExpiresAt: commit.Authorization.ExpiresAt,
	}
	var receipt Receipt
	commitAttempted := false
	err = s.directory.CommitWithActiveHumanReachabilityGrant(ctx, access, func(grant taskcoord.HumanReachabilityGrant) error {
		commitAttempted = true
		intent := Intent{
			Schema: RelayIntentSchemaV1, IntentID: commit.Request.IntentID, GrantID: commit.Request.GrantID,
			RequesterParticipantID: commit.Request.RequesterParticipantID,
			Purpose:                commit.Request.Purpose, Capability: commit.Request.Capability, Channel: commit.Request.Channel,
			ContentRef: commit.Request.ContentRef, ContentDigest: commit.Request.ContentDigest,
			RelaySessionRef: grant.RelaySessionRef,
			ActorID:         commit.Authorization.ActorID, AuthorizationID: commit.Authorization.AuthorizationID,
			ProofID: commit.Authorization.ProofID, RequestDigest: commit.Authorization.RequestDigest,
			QueuedAt: commit.QueuedAt,
		}
		queued := Event{
			Schema: RelayEventSchemaV1, EventID: queuedEventID,
			IntentID: commit.Request.IntentID, Status: StatusQueued, At: commit.QueuedAt,
		}
		var err error
		receipt, err = s.commitIntent(intent, queued)
		return err
	})
	if err != nil {
		if !commitAttempted {
			return Receipt{}, ErrUnavailable
		}
		return Receipt{}, err
	}
	return receipt, nil
}

func (s *MemoryStore) commitIntent(intent Intent, queued Event) (Receipt, error) {
	if err := intent.Validate(); err != nil {
		return Receipt{}, err
	}
	if err := queued.Validate(); err != nil {
		return Receipt{}, err
	}
	if queued.IntentID != intent.IntentID || queued.Status != StatusQueued || !queued.At.Equal(intent.QueuedAt) {
		return Receipt{}, ErrIntentConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[intent.IntentID]; ok {
		if sameBusinessIntent(existing.intent, intent) && len(existing.events) > 0 &&
			existing.events[0].EventID == queued.EventID && existing.events[0].Status == StatusQueued {
			return existing.receipt, nil
		}
		return Receipt{}, ErrIntentConflict
	}
	if owner, used := s.grantUse[intent.GrantID]; used && owner != intent.IntentID {
		return Receipt{}, ErrGrantConsumed
	}
	receipt := Receipt{
		Schema: RelayReceiptSchemaV1, IntentID: intent.IntentID, GrantID: intent.GrantID,
		Status: StatusQueued, ContentDigest: intent.ContentDigest,
		QueuedAt: intent.QueuedAt, UpdatedAt: intent.QueuedAt,
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	s.records[intent.IntentID] = memoryRecord{intent: intent, receipt: receipt, events: []Event{queued}}
	s.grantUse[intent.GrantID] = intent.IntentID
	return receipt, nil
}

func (s *MemoryStore) LoadIntent(_ context.Context, intentID string) (Intent, Receipt, error) {
	if err := validateID("intent_id", intentID); err != nil {
		return Intent{}, Receipt{}, invalidRequest(err.Error())
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[intentID]
	if !ok {
		return Intent{}, Receipt{}, fmt.Errorf("%w: %s", ErrNotFound, intentID)
	}
	return record.intent, record.receipt, nil
}

// CommitAuthorizedDispatch serializes the final active-grant decision with a
// durable dispatch reservation and the one allowed provider callback. The
// MemoryStore and MemoryReachabilityDirectory locks remain held through the
// callback; dispatchers must therefore not re-enter either component.
//
// When reachability is unavailable before the callback, the store records
// CANCELED and returns without invoking the provider. Once DISPATCHING is
// durable, a provider error or invalid acknowledgement leaves that state in
// place because the external outcome may be unknown. This reference worker
// never blindly invokes the provider a second time.
func (s *MemoryStore) CommitAuthorizedDispatch(
	ctx context.Context,
	intentID string,
	dispatcher SessionDispatcher,
	now func() time.Time,
) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, invalidRequest("context is required")
	}
	if err := validateID("intent_id", intentID); err != nil {
		return Receipt{}, invalidRequest(err.Error())
	}
	if isNilDependency(dispatcher) {
		return Receipt{}, ErrMissingDispatcher
	}
	if now == nil {
		return Receipt{}, ErrDispatchConflict
	}

	s.mu.RLock()
	record, ok := s.records[intentID]
	s.mu.RUnlock()
	if !ok {
		return Receipt{}, fmt.Errorf("%w: %s", ErrNotFound, intentID)
	}
	if record.receipt.Status != StatusQueued {
		return record.receipt, nil
	}

	access := taskcoord.HumanReachabilityDispatchAccess{
		GrantID:                record.intent.GrantID,
		RequesterParticipantID: record.intent.RequesterParticipantID,
		Purpose:                record.intent.Purpose,
		Capability:             record.intent.Capability,
		Channel:                record.intent.Channel,
	}
	result := record.receipt
	err := s.directory.CommitWithActiveHumanReachabilityGrantForDispatch(
		ctx,
		access,
		func(grant taskcoord.HumanReachabilityGrant) error {
			s.mu.Lock()
			defer s.mu.Unlock()

			current, exists := s.records[intentID]
			if !exists {
				return fmt.Errorf("%w: %s", ErrNotFound, intentID)
			}
			result = current.receipt
			if current.receipt.Status != StatusQueued {
				return nil
			}
			if grant.GrantID != current.intent.GrantID ||
				grant.RequesterParticipantID != current.intent.RequesterParticipantID ||
				grant.Purpose != current.intent.Purpose ||
				grant.Capability != current.intent.Capability ||
				grant.Channel != current.intent.Channel ||
				grant.RelaySessionRef != current.intent.RelaySessionRef {
				return ErrDispatchConflict
			}

			dispatchingAt := now().UTC()
			if dispatchingAt.IsZero() || dispatchingAt.Before(current.intent.QueuedAt) {
				return ErrDispatchConflict
			}
			dispatchingID, idErr := relayEventID(StatusDispatching, intentID)
			if idErr != nil {
				return idErr
			}
			dispatching := Event{
				Schema: RelayEventSchemaV1, EventID: dispatchingID,
				IntentID: intentID, Status: StatusDispatching, At: dispatchingAt,
			}
			if eventErr := dispatching.Validate(); eventErr != nil {
				return eventErr
			}
			current.receipt.Status = StatusDispatching
			current.receipt.UpdatedAt = dispatchingAt
			if receiptErr := current.receipt.Validate(); receiptErr != nil {
				return receiptErr
			}
			current.events = append(current.events, dispatching)
			s.records[intentID] = current
			result = current.receipt

			ack, dispatchErr := dispatcher.Dispatch(ctx, DispatchRequest{
				IntentID: current.intent.IntentID, RelaySessionRef: current.intent.RelaySessionRef,
				Channel: current.intent.Channel, ContentRef: current.intent.ContentRef,
				ContentDigest: current.intent.ContentDigest,
			})
			if dispatchErr != nil {
				// Provider and contact-resolution errors are private gateway
				// telemetry and must not cross the relay boundary.
				return ErrDispatchUnavailable
			}
			if ack.IntentID != current.intent.IntentID {
				return ErrDispatchConflict
			}
			if ackErr := validateID("provider_ack_ref", ack.AckRef); ackErr != nil {
				return ErrDispatchConflict
			}

			acknowledgedAt := now().UTC()
			if acknowledgedAt.IsZero() || acknowledgedAt.Before(current.receipt.UpdatedAt) {
				return ErrDispatchConflict
			}
			acknowledgedID, idErr := relayEventID(StatusProviderAcknowledged, intentID)
			if idErr != nil {
				return idErr
			}
			acknowledged := Event{
				Schema: RelayEventSchemaV1, EventID: acknowledgedID,
				IntentID: intentID, Status: StatusProviderAcknowledged,
				At: acknowledgedAt, ProviderAckRef: ack.AckRef,
			}
			if eventErr := acknowledged.Validate(); eventErr != nil {
				return ErrDispatchConflict
			}
			current.receipt.Status = StatusProviderAcknowledged
			current.receipt.UpdatedAt = acknowledgedAt
			if receiptErr := current.receipt.Validate(); receiptErr != nil {
				return ErrDispatchConflict
			}
			current.events = append(current.events, acknowledged)
			s.records[intentID] = current
			result = current.receipt
			return nil
		},
	)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, taskcoord.ErrNotFound) {
		return s.cancelQueuedIntent(intentID, now)
	}
	return result, err
}

// cancelQueuedIntent records a zero-provider-call cancellation only after the
// authoritative dispatch transaction reports that reachability is unavailable.
// A concurrent or prior dispatch state always wins over cancellation.
func (s *MemoryStore) cancelQueuedIntent(intentID string, now func() time.Time) (Receipt, error) {
	canceledID, err := relayEventID(StatusCanceled, intentID)
	if err != nil {
		return Receipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[intentID]
	if !ok {
		return Receipt{}, fmt.Errorf("%w: %s", ErrNotFound, intentID)
	}
	if record.receipt.Status != StatusQueued {
		return record.receipt, nil
	}
	canceledAt := now().UTC()
	if canceledAt.IsZero() || canceledAt.Before(record.intent.QueuedAt) {
		return record.receipt, ErrDispatchConflict
	}
	canceled := Event{
		Schema: RelayEventSchemaV1, EventID: canceledID,
		IntentID: intentID, Status: StatusCanceled, At: canceledAt,
	}
	if err := canceled.Validate(); err != nil {
		return record.receipt, err
	}
	record.receipt.Status = StatusCanceled
	record.receipt.UpdatedAt = canceledAt
	if err := record.receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	record.events = append(record.events, canceled)
	s.records[intentID] = record
	return record.receipt, nil
}

// Events returns a detached audit sequence for tests and local inspection.
func (s *MemoryStore) Events(intentID string) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[intentID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, intentID)
	}
	return append([]Event(nil), record.events...), nil
}

func sameJSON(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

// sameBusinessIntent excludes verifier proof identifiers and queue time. A
// fresh ASB proof for the same exact request may recover the first receipt
// after a lost response, while any change to routing or content conflicts.
func sameBusinessIntent(left, right Intent) bool {
	return left.Schema == right.Schema &&
		left.IntentID == right.IntentID &&
		left.GrantID == right.GrantID &&
		left.RequesterParticipantID == right.RequesterParticipantID &&
		left.Purpose == right.Purpose &&
		left.Capability == right.Capability &&
		left.Channel == right.Channel &&
		left.ContentRef == right.ContentRef &&
		left.ContentDigest == right.ContentDigest &&
		left.RelaySessionRef == right.RelaySessionRef &&
		left.RequestDigest == right.RequestDigest
}

func sameQueueCommit(existing Intent, commit QueueCommit) bool {
	return existing.Schema == RelayIntentSchemaV1 &&
		existing.IntentID == commit.Request.IntentID &&
		existing.GrantID == commit.Request.GrantID &&
		existing.RequesterParticipantID == commit.Request.RequesterParticipantID &&
		existing.Purpose == commit.Request.Purpose &&
		existing.Capability == commit.Request.Capability &&
		existing.Channel == commit.Request.Channel &&
		existing.ContentRef == commit.Request.ContentRef &&
		existing.ContentDigest == commit.Request.ContentDigest &&
		existing.RequestDigest == commit.Authorization.RequestDigest
}

func validateQueueCommit(commit QueueCommit) error {
	if err := commit.Request.Validate(); err != nil {
		return err
	}
	if err := commit.Authorization.Validate(); err != nil {
		return err
	}
	digest, err := RequestDigest(commit.Request)
	if err != nil {
		return err
	}
	if commit.Authorization.RequestDigest != digest.String() {
		return fmt.Errorf("%w: request digest mismatch", ErrInvalidProjection)
	}
	if commit.QueuedAt.IsZero() || commit.QueuedAt.Before(commit.Authorization.IssuedAt) ||
		!commit.QueuedAt.Before(commit.Authorization.ExpiresAt) {
		return fmt.Errorf("%w: projection is not valid at queue time", ErrInvalidProjection)
	}
	return nil
}
