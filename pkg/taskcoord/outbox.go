// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// OutboxEventSchemaV1 identifies a backend-internal TaskCoord domain event.
	// It is not a peer protocol document and never contains a direct Human
	// contact address.
	OutboxEventSchemaV1 = "asb.taskcoord-outbox-event/v1"
	// MaxOutboxPayloadBytes bounds the canonical mutation projection retained
	// for at-least-once publication.
	MaxOutboxPayloadBytes = MaxDocumentBytes
)

var (
	// ErrStoreUnavailable means durable state could not be read or committed.
	// Callers must fail closed; a write error can have an unknown commit outcome.
	ErrStoreUnavailable = errors.New("task coordination: durable store unavailable")
	// ErrOutboxConflict means an acknowledgement does not own the current lease.
	ErrOutboxConflict = errors.New("task coordination: outbox lease conflict")
	// ErrOutboxLeaseExpired means the delivery lease is no longer current.
	ErrOutboxLeaseExpired = errors.New("task coordination: outbox lease expired")
	// ErrStoreLimit means a configured durable-history or batch bound was hit.
	ErrStoreLimit = errors.New("task coordination: durable store limit reached")
)

// OutboxEventKind identifies the durable mutation projection to publish.
type OutboxEventKind string

const (
	OutboxAssignmentTransition OutboxEventKind = "ASSIGNMENT_TRANSITION"
	OutboxDelegationCommitted  OutboxEventKind = "DELEGATION_COMMITTED"
	OutboxInteractionAppended  OutboxEventKind = "INTERACTION_APPENDED"
)

// OutboxEvent is written atomically with one newly committed TaskCoord
// mutation. Payload is a canonical Transition, DelegationTransition, or
// InteractionEvent. EventID is the stable downstream deduplication key.
type OutboxEvent struct {
	Schema        string          `json:"schema"`
	EventID       string          `json:"event_id"`
	Kind          OutboxEventKind `json:"kind"`
	TaskID        string          `json:"task_id"`
	AssignmentID  string          `json:"assignment_id"`
	ParticipantID string          `json:"participant_id"`
	Payload       json.RawMessage `json:"payload"`
	PayloadDigest string          `json:"payload_digest"`
	OccurredAt    time.Time       `json:"occurred_at"`
}

// OutboxPoll requests a bounded lease batch. LeaseID must be fresh for each
// poll attempt. A caller receiving an unavailable error must not publish and
// must allow the lease to expire before retrying with a new lease identifier.
type OutboxPoll struct {
	ConsumerID    string
	LeaseID       string
	Limit         uint16
	LeaseDuration time.Duration
}

// OutboxDelivery is one leased domain event. DeliveryID is store-specific and
// must be returned unchanged when acknowledging delivery.
type OutboxDelivery struct {
	DeliveryID string      `json:"delivery_id"`
	LeaseID    string      `json:"lease_id"`
	Event      OutboxEvent `json:"event"`
}

// OutboxAcknowledgement removes one event only when ConsumerID and LeaseID
// still own its unexpired lease. External delivery is at-least-once, so
// consumers must also deduplicate Event.EventID.
type OutboxAcknowledgement struct {
	DeliveryID string
	ConsumerID string
	LeaseID    string
}

// OutboxStore is the backend-neutral delivery half of a transactional outbox.
// Implementations enqueue events inside the same atomic commit that implements
// Store, then lease and acknowledge them separately.
type OutboxStore interface {
	PollOutbox(context.Context, OutboxPoll) ([]OutboxDelivery, error)
	AcknowledgeOutbox(context.Context, OutboxAcknowledgement) error
}

// Validate checks the outbox envelope and its kind-specific payload binding.
func (e OutboxEvent) Validate() error {
	if e.Schema != OutboxEventSchemaV1 {
		return fmt.Errorf("%w: unsupported outbox schema", ErrInvalidEvent)
	}
	for field, value := range map[string]string{
		"event_id": e.EventID, "task_id": e.TaskID,
		"assignment_id": e.AssignmentID, "participant_id": e.ParticipantID,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	if e.OccurredAt.IsZero() || len(e.Payload) == 0 || len(e.Payload) > MaxOutboxPayloadBytes || !json.Valid(e.Payload) {
		return fmt.Errorf("%w: invalid outbox payload", ErrInvalidEvent)
	}
	digest := sha256.Sum256(e.Payload)
	if e.PayloadDigest != hex.EncodeToString(digest[:]) {
		return fmt.Errorf("%w: outbox payload digest mismatch", ErrInvalidEvent)
	}

	switch e.Kind {
	case OutboxAssignmentTransition:
		var transition Transition
		if err := decodeOutboxPayload(e.Payload, &transition); err != nil {
			return err
		}
		if transition.Assignment.Revision == 0 {
			return fmt.Errorf("%w: invalid outbox assignment revision", ErrInvalidEvent)
		}
		if err := ValidateAssignmentCommit(transition.Assignment.Revision-1, transition.Assignment, transition.Record); err != nil {
			return err
		}
		if e.EventID != transition.Record.EventID || e.TaskID != transition.Assignment.TaskID ||
			e.AssignmentID != transition.Assignment.AssignmentID || e.ParticipantID != transition.Assignment.ParticipantID ||
			!e.OccurredAt.Equal(transition.Record.At) {
			return fmt.Errorf("%w: assignment outbox binding mismatch", ErrInvalidEvent)
		}
	case OutboxDelegationCommitted:
		var transition DelegationTransition
		if err := decodeOutboxPayload(e.Payload, &transition); err != nil {
			return err
		}
		if transition.Parent.Revision < 2 {
			return fmt.Errorf("%w: invalid outbox delegation revision", ErrInvalidEvent)
		}
		if err := ValidateDelegationCommit(transition.Parent.Revision-1, transition); err != nil {
			return err
		}
		if e.EventID != transition.Delegation.EventID || e.TaskID != transition.Child.TaskID ||
			e.AssignmentID != transition.Child.AssignmentID || e.ParticipantID != transition.Child.ParticipantID ||
			!e.OccurredAt.Equal(transition.Delegation.At) {
			return fmt.Errorf("%w: delegation outbox binding mismatch", ErrInvalidEvent)
		}
	case OutboxInteractionAppended:
		var event InteractionEvent
		if err := decodeOutboxPayload(e.Payload, &event); err != nil {
			return err
		}
		if err := event.Validate(); err != nil {
			return err
		}
		if e.EventID != event.EventID || e.TaskID != event.TaskID || e.AssignmentID != event.AssignmentID ||
			e.ParticipantID != event.ParticipantID || !e.OccurredAt.Equal(event.At) {
			return fmt.Errorf("%w: interaction outbox binding mismatch", ErrInvalidEvent)
		}
	default:
		return fmt.Errorf("%w: unsupported outbox kind", ErrInvalidEvent)
	}
	return nil
}

// Validate checks a bounded poll request.
func (p OutboxPoll) Validate() error {
	if err := validateID("consumer_id", p.ConsumerID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("lease_id", p.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if p.Limit == 0 || p.LeaseDuration <= 0 || p.LeaseDuration.Milliseconds() < 1 {
		return fmt.Errorf("%w: invalid outbox poll bounds", ErrInvalidEvent)
	}
	return nil
}

// Validate checks an exact acknowledgement tuple.
func (a OutboxAcknowledgement) Validate() error {
	if err := validateID("delivery_id", a.DeliveryID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("consumer_id", a.ConsumerID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("lease_id", a.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	return nil
}

func decodeOutboxPayload(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: decode outbox payload: %v", ErrInvalidEvent, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing outbox payload", ErrInvalidEvent)
	}
	return nil
}
