// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"time"
)

// ProviderReconciler performs an authenticated, read-only query to the same
// configured provider that received Dispatch. It must check the complete
// request binding before returning found=true. A missing, pending, expired or
// unavailable provider record is NOT evidence that dispatch never happened.
// Lookup must honor context cancellation and must never send/redeliver content.
// This interface is a trusted deployment adapter, not a peer JSON endpoint.
type ProviderReconciler interface {
	Lookup(context.Context, DispatchRequest) (ack ProviderAck, found bool, err error)
}

// ReconciliationStore is an optional extension of Store. Recovery can only
// append an acknowledgement to DISPATCHING. It cannot reset dispatch, cancel
// an attempted delivery, replace a terminal outcome or release grant reuse.
type ReconciliationStore interface {
	ReconcileDispatch(context.Context, string, ProviderReconciler, func() time.Time) (Receipt, error)
}

// Reconcile queries historical provider evidence for an unknown attempt. Like
// Dispatch, it belongs to a trusted internal worker, never an Agent route.
func (w *Worker) Reconcile(ctx context.Context, intentID string, provider ProviderReconciler) (Receipt, error) {
	store, ok := w.store.(ReconciliationStore)
	if !ok || isNilDependency(provider) {
		return Receipt{}, ErrReconcileUnavailable
	}
	return store.ReconcileDispatch(ctx, intentID, provider, w.now)
}

func (s *MemoryStore) ReconcileDispatch(ctx context.Context, intentID string, provider ProviderReconciler, now func() time.Time) (Receipt, error) {
	if ctx == nil || now == nil || validateID("intent_id", intentID) != nil {
		return Receipt{}, ErrDispatchConflict
	}
	if isNilDependency(provider) {
		return Receipt{}, ErrReconcileUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[intentID]
	if !ok {
		return Receipt{}, ErrNotFound
	}
	if record.receipt.Status != StatusDispatching {
		return record.receipt, nil
	}
	ack, found, err := provider.Lookup(ctx, dispatchRequest(record.intent))
	if err != nil || ctx.Err() != nil {
		return record.receipt, ErrReconcileUnavailable
	}
	if !found {
		return record.receipt, nil
	}
	if ack.IntentID != intentID || validateID("provider_ack_ref", ack.AckRef) != nil {
		return record.receipt, ErrDispatchConflict
	}
	at := now().UTC()
	if at.IsZero() || at.Before(record.receipt.UpdatedAt) {
		return record.receipt, ErrDispatchConflict
	}
	id, err := relayEventID(StatusProviderAcknowledged, intentID)
	if err != nil {
		return record.receipt, err
	}
	event := Event{
		Schema: RelayEventSchemaV1, EventID: id, IntentID: intentID,
		Status: StatusProviderAcknowledged, At: at, ProviderAckRef: ack.AckRef,
	}
	if err := event.Validate(); err != nil {
		return record.receipt, ErrDispatchConflict
	}
	next := record
	next.events = append(append([]Event(nil), record.events...), event)
	next.receipt.Status, next.receipt.UpdatedAt = StatusProviderAcknowledged, at
	if err := s.commitRecord(intentID, next); err != nil {
		return record.receipt, err
	}
	return next.receipt, nil
}

func dispatchRequest(intent Intent) DispatchRequest {
	return DispatchRequest{
		IntentID: intent.IntentID, RelaySessionRef: intent.RelaySessionRef,
		Channel: intent.Channel, ContentRef: intent.ContentRef, ContentDigest: intent.ContentDigest,
	}
}

// Lookup returns exact synthetic gateway evidence without sending a message.
// LocalGatewaySink remains an in-process test adapter, not a durable provider.
func (s *LocalGatewaySink) Lookup(ctx context.Context, request DispatchRequest) (ProviderAck, bool, error) {
	if ctx == nil {
		return ProviderAck{}, false, ErrReconcileUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ProviderAck{}, false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing, found := s.requests[request.IntentID]
	if !found {
		return ProviderAck{}, false, nil
	}
	if !sameJSON(existing, request) {
		return ProviderAck{}, false, ErrDispatchConflict
	}
	return s.acks[request.IntentID], true, nil
}
