// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"fmt"
	"time"
)

// Service verifies active grant scope and commits a queued intent. The separate
// trusted Worker dispatches it to an opaque Human gateway session. Neither
// component loads a Human identifier or direct contact endpoint.
type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store, now func() time.Time) (*Service, error) {
	if isNilDependency(store) {
		return nil, ErrMissingStore
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}, nil
}

// Queue consumes an already verified projection and commits one QUEUED relay
// intent. Missing, expired, revoked, inactive, and scope-mismatched grants are
// deliberately collapsed to ErrUnavailable.
func (s *Service) Queue(ctx context.Context, request RelayIntentRequest, auth AuthenticatedRelayIntent) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, invalidRequest("context is required")
	}
	digest, err := RequestDigest(request)
	if err != nil {
		return Receipt{}, err
	}
	if err := auth.Validate(); err != nil {
		return Receipt{}, err
	}
	if auth.RequestDigest != digest.String() {
		return Receipt{}, fmt.Errorf("%w: request digest mismatch", ErrInvalidProjection)
	}
	now := s.now().UTC()
	if now.Before(auth.IssuedAt) || !now.Before(auth.ExpiresAt) {
		return Receipt{}, fmt.Errorf("%w: projection is not currently valid", ErrInvalidProjection)
	}
	return s.store.CommitAuthorizedIntent(ctx, QueueCommit{
		Request: request, Authorization: auth, QueuedAt: now,
	})
}

// Worker is the trusted relay-outbox consumer. It is deliberately separate
// from the Agent-facing Service: Dispatch accepts an internal IntentID and
// must never be mounted as an Agent-reachable route.
type Worker struct {
	store      Store
	dispatcher SessionDispatcher
	now        func() time.Time
}

func NewWorker(store Store, dispatcher SessionDispatcher) (*Worker, error) {
	return NewWorkerWithClock(store, dispatcher, time.Now)
}

// NewWorkerWithClock constructs a Worker with a broker-controlled clock. The
// clock records dispatch reservation and when the broker observes a valid
// provider acknowledgement; provider-supplied timestamps never become durable
// relay state.
func NewWorkerWithClock(store Store, dispatcher SessionDispatcher, now func() time.Time) (*Worker, error) {
	if isNilDependency(store) {
		return nil, ErrMissingStore
	}
	if isNilDependency(dispatcher) {
		return nil, ErrMissingDispatcher
	}
	if now == nil {
		now = time.Now
	}
	return &Worker{store: store, dispatcher: dispatcher, now: now}, nil
}

// Dispatch asks the Store to serialize a fresh reachability check, durable
// DISPATCHING marker, one provider attempt, and any acknowledgement. A
// provider error leaves the intent DISPATCHING because the external outcome
// may be unknown; this Worker never retries that attempt blindly.
func (w *Worker) Dispatch(ctx context.Context, intentID string) (Receipt, error) {
	if ctx == nil {
		return Receipt{}, invalidRequest("context is required")
	}
	return w.store.CommitAuthorizedDispatch(ctx, intentID, w.dispatcher, w.now)
}
