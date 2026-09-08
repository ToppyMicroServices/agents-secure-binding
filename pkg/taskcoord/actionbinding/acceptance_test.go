// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestServiceAcceptRejectsMissingAndTamperedAuthentication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-auth", "task:accept-auth", "human:owner", at)
	other := acceptedAssignment(t, "assignment:accept-other", "task:accept-other", "human:other", at)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:authenticated",
		ActionID:     "action:accept:authenticated",
		ActionDigest: "sha256:" + strings.Repeat("a", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 2,
			IdempotencyKey: "idempotency:accept:authenticated",
		},
	}

	newService := func(t *testing.T) (*MemoryStore, *Service) {
		t.Helper()
		store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment, other}, nil, func() time.Time { return at.Add(time.Second) })
		if err != nil {
			t.Fatal(err)
		}
		service, err := NewService(store, func() time.Time { return at.Add(time.Second) })
		if err != nil {
			t.Fatal(err)
		}
		return store, service
	}

	store, service := newService(t)
	if _, err := service.Accept(ctx, request); !errors.Is(err, actionlifecycle.ErrAuthenticationRequired) {
		t.Fatalf("missing authentication error = %v", err)
	}
	if _, err := store.Load(ctx, request.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing-auth acceptance wrote Action: %v", err)
	}

	bindTestAcceptance(t, assignment, at.Add(time.Second), &request)
	tests := map[string]func(*AcceptRequest){
		"assignment": func(candidate *AcceptRequest) { candidate.AssignmentID = other.AssignmentID },
		"event":      func(candidate *AcceptRequest) { candidate.EventID += ":substituted" },
		"action":     func(candidate *AcceptRequest) { candidate.ActionID += ":substituted" },
		"digest": func(candidate *AcceptRequest) {
			candidate.ActionDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"recovery mode": func(candidate *AcceptRequest) {
			candidate.RecoveryPolicy.Mode = actionlifecycle.RecoveryManual
			candidate.RecoveryPolicy.IdempotencyKey = ""
		},
		"recovery attempts": func(candidate *AcceptRequest) { candidate.RecoveryPolicy.MaxAttempts++ },
		"idempotency key": func(candidate *AcceptRequest) {
			candidate.RecoveryPolicy.IdempotencyKey += ":substituted"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, service := newService(t)
			candidate := request
			auth := *request.Auth
			candidate.Auth = &auth
			mutate(&candidate)
			if _, err := service.Accept(ctx, candidate); err == nil {
				t.Fatal("tampered acceptance succeeded")
			}
		})
	}
}

func TestAcceptanceDigestBindsTrustedAssignmentProjection(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:digest", "task:digest", "human:digest", at)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:digest",
		ActionID: "action:accept:digest", ActionDigest: "sha256:" + strings.Repeat("c", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1},
	}
	want, err := AcceptanceRequestDigest(assignment, request)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*taskcoord.Assignment){
		"revision": func(candidate *taskcoord.Assignment) {
			candidate.Revision++
			candidate.LastTransition.Revision++
		},
		"task": func(candidate *taskcoord.Assignment) {
			candidate.TaskID += ":changed"
			candidate.LastTransition.TaskID = candidate.TaskID
		},
		"participant": func(candidate *taskcoord.Assignment) {
			candidate.ParticipantID += ":changed"
			candidate.LastTransition.ParticipantID = candidate.ParticipantID
		},
		"role": func(candidate *taskcoord.Assignment) { candidate.Role = taskcoord.RoleReviewer },
		"authority": func(candidate *taskcoord.Assignment) {
			candidate.AuthorityDigest = strings.Repeat("d", 64)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := assignment
			mutate(&candidate)
			got, err := AcceptanceRequestDigest(candidate, request)
			if err != nil {
				t.Fatalf("changed valid Assignment rejected: %v", err)
			}
			if got == want {
				t.Fatal("trusted Assignment change did not alter acceptance digest")
			}
		})
	}
}

func TestServiceAndStoreRejectExpiredAcceptance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-expiry", "task:accept-expiry", "agent:owner", at)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:expiry",
		ActionID: "action:accept:expiry", ActionDigest: "sha256:" + strings.Repeat("e", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1},
	}
	serviceAt := at.Add(time.Second)
	bindTestAcceptance(t, assignment, serviceAt, &request)

	expired := request
	expiredAuth := *request.Auth
	expired.Auth = &expiredAuth
	expired.Auth.ExpiresAt = serviceAt
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return serviceAt })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return serviceAt })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Accept(ctx, expired); err == nil {
		t.Fatal("service accepted an expired acceptance authorization")
	}

	clock := serviceAt
	inner, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	delayed := &acceptanceDelayStore{MemoryStore: inner, beforeCommit: func() { clock = request.Auth.ExpiresAt }}
	service, err = NewService(delayed, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Accept(ctx, request); err == nil {
		t.Fatal("Store accepted authorization that expired before commit")
	}
	if _, err := inner.Load(ctx, request.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired commit wrote Action: %v", err)
	}
	if _, err := inner.LoadBinding(ctx, request.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired commit wrote Binding: %v", err)
	}
}

func TestServiceAcceptRejectsAssignmentChangeBeforeCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 10, 30, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-race", "task:accept-race", "agent:owner", at)
	released, err := taskcoord.Apply(assignment, taskEvent(assignment, taskcoord.OperationRelease, at.Add(2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	clock := at.Add(time.Second)
	inner, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	store := &acceptanceDelayStore{MemoryStore: inner, beforeCommit: func() {
		inner.mu.Lock()
		inner.assignments[assignment.AssignmentID] = cloneAssignment(released.Assignment)
		inner.mu.Unlock()
	}}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:race",
		ActionID: "action:accept:race", ActionDigest: "sha256:" + strings.Repeat("9", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1},
	}
	bindTestAcceptance(t, assignment, clock, &request)
	if _, err := service.Accept(ctx, request); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("assignment race error = %v", err)
	}
	if _, err := inner.Load(ctx, request.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("assignment race wrote Action: %v", err)
	}
}

func TestMemoryStoreCommitAcceptanceValidatesBeforeDeduplication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 1, 11, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-store", "task:accept-store", "agent:owner", at)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:store",
		ActionID: "action:accept:store", ActionDigest: "sha256:" + strings.Repeat("f", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1},
	}
	acceptedAt := at.Add(time.Second)
	bindTestAcceptance(t, assignment, acceptedAt, &request)
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return acceptedAt })
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CommitAcceptance(ctx, assignment.Revision, assignment, request)
	if err != nil {
		t.Fatalf("initial commit: %v", err)
	}
	retry, err := store.CommitAcceptance(ctx, assignment.Revision, assignment, request)
	if err != nil {
		t.Fatalf("exact authenticated retry: %v", err)
	}
	if !sameJSON(retry, first) {
		t.Fatalf("exact retry returned a different View: %+v, want %+v", retry, first)
	}
	missing := request
	missing.Auth = nil
	if _, err := store.CommitAcceptance(ctx, assignment.Revision, assignment, missing); !errors.Is(err, actionlifecycle.ErrAuthenticationRequired) {
		t.Fatalf("dedup bypass with missing auth error = %v", err)
	}
	tampered := request
	tamperedAuth := *request.Auth
	tampered.Auth = &tamperedAuth
	tampered.Auth.MutationDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := store.CommitAcceptance(ctx, assignment.Revision, assignment, tampered); !errors.Is(err, actionlifecycle.ErrInvalidEvent) {
		t.Fatalf("dedup bypass with tampered auth error = %v", err)
	}
}

func TestServiceAcceptExactAttemptRetryReturnsCanonicalViewAfterExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-retry", "task:accept-retry", "agent:owner", base)
	clock := base.Add(time.Second)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:retry",
		ActionID:     "action:accept:retry",
		ActionDigest: "sha256:" + strings.Repeat("1", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 2,
			IdempotencyKey: "idempotency:accept:retry",
		},
	}
	bindTestAcceptance(t, assignment, clock, &request)
	first, err := service.Accept(ctx, request)
	if err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	if !first.Action.CreatedAt.Equal(clock) || !first.Binding.CreatedAt.Equal(clock) {
		t.Fatalf("first transaction timestamp = %v/%v, want %v", first.Action.CreatedAt, first.Binding.CreatedAt, clock)
	}

	releaseAt := clock.Add(time.Second)
	released, err := taskcoord.Apply(assignment, taskEvent(assignment, taskcoord.OperationRelease, releaseAt))
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.assignments[assignment.AssignmentID] = cloneAssignment(released.Assignment)
	store.mu.Unlock()
	clock = request.Auth.ExpiresAt.Add(time.Hour)

	retry, err := service.Accept(ctx, request)
	if err != nil {
		t.Fatalf("expired exact retry error = %v", err)
	}
	if !sameJSON(retry, first) {
		t.Fatalf("canonical retry changed:\nfirst: %+v\nretry: %+v", first, retry)
	}
	if retry.Assignment.Status != taskcoord.AssignmentAccepted || retry.Assignment.Revision != assignment.Revision {
		t.Fatalf("retry returned current rather than committed Assignment: %+v", retry.Assignment)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.actions) != 1 || len(store.bindings) != 1 || len(store.events) != 1 {
		t.Fatalf("retry records = actions:%d bindings:%d events:%d", len(store.actions), len(store.bindings), len(store.events))
	}
}

func TestServiceAcceptExpiredAttemptCannotCreateState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 30, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:accept-expired-new", "task:accept-expired-new", "agent:owner", base)
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:expired-new",
		ActionID:     "action:accept:expired-new",
		ActionDigest: "sha256:" + strings.Repeat("2", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1,
		},
	}
	authorizedAt := base.Add(time.Second)
	bindTestAcceptance(t, assignment, authorizedAt, &request)
	clock := request.Auth.ExpiresAt
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Accept(ctx, request); !errors.Is(err, actionlifecycle.ErrInvalidEvent) {
		t.Fatalf("expired new acceptance error = %v, want %v", err, actionlifecycle.ErrInvalidEvent)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.actions) != 0 || len(store.bindings) != 0 || len(store.events) != 0 || len(store.actionByAssignment) != 0 {
		t.Fatalf(
			"expired acceptance wrote state: actions:%d bindings:%d events:%d indexes:%d",
			len(store.actions), len(store.bindings), len(store.events), len(store.actionByAssignment),
		)
	}
}

func TestServiceAcceptDifferentProofRequiresReconciliation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	clock := base.Add(time.Second)
	assignment := acceptedAssignment(t, "assignment:accept-cross-proof", "task:accept-cross-proof", "agent:owner", base)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:cross-proof",
		ActionID:     "action:accept:cross-proof",
		ActionDigest: "sha256:" + strings.Repeat("3", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1,
		},
	}
	bindTestAcceptance(t, assignment, clock, &request)
	first, err := service.Accept(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	missing := request
	missing.Auth = nil
	if _, err := service.Accept(ctx, missing); !errors.Is(err, actionlifecycle.ErrAuthenticationRequired) {
		t.Fatalf("missing-auth retry error = %v, want %v", err, actionlifecycle.ErrAuthenticationRequired)
	}
	tampered := request
	tamperedAuth := *request.Auth
	tampered.Auth = &tamperedAuth
	tampered.Auth.MutationDigest = "sha256:" + strings.Repeat("9", 64)
	if _, err := service.Accept(ctx, tampered); !errors.Is(err, actionlifecycle.ErrInvalidEvent) {
		t.Fatalf("tampered-auth retry error = %v, want %v", err, actionlifecycle.ErrInvalidEvent)
	}
	fresh := request
	freshAuth := *request.Auth
	fresh.Auth = &freshAuth
	fresh.Auth.AuthorizationID += ":fresh"
	fresh.Auth.ProofID += ":fresh"
	fresh.Auth.VerifierNonce += ":fresh"
	fresh.Auth.IssuedAt = clock
	fresh.Auth.ExpiresAt = clock.Add(15 * time.Minute)
	clock = clock.Add(time.Second)
	if _, err := service.Accept(ctx, fresh); !errors.Is(err, ErrAcceptanceReconciliationRequired) {
		t.Fatalf("fresh-proof retry error = %v, want %v", err, ErrAcceptanceReconciliationRequired)
	}
	stored, err := store.Load(ctx, request.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJSON(stored, first.Action) {
		t.Fatalf("fresh proof changed first Action: %+v", stored)
	}
}

func TestServiceAcceptRejectsConflictingBusinessRetry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 13, 30, 0, 0, time.UTC)
	clock := base.Add(time.Second)
	assignment := acceptedAssignment(t, "assignment:accept-conflict", "task:accept-conflict", "agent:owner", base)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:conflict",
		ActionID:     "action:accept:conflict",
		ActionDigest: "sha256:" + strings.Repeat("4", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1,
		},
	}
	bindTestAcceptance(t, assignment, clock, &request)
	if _, err := service.Accept(ctx, request); err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.ActionDigest = "sha256:" + strings.Repeat("5", 64)
	bindTestAcceptance(t, assignment, clock, &changed)
	if _, err := service.Accept(ctx, changed); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("changed business retry error = %v, want %v", err, ErrEventConflict)
	}
}

func TestServiceAcceptExactRetryRejectsPartialOutcome(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	clock := base.Add(time.Second)
	assignment := acceptedAssignment(t, "assignment:accept-partial", "task:accept-partial", "agent:owner", base)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:partial",
		ActionID:     "action:accept:partial",
		ActionDigest: "sha256:" + strings.Repeat("6", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1,
		},
	}
	bindTestAcceptance(t, assignment, clock, &request)
	if _, err := service.Accept(ctx, request); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	delete(store.bindings, request.ActionID)
	store.mu.Unlock()
	if _, err := service.Accept(ctx, request); !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("partial retry error = %v, want %v", err, ErrStoreConflict)
	}
}

type acceptanceDelayStore struct {
	*MemoryStore
	beforeCommit func()
}

func (s *acceptanceDelayStore) CommitAcceptance(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	request AcceptRequest,
) (View, error) {
	if s.beforeCommit != nil {
		s.beforeCommit()
	}
	return s.MemoryStore.CommitAcceptance(ctx, expectedAssignmentRevision, assignment, request)
}
