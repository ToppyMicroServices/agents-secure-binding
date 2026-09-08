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

func TestMemoryStoreReappliesAuthorizedEventBeforeCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	clock := at.Add(2 * time.Second)
	assignment := acceptedAssignment(t, "assignment:forged", "task:forged", "agent:owner", at)
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	view, err := acceptWithTestAuth(t, service, ctx, assignment, clock, AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:forged",
		ActionID:     "action:forged",
		ActionDigest: "sha256:" + strings.Repeat("a", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:forged",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := authenticatedActionEvent(view.Action, actionlifecycle.EventComplete, at.Add(3*time.Second), "agent:owner")
	event.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonCompleted}
	event.ResultRef = "urn:result:forged"
	bindActionEvent(t, &event)
	record := actionlifecycle.TransitionRecord{
		EventID: event.ID, Kind: event.Kind, From: actionlifecycle.StateAccepted,
		To: actionlifecycle.StateSucceeded, Reason: event.Reason, At: event.At,
		ActorID: event.Auth.ActorID, AuthorizationID: event.Auth.AuthorizationID,
		ProofID: event.Auth.ProofID, MutationDigest: event.Auth.MutationDigest,
	}
	next := cloneAction(view.Action)
	next.Revision++
	next.State = actionlifecycle.StateSucceeded
	next.Reason = event.Reason
	next.UpdatedAt = event.At
	next.Outcome = &actionlifecycle.Outcome{
		Status: actionlifecycle.OutcomeSucceeded, ResultRef: event.ResultRef, RecordedAt: event.At,
	}
	next.LastTransition = record
	forged := actionlifecycle.Transition{Snapshot: next, Record: record}
	if err := validateTransition(forged); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("structural validation error = %v, want %v", err, ErrInvalidBinding)
	}
	if _, err := actionlifecycle.Apply(view.Action, event); !errors.Is(err, actionlifecycle.ErrInvalidTransition) {
		t.Fatalf("state machine unexpectedly accepted forged edge: %v", err)
	}

	clock = event.At
	if err := store.CommitAuthorizedTransition(ctx, view.Action.Revision, view.Action, event, forged); !errors.Is(err, actionlifecycle.ErrInvalidTransition) {
		t.Fatalf("forged authorized transition error = %v", err)
	}
	assertActionState(t, store, view.Action.ActionID, actionlifecycle.StateAccepted, view.Action.Revision)
}

func TestMemoryStoreReappliesExecutionEventBeforeCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	clock := at.Add(2 * time.Second)
	assignment := acceptedAssignment(t, "assignment:event-execution", "task:event-execution", "agent:owner", at)
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	view, err := acceptWithTestAuth(t, service, ctx, assignment, clock, AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:event-execution",
		ActionID:     "action:event-execution",
		ActionDigest: "sha256:" + strings.Repeat("b", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:event-execution",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := authenticatedActionEvent(view.Action, actionlifecycle.EventStart, at.Add(3*time.Second), "executor:event-execution")
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = lease(view.Action.LeaseGeneration+1, start.Auth.ActorID, start.At)
	bindActionEvent(t, &start)
	transition, err := actionlifecycle.Apply(view.Action, start)
	if err != nil {
		t.Fatal(err)
	}
	substituted := cloneEvent(start)
	substituted.Auth.AuthorizationID += ":substituted"
	clock = start.At
	if err := store.CommitExecutionTransition(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision,
		view.Action, substituted, transition, view.Binding,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted execution Event error = %v", err)
	}
	assertActionState(t, store, view.Action.ActionID, actionlifecycle.StateAccepted, view.Action.Revision)
}

func TestMemoryStoreReappliesDependencyEventsAndKeepsRetriesIdempotent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC)
	dependencies := []taskcoord.Dependency{
		dependency("dependency:event-binding", "task:event-binding", "task:upstream", false),
	}
	store, view, clock := newRunningActionWithDependencies(t, at, dependencies)

	waitEvent := executorEvent(view.Action, actionlifecycle.EventWait, at.Add(4*time.Second))
	waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	prepareDependencyWaitEvent(t, view.Binding, view.Action, dependencies, &waitEvent)
	waitTransition, wait, err := WaitForDependencies(
		view.Binding, view.Assignment, view.Action, dependencies, waitEvent,
	)
	if err != nil {
		t.Fatal(err)
	}
	substitutedWait := cloneEvent(waitEvent)
	substitutedWait.Auth.AuthorizationID += ":substituted"
	*clock = waitEvent.At
	if err := store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, substitutedWait, waitTransition, view.Binding, wait,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted dependency WAIT Event error = %v", err)
	}
	assertActionState(t, store, view.Action.ActionID, actionlifecycle.StateRunning, view.Action.Revision)
	if _, err := store.LoadDependencyWait(ctx, view.Action.ActionID, waitTransition.Snapshot.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected dependency WAIT stored a companion record: %v", err)
	}

	if err := store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, waitEvent, waitTransition, view.Binding, wait,
	); err != nil {
		t.Fatalf("commit dependency WAIT: %v", err)
	}
	if err := store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, waitEvent, waitTransition, view.Binding, wait,
	); err != nil {
		t.Fatalf("exact dependency WAIT retry: %v", err)
	}
	if err := store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, substitutedWait, waitTransition, view.Binding, wait,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted dependency WAIT retry error = %v", err)
	}

	if err := store.SetDependencySatisfied(ctx, dependencies[0].DependencyID, true); err != nil {
		t.Fatal(err)
	}
	satisfied := append([]taskcoord.Dependency(nil), dependencies...)
	satisfied[0].Satisfied = true
	resumeEvent := authenticatedActionEvent(waitTransition.Snapshot, actionlifecycle.EventResume, at.Add(5*time.Second), "executor:resumed")
	resumeEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonResumed}
	resumeEvent.Lease = lease(waitTransition.Snapshot.LeaseGeneration+1, resumeEvent.Auth.ActorID, resumeEvent.At)
	evidence, err := DependencyResumeEvidence(view.Binding, view.Assignment, waitTransition.Snapshot, wait, satisfied)
	if err != nil {
		t.Fatal(err)
	}
	resumeEvent.EvidenceRef = evidence
	bindActionEvent(t, &resumeEvent)
	resumeTransition, err := ResumeDependencyWait(
		view.Binding, view.Assignment, waitTransition.Snapshot, wait, satisfied, resumeEvent,
	)
	if err != nil {
		t.Fatal(err)
	}
	substitutedResume := cloneEvent(resumeEvent)
	substitutedResume.Auth.ProofID += ":substituted"
	*clock = resumeEvent.At
	if err := store.CommitDependencyResume(
		ctx, view.Assignment.Revision, view.Assignment, waitTransition.Snapshot.Revision,
		waitTransition.Snapshot, satisfied, substitutedResume, resumeTransition, view.Binding, wait,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted dependency RESUME Event error = %v", err)
	}
	assertActionState(t, store, view.Action.ActionID, actionlifecycle.StateWaiting, waitTransition.Snapshot.Revision)

	if err := store.CommitDependencyResume(
		ctx, view.Assignment.Revision, view.Assignment, waitTransition.Snapshot.Revision,
		waitTransition.Snapshot, satisfied, resumeEvent, resumeTransition, view.Binding, wait,
	); err != nil {
		t.Fatalf("commit dependency RESUME: %v", err)
	}
	if err := store.CommitDependencyResume(
		ctx, view.Assignment.Revision, view.Assignment, waitTransition.Snapshot.Revision,
		waitTransition.Snapshot, satisfied, resumeEvent, resumeTransition, view.Binding, wait,
	); err != nil {
		t.Fatalf("exact dependency RESUME retry: %v", err)
	}
	if err := store.CommitDependencyResume(
		ctx, view.Assignment.Revision, view.Assignment, waitTransition.Snapshot.Revision,
		waitTransition.Snapshot, satisfied, substitutedResume, resumeTransition, view.Binding, wait,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted dependency RESUME retry error = %v", err)
	}
}

func TestMemoryStoreReappliesTrustedLeaseExpiryEventBeforeCommit(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	store, _, view, clock := newRunningActionService(t, at)
	expiry := view.Action.ExecutorLease.ExpiresAt
	event := actionlifecycle.Event{
		ID: "event:trusted-expiry:event-binding", Kind: actionlifecycle.EventLeaseExpired,
		ExpectedRevision: view.Action.Revision, At: expiry,
		Reason: actionlifecycle.Reason{Code: actionlifecycle.ReasonLeaseExpired},
	}
	transition, err := actionlifecycle.Apply(view.Action, event)
	if err != nil {
		t.Fatal(err)
	}
	substituted := event
	substituted.ID += ":substituted"
	*clock = expiry
	if err := store.CommitTrustedLeaseExpiry(
		context.Background(), view.Action.Revision, view.Action, substituted, transition,
	); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("substituted trusted expiry Event error = %v", err)
	}
	assertActionState(t, store, view.Action.ActionID, actionlifecycle.StateRunning, view.Action.Revision)
}

func newRunningActionWithDependencies(
	t *testing.T,
	at time.Time,
	dependencies []taskcoord.Dependency,
) (*MemoryStore, View, *time.Time) {
	t.Helper()
	ctx := context.Background()
	clock := at.Add(2 * time.Second)
	assignment := acceptedAssignment(t, "assignment:event-binding", "task:event-binding", "agent:owner", at)
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, dependencies, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	view, err := acceptWithTestAuth(t, service, ctx, assignment, clock, AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:event-binding",
		ActionID:     "action:event-binding",
		ActionDigest: "sha256:" + strings.Repeat("c", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:event-binding",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := authenticatedActionEvent(view.Action, actionlifecycle.EventStart, at.Add(3*time.Second), "executor:event-binding")
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = lease(view.Action.LeaseGeneration+1, start.Auth.ActorID, start.At)
	bindActionEvent(t, &start)
	clock = start.At
	view, err = service.Transition(ctx, view.Action.ActionID, start)
	if err != nil {
		t.Fatal(err)
	}
	return store, view, &clock
}

func cloneEvent(in actionlifecycle.Event) actionlifecycle.Event {
	out := in
	if in.Auth != nil {
		value := *in.Auth
		out.Auth = &value
	}
	if in.Fence != nil {
		value := *in.Fence
		out.Fence = &value
	}
	if in.Lease != nil {
		value := *in.Lease
		out.Lease = &value
	}
	if in.ResumeCondition != nil {
		value := *in.ResumeCondition
		out.ResumeCondition = &value
	}
	if in.Checkpoint != nil {
		value := *in.Checkpoint
		out.Checkpoint = &value
	}
	return out
}

func assertActionState(
	t *testing.T,
	store *MemoryStore,
	actionID string,
	state actionlifecycle.State,
	revision uint64,
) {
	t.Helper()
	stored, err := store.Load(context.Background(), actionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != state || stored.Revision != revision {
		t.Fatalf("stored Action = state %s revision %d, want %s revision %d", stored.State, stored.Revision, state, revision)
	}
}
