// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestDurableActionStatePreservesFirstAcceptanceAndFreshProofBoundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, assignment, request, first, at := durableActionFixture(t)
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if _, hasCurrentAssignments := document["assignments"]; hasCurrentAssignments {
		t.Fatal("current Assignment cache must not be serialized in Action state")
	}
	// Recovery after expiry retains the original response only for the exact
	// stored proof attempt. A fresh proof cannot silently replace provenance.
	restored, err := RestoreMemoryStore(raw, []taskcoord.Assignment{assignment}, func() time.Time { return at.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.CommitAcceptance(ctx, assignment.Revision, assignment, request)
	if err != nil || !sameJSON(got, first) {
		t.Fatalf("original acceptance did not survive restore: %+v, %v", got, err)
	}
	fresh := request
	freshAuth := *request.Auth
	fresh.Auth = &freshAuth
	fresh.Auth.ProofID = "proof:fresh"
	fresh.Auth.VerifierNonce = "nonce:fresh"
	if _, err := restored.CommitAcceptance(ctx, assignment.Revision, assignment, fresh); !errors.Is(err, ErrAcceptanceReconciliationRequired) {
		t.Fatalf("fresh proof overwrote acceptance provenance: %v", err)
	}
	roundTrip, err := restored.ExportState()
	if err != nil || string(roundTrip) != string(raw) {
		t.Fatalf("canonical stored state changed: %v", err)
	}
}

func TestDurableActionStateUsesCurrentAuthoritativeRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, assignment, request, first, at := durableActionFixture(t)
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := taskcoord.Apply(assignment, taskEvent(assignment, taskcoord.OperationRevoke, at.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMemoryStore(raw, []taskcoord.Assignment{revoked.Assignment}, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(restored, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.Load(ctx, first.Action.ActionID)
	if err != nil || view.Assignment.Status != taskcoord.AssignmentRevoked {
		t.Fatalf("restored stale Assignment authority: %+v, %v", view, err)
	}
	start := authenticatedActionEvent(first.Action, actionlifecycle.EventStart, at.Add(2*time.Second), "agent:executor")
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = lease(1, "agent:executor", start.At)
	bindActionEvent(t, &start)
	if _, err := service.Transition(ctx, first.Action.ActionID, start); !errors.Is(err, ErrAssignmentNotAccepted) {
		t.Fatalf("revoked Assignment started execution: %v", err)
	}
	// The historical accepted response still exists, without reverting the
	// authoritative Assignment or treating that response as permission to run.
	got, err := restored.CommitAcceptance(ctx, assignment.Revision, assignment, request)
	if err != nil || !sameJSON(got, first) {
		t.Fatalf("historical response lost on revocation: %+v, %v", got, err)
	}
}

func TestDurableActionStateRejectsMissingOrCorruptJoins(t *testing.T) {
	t.Parallel()
	store, assignment, request, _, at := durableActionFixture(t)
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return at }
	if _, err := RestoreMemoryStore(raw, nil, now); err == nil {
		t.Fatal("restored Action without authoritative Assignment")
	}
	mutations := map[string]func(*durableActionState){
		"version":       func(s *durableActionState) { s.Schema = "asb.task-action-store/v2" },
		"missing index": func(s *durableActionState) { delete(s.ActionByAssignment, assignment.AssignmentID) },
		"missing event": func(s *durableActionState) { delete(s.Events, request.EventID) },
		"lost proof fingerprint": func(s *durableActionState) {
			event := s.Events[request.EventID]
			event.AcceptanceAttemptFingerprint = ""
			s.Events[request.EventID] = event
		},
		"changed acceptance view": func(s *durableActionState) {
			event := s.Events[request.EventID]
			event.Acceptance.Action.LastTransition.ProofID = "proof:changed"
			s.Events[request.EventID] = event
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var state durableActionState
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			mutate(&state)
			changed, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RestoreMemoryStore(changed, []taskcoord.Assignment{assignment}, now); err == nil {
				t.Fatal("corrupt Action state was restored")
			}
		})
	}
	for _, bad := range [][]byte{
		[]byte("null"), []byte("{}"), append(append([]byte(nil), raw...), []byte(" {}")...),
		append([]byte(`{"schema":"duplicate",`), raw[1:]...),
		append([]byte(`{"unknown":true,`), raw[1:]...),
	} {
		if _, err := RestoreMemoryStore(bad, []taskcoord.Assignment{assignment}, now); err == nil {
			t.Fatal("malformed Action state was restored")
		}
	}
	if _, err := RestoreMemoryStore(nil, []taskcoord.Assignment{assignment}, nil); err == nil {
		t.Fatal("missing transaction clock was accepted")
	}
}

func TestDurableActionDependenciesSurviveRestore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, assignment, _, _, at := durableActionFixture(t)
	edge := dependency("dependency:stored", assignment.TaskID, "task:prerequisite", false)
	if err := store.SetDependencies(ctx, []taskcoord.Dependency{edge}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDependencySatisfied(ctx, edge.DependencyID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetDependencies(ctx, []taskcoord.Dependency{edge, edge}); err == nil {
		t.Fatal("duplicate dependency replaced graph")
	}
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMemoryStore(raw, []taskcoord.Assignment{assignment}, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := restored.ListDependencies(ctx, assignment.TaskID)
	if err != nil || len(dependencies) != 1 || !dependencies[0].Satisfied {
		t.Fatalf("dependency state lost: %+v, %v", dependencies, err)
	}
}

func TestDurableActionStatePreservesDependencyWaitAndFencingHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 11, 0, 0, 0, time.UTC)
	dependencies := []taskcoord.Dependency{dependency("dependency:stored", "task:event-binding", "task:upstream", false)}
	store, view, clock := newRunningActionWithDependencies(t, at, dependencies)
	waitEvent := executorEvent(view.Action, actionlifecycle.EventWait, at.Add(4*time.Second))
	waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	prepareDependencyWaitEvent(t, view.Binding, view.Action, dependencies, &waitEvent)
	transition, wait, err := WaitForDependencies(view.Binding, view.Assignment, view.Action, dependencies, waitEvent)
	if err != nil {
		t.Fatal(err)
	}
	*clock = waitEvent.At
	if err := store.CommitDependencyWait(ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, waitEvent, transition, view.Binding, wait); err != nil {
		t.Fatal(err)
	}
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMemoryStore(raw, []taskcoord.Assignment{view.Assignment}, func() time.Time { return *clock })
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.LoadDependencyWait(ctx, view.Action.ActionID, transition.Snapshot.Revision)
	if err != nil || !sameJSON(got, wait) {
		t.Fatalf("dependency wait changed: %+v, %v", got, err)
	}
	if err := restored.CommitDependencyWait(ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, waitEvent, transition, view.Binding, wait); err != nil {
		t.Fatalf("exact wait retry after restore: %v", err)
	}
	action, err := restored.Load(ctx, view.Action.ActionID)
	if err != nil || action.LeaseGeneration != transition.Snapshot.LeaseGeneration || action.State != actionlifecycle.StateWaiting {
		t.Fatalf("fencing/state changed: %+v, %v", action, err)
	}
	// Topology edits remain explicit trusted application changes; restoring
	// them must preserve the old wait so an incompatible resume fails closed.
	changed := dependencies[0]
	changed.ToTaskID = "task:different-upstream"
	if err := restored.SetDependencies(ctx, []taskcoord.Dependency{changed}); err != nil {
		t.Fatal(err)
	}
	raw, err = restored.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err = RestoreMemoryStore(raw, []taskcoord.Assignment{view.Assignment}, func() time.Time { return *clock })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DependencyResumeEvidence(view.Binding, view.Assignment, action, wait, []taskcoord.Dependency{changed}); !errors.Is(err, ErrDependencyTopologyChanged) {
		t.Fatalf("changed topology resumed old wait: %v", err)
	}
	if _, err := restored.LoadDependencyWait(ctx, view.Action.ActionID, action.Revision); err != nil {
		t.Fatalf("changed topology discarded old wait: %v", err)
	}
}

func durableActionFixture(t *testing.T) (*MemoryStore, taskcoord.Assignment, AcceptRequest, View, time.Time) {
	t.Helper()
	at := time.Date(2026, 9, 20, 9, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:stored", "task:stored", "human:stored", at)
	at = at.Add(2 * time.Second)
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, func() time.Time { return at })
	if err != nil {
		t.Fatal(err)
	}
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:stored", ActionID: "action:stored",
		ActionDigest:   "sha256:" + strings.Repeat("b", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryManual, MaxAttempts: 1},
	}
	bindTestAcceptance(t, assignment, at, &request)
	view, err := store.CommitAcceptance(context.Background(), assignment.Revision, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	return store, assignment, request, view, at
}
