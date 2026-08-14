// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

func TestBindingKeepsResponsibilityAndExecutionIndependent(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:human", "task:human", "human:reviewer", at)
	initial := acceptedAction(t, "action:human", "human:reviewer", at.Add(2*time.Second))
	binding, err := NewBinding(assignment, initial)
	if err != nil {
		t.Fatalf("bind accepted Action: %v", err)
	}
	running := startAction(t, initial.Snapshot, at.Add(3*time.Second), "agent:executor")

	released, err := taskcoord.Apply(assignment, taskEvent(assignment, taskcoord.OperationRelease, at.Add(4*time.Second)))
	if err != nil {
		t.Fatalf("release Assignment: %v", err)
	}
	if err := ValidateCurrent(binding, released.Assignment, running.Snapshot); err != nil {
		t.Fatalf("released Assignment must preserve binding history: %v", err)
	}
	if running.Snapshot.State != actionlifecycle.StateRunning {
		t.Fatalf("Assignment release changed Action state to %s", running.Snapshot.State)
	}
	eligible, err := FulfillmentEligible(binding, released.Assignment, running.Snapshot)
	if err != nil {
		t.Fatalf("check fulfillment eligibility: %v", err)
	}
	if eligible {
		t.Fatal("released Assignment must not be fulfillment eligible")
	}
}

func TestSucceededActionOnlyMakesFulfillmentEligible(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:1", "task:1", "agent:owner", at)
	initial := acceptedAction(t, "action:1", "agent:owner", at.Add(2*time.Second))
	binding, err := NewBinding(assignment, initial)
	if err != nil {
		t.Fatal(err)
	}
	running := startAction(t, initial.Snapshot, at.Add(3*time.Second), "agent:executor")
	completeEvent := executorEvent(running.Snapshot, actionlifecycle.EventComplete, at.Add(4*time.Second))
	completeEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonCompleted}
	completeEvent.ResultRef = "urn:result:1"
	completed, err := actionlifecycle.Apply(running.Snapshot, completeEvent)
	if err != nil {
		t.Fatalf("complete Action: %v", err)
	}
	eligible, err := FulfillmentEligible(binding, assignment, completed.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !eligible {
		t.Fatal("accepted Assignment with SUCCEEDED Action must be eligible")
	}
	if assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("Action completion mutated Assignment to %s", assignment.Status)
	}
}

func TestDependencyWaitCycleProjectsToExistingDeadlockDetector(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 11, 0, 0, 0, time.UTC)
	dependencies := []taskcoord.Dependency{
		dependency("dependency:a-b", "task:a", "task:b", false),
		dependency("dependency:b-a", "task:b", "task:a", false),
	}
	linked := make([]LinkedAction, 0, 2)
	for index, id := range []string{"a", "b"} {
		assignment := acceptedAssignment(t, "assignment:"+id, "task:"+id, "agent:"+id, at)
		initial := acceptedAction(t, "action:"+id, "agent:"+id, at.Add(2*time.Second))
		binding, err := NewBinding(assignment, initial)
		if err != nil {
			t.Fatal(err)
		}
		running := startAction(t, initial.Snapshot, at.Add(3*time.Second), "executor:"+id)
		waitEvent := executorEvent(running.Snapshot, actionlifecycle.EventWait, at.Add(time.Duration(4+index)*time.Second))
		waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
		waiting, wait, err := WaitForDependencies(binding, assignment, running.Snapshot, dependencies, waitEvent)
		if err != nil {
			t.Fatalf("wait Action %s: %v", id, err)
		}
		linked = append(linked, LinkedAction{Binding: binding, Assignment: assignment, Action: waiting.Snapshot, DependencyWait: &wait})
	}

	deadlocked, err := DetectDeadlockedActions(linked, dependencies)
	if err != nil {
		t.Fatalf("detect deadlock: %v", err)
	}
	if strings.Join(deadlocked, ",") != "task:a,task:b" {
		t.Fatalf("deadlocked = %v", deadlocked)
	}
}

func TestNonDependencyWaitIsAnExternalEscape(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	dependencies := []taskcoord.Dependency{dependency("dependency:a-b", "task:a", "task:b", false)}

	assignmentA := acceptedAssignment(t, "assignment:a", "task:a", "agent:a", at)
	initialA := acceptedAction(t, "action:a", "agent:a", at.Add(2*time.Second))
	bindingA, _ := NewBinding(assignmentA, initialA)
	runningA := startAction(t, initialA.Snapshot, at.Add(3*time.Second), "executor:a")
	waitEventA := executorEvent(runningA.Snapshot, actionlifecycle.EventWait, at.Add(4*time.Second))
	waitEventA.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	waitingA, waitA, err := WaitForDependencies(bindingA, assignmentA, runningA.Snapshot, dependencies, waitEventA)
	if err != nil {
		t.Fatal(err)
	}

	assignmentB := acceptedAssignment(t, "assignment:b", "task:b", "agent:b", at)
	initialB := acceptedAction(t, "action:b", "agent:b", at.Add(2*time.Second))
	bindingB, _ := NewBinding(assignmentB, initialB)
	runningB := startAction(t, initialB.Snapshot, at.Add(3*time.Second), "executor:b")
	notBefore := at.Add(time.Hour)
	waitEventB := executorEvent(runningB.Snapshot, actionlifecycle.EventWait, at.Add(5*time.Second))
	waitEventB.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonScheduled}
	waitEventB.ResumeCondition = &actionlifecycle.ResumeCondition{Type: actionlifecycle.ResumeAtTime, NotBefore: &notBefore}
	waitingB, err := actionlifecycle.Apply(runningB.Snapshot, waitEventB)
	if err != nil {
		t.Fatal(err)
	}

	deadlocked, err := DetectDeadlockedActions([]LinkedAction{
		{Binding: bindingA, Assignment: assignmentA, Action: waitingA.Snapshot, DependencyWait: &waitA},
		{Binding: bindingB, Assignment: assignmentB, Action: waitingB.Snapshot},
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if len(deadlocked) != 0 {
		t.Fatalf("time wait must provide external escape, got %v", deadlocked)
	}
}

func TestDependencyResumeRequiresSameSatisfiedTopology(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:a", "task:a", "agent:a", at)
	initial := acceptedAction(t, "action:a", "agent:a", at.Add(2*time.Second))
	binding, _ := NewBinding(assignment, initial)
	running := startAction(t, initial.Snapshot, at.Add(3*time.Second), "executor:a")
	dependencies := []taskcoord.Dependency{dependency("dependency:a-b", "task:a", "task:b", false)}
	waitEvent := executorEvent(running.Snapshot, actionlifecycle.EventWait, at.Add(4*time.Second))
	waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	waiting, wait, err := WaitForDependencies(binding, assignment, running.Snapshot, dependencies, waitEvent)
	if err != nil {
		t.Fatal(err)
	}

	changed := append([]taskcoord.Dependency(nil), dependencies...)
	changed[0].ToTaskID = "task:c"
	changed[0].Satisfied = true
	resumeEvent := authenticatedActionEvent(waiting.Snapshot, actionlifecycle.EventResume, at.Add(5*time.Second), "executor:new")
	resumeEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonResumed}
	resumeEvent.Lease = lease(waiting.Snapshot.LeaseGeneration+1, "executor:new", resumeEvent.At)
	if _, err := ResumeDependencyWait(binding, assignment, waiting.Snapshot, wait, changed, resumeEvent); !errors.Is(err, ErrDependencyTopologyChanged) {
		t.Fatalf("topology change error = %v", err)
	}

	dependencies[0].Satisfied = true
	resumed, err := ResumeDependencyWait(binding, assignment, waiting.Snapshot, wait, dependencies, resumeEvent)
	if err != nil {
		t.Fatalf("resume satisfied dependency wait: %v", err)
	}
	if resumed.Snapshot.State != actionlifecycle.StateRunning || !strings.HasPrefix(resumed.Record.EvidenceRef, dependencyEvidencePrefix) {
		t.Fatalf("unexpected resume transition: %#v", resumed)
	}
}

func TestDependenciesSatisfiedCombinesAllAnyAndQuorum(t *testing.T) {
	t.Parallel()
	dependencies := []taskcoord.Dependency{
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:all:1", FromTaskID: "task:a", ToTaskID: "task:b", GroupID: "g:all", Mode: taskcoord.DependencyAll, Active: true, Satisfied: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:all:2", FromTaskID: "task:a", ToTaskID: "task:c", GroupID: "g:all", Mode: taskcoord.DependencyAll, Active: true, Satisfied: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:any:1", FromTaskID: "task:a", ToTaskID: "task:d", GroupID: "g:any", Mode: taskcoord.DependencyAny, Active: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:any:2", FromTaskID: "task:a", ToTaskID: "task:e", GroupID: "g:any", Mode: taskcoord.DependencyAny, Active: true, Satisfied: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:quorum:1", FromTaskID: "task:a", ToTaskID: "task:f", GroupID: "g:quorum", Mode: taskcoord.DependencyQuorum, Quorum: 2, Active: true, Satisfied: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:quorum:2", FromTaskID: "task:a", ToTaskID: "task:g", GroupID: "g:quorum", Mode: taskcoord.DependencyQuorum, Quorum: 2, Active: true, Satisfied: true},
		{Schema: taskcoord.DependencySchemaV1, DependencyID: "d:quorum:3", FromTaskID: "task:a", ToTaskID: "task:h", GroupID: "g:quorum", Mode: taskcoord.DependencyQuorum, Quorum: 2, Active: true},
	}
	satisfied, err := DependenciesSatisfied("task:a", dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !satisfied {
		t.Fatal("ALL, ANY, and QUORUM groups should all be satisfied")
	}
	dependencies[3].Satisfied = false
	satisfied, err = DependenciesSatisfied("task:a", dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if satisfied {
		t.Fatal("multiple groups must be conjunctive")
	}
}

func TestStrictBindingDecoderRejectsUnknownAndTrailingJSON(t *testing.T) {
	t.Parallel()
	binding := Binding{Schema: BindingSchemaV1, TaskID: "task:1", AssignmentID: "assignment:1", ActionID: "action:1", CreatedAt: time.Date(2026, 8, 14, 14, 0, 0, 0, time.UTC)}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBinding(strings.NewReader(string(raw))); err != nil {
		t.Fatalf("decode valid binding: %v", err)
	}
	withUnknown := strings.TrimSuffix(string(raw), "}") + `,"unexpected":true}`
	if _, err := DecodeBinding(strings.NewReader(withUnknown)); err == nil {
		t.Fatal("unknown member accepted")
	}
	if _, err := DecodeBinding(strings.NewReader(string(raw) + `{}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}

func TestServiceRunsHumanTaskActionLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:service", "task:service", "human:operator", at)
	dependencies := []taskcoord.Dependency{dependency("dependency:service", "task:service", "task:upstream", false)}
	store, err := NewMemoryStore([]taskcoord.Assignment{assignment}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.Accept(ctx, AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:action:accept:service",
		ActionID: "action:service", ActionDigest: "sha256:" + strings.Repeat("c", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 2,
			IdempotencyKey: "idempotency:action:service",
		},
	})
	if err != nil {
		t.Fatalf("accept linked Action: %v", err)
	}
	if view.Action.OwnerID != assignment.ParticipantID || view.Binding.AssignmentID != assignment.AssignmentID {
		t.Fatalf("trusted owner binding was not derived: %+v", view)
	}

	startAt := at.Add(3 * time.Second)
	start := authenticatedActionEvent(view.Action, actionlifecycle.EventStart, startAt, "agent:executor")
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = lease(view.Action.LeaseGeneration+1, "agent:executor", startAt)
	view, err = service.Transition(ctx, view.Action.ActionID, start)
	if err != nil {
		t.Fatalf("start linked Action: %v", err)
	}

	waitAt := at.Add(4 * time.Second)
	waitEvent := executorEvent(view.Action, actionlifecycle.EventWait, waitAt)
	waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	if _, err := service.Transition(ctx, view.Action.ActionID, waitEvent); !errors.Is(err, ErrUseDependencyOperation) {
		t.Fatalf("ordinary transition bypass error = %v", err)
	}
	view, wait, err := service.WaitForDependencies(ctx, view.Action.ActionID, waitEvent)
	if err != nil {
		t.Fatalf("commit dependency wait: %v", err)
	}
	if wait.ActionRevision != view.Action.Revision || view.Action.State != actionlifecycle.StateWaiting {
		t.Fatalf("unexpected wait state: view=%+v wait=%+v", view, wait)
	}

	resumeAt := at.Add(5 * time.Second)
	resume := authenticatedActionEvent(view.Action, actionlifecycle.EventResume, resumeAt, "agent:executor:2")
	resume.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonResumed}
	resume.Lease = lease(view.Action.LeaseGeneration+1, "agent:executor:2", resumeAt)
	if _, err := service.Transition(ctx, view.Action.ActionID, resume); !errors.Is(err, ErrUseDependencyOperation) {
		t.Fatalf("ordinary resume bypass error = %v", err)
	}
	if err := store.SetDependencySatisfied(ctx, "dependency:service", true); err != nil {
		t.Fatal(err)
	}
	view, err = service.ResumeDependencyWait(ctx, view.Action.ActionID, resume)
	if err != nil {
		t.Fatalf("resume dependency wait: %v", err)
	}

	completeAt := at.Add(6 * time.Second)
	complete := executorEvent(view.Action, actionlifecycle.EventComplete, completeAt)
	complete.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonCompleted}
	complete.ResultRef = "urn:result:service"
	view, err = service.Transition(ctx, view.Action.ActionID, complete)
	if err != nil {
		t.Fatalf("complete linked Action: %v", err)
	}
	eligible, err := FulfillmentEligible(view.Binding, view.Assignment, view.Action)
	if err != nil || !eligible {
		t.Fatalf("fulfillment eligibility = (%v, %v)", eligible, err)
	}
	if view.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("Action completion mutated Assignment to %s", view.Assignment.Status)
	}
}

func TestMemoryStoreRejectsDependencyTOCTOUWithoutPartialCommit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 14, 17, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:toctou", "task:toctou", "agent:owner", at)
	dependencies := []taskcoord.Dependency{dependency("dependency:toctou", "task:toctou", "task:target", false)}
	store, err := NewMemoryStore([]taskcoord.Assignment{assignment}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.Accept(ctx, AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:toctou", ActionID: "action:toctou",
		ActionDigest: "sha256:" + strings.Repeat("d", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:toctou",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := authenticatedActionEvent(view.Action, actionlifecycle.EventStart, at.Add(3*time.Second), "executor:toctou")
	start.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	start.Lease = lease(view.Action.LeaseGeneration+1, "executor:toctou", start.At)
	view, err = service.Transition(ctx, view.Action.ActionID, start)
	if err != nil {
		t.Fatal(err)
	}
	waitEvent := executorEvent(view.Action, actionlifecycle.EventWait, at.Add(4*time.Second))
	waitEvent.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonDependencyPending}
	transition, wait, err := WaitForDependencies(view.Binding, view.Assignment, view.Action, dependencies, waitEvent)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetDependencySatisfied(ctx, "dependency:toctou", true); err != nil {
		t.Fatal(err)
	}
	err = store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, transition, view.Binding, wait,
	)
	if !errors.Is(err, ErrStoreConflict) {
		t.Fatalf("TOCTOU commit error = %v", err)
	}
	stored, err := store.Load(ctx, view.Action.ActionID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != actionlifecycle.StateRunning || stored.Revision != view.Action.Revision {
		t.Fatalf("failed atomic commit changed Action: %+v", stored)
	}
	if _, err := store.LoadDependencyWait(ctx, view.Action.ActionID, transition.Snapshot.Revision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed atomic commit stored wait: %v", err)
	}
}

func TestMemoryStoreActionCASHasOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 8, 14, 18, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:race", "task:race", "agent:owner", at)
	store, err := NewMemoryStore([]taskcoord.Assignment{assignment}, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return at.Add(2 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.Accept(ctx, AcceptRequest{
		AssignmentID: assignment.AssignmentID, EventID: "event:accept:race", ActionID: "action:race",
		ActionDigest: "sha256:" + strings.Repeat("e", 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:race",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transitions := make([]actionlifecycle.Transition, 2)
	for index, executor := range []string{"executor:race:1", "executor:race:2"} {
		event := authenticatedActionEvent(view.Action, actionlifecycle.EventStart, at.Add(time.Duration(3+index)*time.Second), executor)
		event.ID += fmt.Sprintf(":%d", index)
		event.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
		event.Lease = lease(view.Action.LeaseGeneration+1, executor, event.At)
		transitions[index], err = actionlifecycle.Apply(view.Action, event)
		if err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, len(transitions))
	for _, transition := range transitions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- store.Commit(ctx, view.Action.Revision, transition.Snapshot, transition.Record)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	conflicts := 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrStoreConflict):
			conflicts++
		default:
			t.Fatalf("unexpected CAS result: %v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("CAS results: successes=%d conflicts=%d", successes, conflicts)
	}
}

func acceptedAssignment(t *testing.T, assignmentID, taskID, participantID string, at time.Time) taskcoord.Assignment {
	t.Helper()
	kind := taskcoord.ParticipantAgent
	if strings.HasPrefix(participantID, "human:") {
		kind = taskcoord.ParticipantHuman
	}
	participant := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: participantID,
		Kind: kind, IdentityRef: "urn:identity:" + participantID,
		Status: taskcoord.ParticipantActive, RegisteredAt: at.Add(-time.Hour),
	}
	offerAuth := taskcoord.AuthenticatedOperation{
		ActorID: "agent:requester", ParticipantID: "agent:requester", AuthorizationID: "authorization:offer:" + assignmentID,
		ProofID: "proof:offer:" + assignmentID, Operation: taskcoord.OperationOffer, TaskID: taskID,
		AssignmentID: assignmentID, TargetParticipantID: participantID, VerifierNonce: "nonce:offer:" + assignmentID,
		IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute),
	}
	offer, err := taskcoord.Offer(taskcoord.AssignmentDefinition{
		EventID: "event:offer:" + assignmentID, AssignmentID: assignmentID, TaskID: taskID,
		ParticipantID: participantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: strings.Repeat("a", 64), OfferedAt: at,
	}, participant, offerAuth)
	if err != nil {
		t.Fatalf("offer Assignment: %v", err)
	}
	acceptAt := at.Add(time.Second)
	accept, err := taskcoord.Apply(offer.Assignment, taskcoord.Event{
		ID: "event:accept:" + assignmentID, Kind: taskcoord.OperationAccept,
		ExpectedRevision: offer.Assignment.Revision, At: acceptAt,
		Auth: taskcoord.AuthenticatedOperation{
			ActorID: participantID, ParticipantID: participantID, AuthorizationID: "authorization:accept:" + assignmentID,
			ProofID: "proof:accept:" + assignmentID, Operation: taskcoord.OperationAccept, TaskID: taskID,
			AssignmentID: assignmentID, VerifierNonce: "nonce:accept:" + assignmentID,
			IssuedAt: acceptAt.Add(-time.Second), ExpiresAt: acceptAt.Add(time.Minute),
		},
	})
	if err != nil {
		t.Fatalf("accept Assignment: %v", err)
	}
	return accept.Assignment
}

func acceptedAction(t *testing.T, actionID, ownerID string, at time.Time) actionlifecycle.Transition {
	t.Helper()
	transition, err := actionlifecycle.NewSnapshot(actionlifecycle.Definition{
		EventID: "event:accept:" + actionID, ActionID: actionID,
		ActionDigest: "sha256:" + strings.Repeat("b", 64), OwnerID: ownerID,
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 2,
			IdempotencyKey: "idempotency:" + actionID,
		},
		AcceptedAt: at,
	})
	if err != nil {
		t.Fatalf("accept Action: %v", err)
	}
	return transition
}

func startAction(t *testing.T, snapshot actionlifecycle.Snapshot, at time.Time, executor string) actionlifecycle.Transition {
	t.Helper()
	event := authenticatedActionEvent(snapshot, actionlifecycle.EventStart, at, executor)
	event.Reason = actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted}
	event.Lease = lease(snapshot.LeaseGeneration+1, executor, at)
	transition, err := actionlifecycle.Apply(snapshot, event)
	if err != nil {
		t.Fatalf("start Action: %v", err)
	}
	return transition
}

func authenticatedActionEvent(snapshot actionlifecycle.Snapshot, kind actionlifecycle.EventKind, at time.Time, actor string) actionlifecycle.Event {
	return actionlifecycle.Event{
		ID:   "event:" + strings.ToLower(string(kind)) + ":" + snapshot.ActionID,
		Kind: kind, ExpectedRevision: snapshot.Revision, At: at,
		Auth: &actionlifecycle.AuthenticatedOperation{
			ActorID: actor, AuthorizationID: "authorization:" + actor, ProofID: "proof:" + actor + ":" + at.Format("150405"),
			Operation: kind, ActionID: snapshot.ActionID, ActionDigest: snapshot.ActionDigest,
			VerifierNonce: "nonce:" + actor + ":" + at.Format("150405"), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
		},
	}
}

func executorEvent(snapshot actionlifecycle.Snapshot, kind actionlifecycle.EventKind, at time.Time) actionlifecycle.Event {
	event := authenticatedActionEvent(snapshot, kind, at, snapshot.ExecutorLease.ExecutorID)
	event.Fence = &actionlifecycle.LeaseFence{
		LeaseID: snapshot.ExecutorLease.LeaseID, ExecutorID: snapshot.ExecutorLease.ExecutorID,
		Generation: snapshot.ExecutorLease.Generation,
	}
	return event
}

func lease(generation uint64, executor string, at time.Time) *actionlifecycle.ExecutorLease {
	return &actionlifecycle.ExecutorLease{
		LeaseID: "lease:" + executor + ":" + at.Format("150405"), ExecutorID: executor,
		Generation: generation, IssuedAt: at, ExpiresAt: at.Add(10 * time.Minute),
	}
}

func taskEvent(assignment taskcoord.Assignment, kind taskcoord.OperationKind, at time.Time) taskcoord.Event {
	return taskcoord.Event{
		ID:   "event:" + strings.ToLower(string(kind)) + ":" + assignment.AssignmentID,
		Kind: kind, ExpectedRevision: assignment.Revision, At: at,
		Auth: taskcoord.AuthenticatedOperation{
			ActorID: assignment.ParticipantID, ParticipantID: assignment.ParticipantID,
			AuthorizationID: "authorization:" + string(kind), ProofID: "proof:" + string(kind),
			Operation: kind, TaskID: assignment.TaskID, AssignmentID: assignment.AssignmentID,
			VerifierNonce: "nonce:" + string(kind), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
		},
	}
}

func dependency(id, from, to string, satisfied bool) taskcoord.Dependency {
	return taskcoord.Dependency{
		Schema: taskcoord.DependencySchemaV1, DependencyID: id, FromTaskID: from,
		ToTaskID: to, GroupID: "group:" + from, Mode: taskcoord.DependencyAll,
		Active: true, Satisfied: satisfied,
	}
}
