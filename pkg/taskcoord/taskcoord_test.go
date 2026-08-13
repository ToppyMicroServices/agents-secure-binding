// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHumanAssignmentSeparatesParticipantFromActor(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	human := participant("human:akira", ParticipantHuman, false, base)
	def := definition("offer-1", "assignment-1", "task-1", human.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID

	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatalf("Offer() error = %v", err)
	}
	if offered.Assignment.Status != AssignmentOffered {
		t.Fatalf("status = %s, want OFFERED", offered.Assignment.Status)
	}

	acceptAt := base.Add(time.Minute)
	acceptAuth := auth(OperationAccept, human.ParticipantID, "service:human-gateway", def.TaskID, def.AssignmentID, acceptAt)
	accepted, err := Apply(offered.Assignment, Event{
		ID:               "accept-1",
		Kind:             OperationAccept,
		ExpectedRevision: 1,
		At:               acceptAt,
		Auth:             acceptAuth,
	})
	if err != nil {
		t.Fatalf("Apply(ACCEPT) error = %v", err)
	}
	if accepted.Assignment.ParticipantID != human.ParticipantID {
		t.Fatalf("participant_id = %q", accepted.Assignment.ParticipantID)
	}
	if accepted.Record.ActorID != "service:human-gateway" {
		t.Fatalf("actor_id = %q", accepted.Record.ActorID)
	}
	if accepted.Record.ParticipantID == accepted.Record.ActorID {
		t.Fatal("participant and actor were unexpectedly conflated")
	}
}

func TestAssigneeOperationRejectsDifferentParticipant(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	human := participant("human:akira", ParticipantHuman, false, base)
	def := definition("offer-1", "assignment-1", "task-1", human.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Minute)
	wrongAuth := auth(OperationAccept, "human:other", "service:gateway", def.TaskID, def.AssignmentID, at)
	_, err = Apply(offered.Assignment, Event{ID: "accept-1", Kind: OperationAccept, ExpectedRevision: 1, At: at, Auth: wrongAuth})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
}

func TestDelegationCreatesChildWithoutReleasingParent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:a", ParticipantAgent, true, base)
	human := participant("human:b", ParticipantHuman, true, base)
	store := NewMemoryStore()
	if err := store.RegisterParticipant(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}

	parentDef := definition("offer-parent", "assignment-parent", "task-parent", agent.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", parentDef.TaskID, parentDef.AssignmentID, base)
	offerAuth.TargetParticipantID = agent.ParticipantID
	offered, err := Offer(parentDef, agent, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	acceptAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID:               "accept-parent",
		Kind:             OperationAccept,
		ExpectedRevision: 1,
		At:               acceptAt,
		Auth:             auth(OperationAccept, agent.ParticipantID, "runtime:agent-a", parentDef.TaskID, parentDef.AssignmentID, acceptAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}

	delegatedAt := acceptAt.Add(time.Minute)
	childDef := definition("offer-child", "assignment-child", "task-child", human.ParticipantID, accepted.Assignment.AssignmentID, digest('b'), delegatedAt)
	delegateAuth := auth(OperationDelegate, agent.ParticipantID, "runtime:agent-a", accepted.Assignment.TaskID, accepted.Assignment.AssignmentID, delegatedAt)
	delegateAuth.TargetTaskID = childDef.TaskID
	delegateAuth.TargetAssignmentID = childDef.AssignmentID
	delegateAuth.TargetParticipantID = childDef.ParticipantID
	transition, err := Delegate(
		accepted.Assignment,
		agent,
		human,
		childDef,
		Event{ID: "delegate-1", Kind: OperationDelegate, ExpectedRevision: 2, At: delegatedAt, Auth: delegateAuth},
		VerifiedDelegation{
			DecisionID:            "decision-1",
			ParentAssignmentID:    accepted.Assignment.AssignmentID,
			ChildAssignmentID:     childDef.AssignmentID,
			FromParticipantID:     agent.ParticipantID,
			ToParticipantID:       human.ParticipantID,
			ParentAuthorityDigest: accepted.Assignment.AuthorityDigest,
			ChildAuthorityDigest:  childDef.AuthorityDigest,
			PolicyRef:             "policy:scope-narrowing-v1",
			EvidenceRef:           "evidence:decision-1",
			VerifiedAt:            delegatedAt,
		},
	)
	if err != nil {
		t.Fatalf("Delegate() error = %v", err)
	}
	if transition.Parent.Status != AssignmentAccepted {
		t.Fatalf("parent status = %s, want ACCEPTED", transition.Parent.Status)
	}
	if transition.Child.Status != AssignmentOffered {
		t.Fatalf("child status = %s, want OFFERED", transition.Child.Status)
	}
	if transition.Child.ParentAssignmentID != transition.Parent.AssignmentID {
		t.Fatal("child does not bind parent assignment")
	}
	if err := store.CommitDelegation(ctx, 2, transition); err != nil {
		t.Fatalf("CommitDelegation() error = %v", err)
	}
	if err := store.CommitDelegation(ctx, 2, transition); err != nil {
		t.Fatalf("idempotent CommitDelegation() error = %v", err)
	}
	storedChild, err := store.LoadAssignment(ctx, childDef.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if storedChild.ParentAssignmentID != accepted.Assignment.AssignmentID {
		t.Fatalf("stored parent = %q", storedChild.ParentAssignmentID)
	}
	if _, err := store.LoadDelegation(ctx, "delegate-1"); err != nil {
		t.Fatal(err)
	}
}

func TestDelegationRejectsAuthorityDigestSubstitution(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:a", ParticipantAgent, true, base)
	human := participant("human:b", ParticipantHuman, false, base)
	parent := acceptedAssignment(t, agent, base)
	at := base.Add(2 * time.Minute)
	childDef := definition("offer-child", "assignment-child", "task-child", human.ParticipantID, parent.AssignmentID, digest('b'), at)
	delegateAuth := auth(OperationDelegate, agent.ParticipantID, "runtime:agent-a", parent.TaskID, parent.AssignmentID, at)
	delegateAuth.TargetTaskID = childDef.TaskID
	delegateAuth.TargetAssignmentID = childDef.AssignmentID
	delegateAuth.TargetParticipantID = childDef.ParticipantID
	_, err := Delegate(parent, agent, human, childDef,
		Event{ID: "delegate-1", Kind: OperationDelegate, ExpectedRevision: parent.Revision, At: at, Auth: delegateAuth},
		VerifiedDelegation{
			DecisionID:            "decision-1",
			ParentAssignmentID:    parent.AssignmentID,
			ChildAssignmentID:     childDef.AssignmentID,
			FromParticipantID:     agent.ParticipantID,
			ToParticipantID:       human.ParticipantID,
			ParentAuthorityDigest: parent.AuthorityDigest,
			ChildAuthorityDigest:  digest('c'),
			PolicyRef:             "policy:narrowing",
			EvidenceRef:           "evidence:decision-1",
			VerifiedAt:            at,
		})
	if !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("error = %v, want ErrInvalidDelegation", err)
	}
}

func TestMemoryStoreRejectsStaleRevision(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	human := participant("human:akira", ParticipantHuman, false, base)
	def := definition("offer-1", "assignment-1", "task-1", human.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	acceptedAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID: "accept-1", Kind: OperationAccept, ExpectedRevision: 1, At: acceptedAt,
		Auth: auth(OperationAccept, human.ParticipantID, "gateway:1", def.TaskID, def.AssignmentID, acceptedAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, accepted.Assignment, accepted.Record); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("error = %v, want ErrInvalidTransition", err)
	}
}

func TestMemoryStoreRejectsConflictingIdempotencyPayload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	human := participant("human:akira", ParticipantHuman, false, base)
	def := definition("offer-1", "assignment-1", "task-1", human.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	conflicting := offered.Assignment
	conflicting.AuthorityDigest = digest('b')
	if err := store.CommitAssignment(ctx, 0, conflicting, offered.Record); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("error = %v, want ErrEventConflict", err)
	}
}

func TestAssignmentValidationRejectsImpossibleTransition(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:a", ParticipantAgent, false, base)
	assignment := acceptedAssignment(t, agent, base)
	assignment.LastTransition.Kind = OperationRevoke
	assignment.LastTransition.Reason.Code = OperationRevoke
	if err := assignment.Validate(); !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("error = %v, want ErrInvalidAssignment", err)
	}
}

func TestDecodeAssignmentRejectsUnknownField(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:a", ParticipantAgent, false, base)
	assignment := acceptedAssignment(t, agent, base)
	raw, err := json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":true,"schema":`), 1)
	if _, err := DecodeAssignment(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("error = %v, want ErrInvalidAssignment", err)
	}
}

func TestInteractionHistoryPreservesMultipleResponsesAndCorrection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	owner := participant("agent:owner", ParticipantAgent, false, base)
	human := participant("human:akira", ParticipantHuman, false, base)
	store := NewMemoryStore()
	for _, p := range []Participant{owner, human} {
		if err := store.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	def := definition("offer-1", "assignment-1", "task-1", human.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, owner.ParticipantID, "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	acceptedAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID: "accept-1", Kind: OperationAccept, ExpectedRevision: 1, At: acceptedAt,
		Auth: auth(OperationAccept, human.ParticipantID, "service:human-gateway", def.TaskID, def.AssignmentID, acceptedAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}

	questionDef := interactionDefinition("question-1", "interaction-1", def.TaskID, def.AssignmentID, InteractionQuestion, base.Add(2*time.Minute))
	question := interactionEvent(t, questionDef, owner.ParticipantID, "runtime:owner")
	if err := store.AppendInteractionEvent(ctx, question); err != nil {
		t.Fatal(err)
	}
	rawQuestion, err := json.Marshal(question)
	if err != nil {
		t.Fatal(err)
	}
	decodedQuestion, err := DecodeInteractionEvent(bytes.NewReader(rawQuestion))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendInteractionEvent(ctx, decodedQuestion); err != nil {
		t.Fatalf("idempotent AppendInteractionEvent() error = %v", err)
	}

	interimDef := interactionDefinition("response-1", "interaction-1", def.TaskID, def.AssignmentID, InteractionResponse, base.Add(3*time.Minute))
	interimDef.InReplyTo = question.EventID
	interimDef.Finality = ResponseInterim
	interim := interactionEvent(t, interimDef, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, interim); err != nil {
		t.Fatal(err)
	}

	finalDef := interactionDefinition("response-2", "interaction-1", def.TaskID, def.AssignmentID, InteractionResponse, base.Add(4*time.Minute))
	finalDef.InReplyTo = question.EventID
	finalDef.Finality = ResponseFinal
	final := interactionEvent(t, finalDef, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, final); err != nil {
		t.Fatal(err)
	}

	correctionDef := interactionDefinition("correction-1", "interaction-1", def.TaskID, def.AssignmentID, InteractionCorrection, base.Add(5*time.Minute))
	correctionDef.InReplyTo = question.EventID
	correctionDef.Supersedes = final.EventID
	correctionDef.Finality = ResponseFinal
	correction := interactionEvent(t, correctionDef, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, correction); err != nil {
		t.Fatal(err)
	}

	history, err := store.ListInteractionEvents(ctx, question.InteractionID)
	if err != nil {
		t.Fatal(err)
	}
	gotIDs := make([]string, 0, len(history))
	for _, event := range history {
		gotIDs = append(gotIDs, event.EventID)
	}
	if got, want := strings.Join(gotIDs, ","), "question-1,response-1,response-2,correction-1"; got != want {
		t.Fatalf("event order = %s, want %s", got, want)
	}
	if history[2].Kind != InteractionResponse || history[3].Supersedes != history[2].EventID {
		t.Fatal("correction lineage did not preserve the final response")
	}
	if history[2].ParticipantID == history[2].ActorID {
		t.Fatal("Human participant and gateway actor were unexpectedly conflated")
	}
	stored, err := store.LoadAssignment(ctx, def.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != accepted.Assignment.Revision || stored.Status != AssignmentAccepted || !stored.UpdatedAt.Equal(accepted.Assignment.UpdatedAt) {
		t.Fatal("interaction events unexpectedly changed the Assignment lifecycle")
	}
}

func TestInteractionCorrectionRejectsDifferentParticipant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	owner := participant("agent:owner", ParticipantAgent, false, base)
	human := participant("human:akira", ParticipantHuman, false, base)
	other := participant("human:other", ParticipantHuman, false, base)
	store := NewMemoryStore()
	for _, p := range []Participant{owner, human, other} {
		if err := store.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}

	// Interaction relation checks require an existing Assignment, but do not
	// require it to enter a particular lifecycle state.
	def := definition("offer-2", "assignment-2", "task-2", human.ParticipantID, "", digest('b'), base)
	offerAuth := auth(OperationOffer, owner.ParticipantID, "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}

	questionDef := interactionDefinition("question-2", "interaction-2", def.TaskID, def.AssignmentID, InteractionQuestion, base.Add(time.Minute))
	question := interactionEvent(t, questionDef, owner.ParticipantID, "runtime:owner")
	if err := store.AppendInteractionEvent(ctx, question); err != nil {
		t.Fatal(err)
	}
	responseDef := interactionDefinition("response-3", "interaction-2", def.TaskID, def.AssignmentID, InteractionResponse, base.Add(2*time.Minute))
	responseDef.InReplyTo = question.EventID
	responseDef.Finality = ResponseFinal
	response := interactionEvent(t, responseDef, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatal(err)
	}
	correctionDef := interactionDefinition("correction-2", "interaction-2", def.TaskID, def.AssignmentID, InteractionCorrection, base.Add(3*time.Minute))
	correctionDef.InReplyTo = question.EventID
	correctionDef.Supersedes = response.EventID
	correctionDef.Finality = ResponseFinal
	correction := interactionEvent(t, correctionDef, other.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, correction); !errors.Is(err, ErrInvalidInteraction) {
		t.Fatalf("error = %v, want ErrInvalidInteraction", err)
	}
}

func TestInteractionAuthorizationBindsContent(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	def := interactionDefinition("question-1", "interaction-1", "task-1", "assignment-1", InteractionQuestion, base)
	auth := interactionAuth(def, "agent:owner", "runtime:owner")
	auth.ContentDigest = digest('f')
	if _, err := NewInteractionEvent(def, auth); !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("error = %v, want ErrAuthenticationRequired", err)
	}
}

func TestDetectDeadlockedTasks(t *testing.T) {
	t.Parallel()
	tasks := []TaskLiveness{{TaskID: "task-a"}, {TaskID: "task-b"}}
	dependencies := []Dependency{
		dependency("dep-a-b", "task-a", "task-b", "group-a", DependencyAll, 0),
		dependency("dep-b-a", "task-b", "task-a", "group-b", DependencyAll, 0),
	}
	deadlocked, err := DetectDeadlockedTasks(tasks, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(deadlocked, ",") != "task-a,task-b" {
		t.Fatalf("deadlocked = %v", deadlocked)
	}
}

func TestDetectDeadlockedTasksDoesNotTreatBreakableCycleAsDeadlock(t *testing.T) {
	t.Parallel()
	tasks := []TaskLiveness{
		{TaskID: "task-a"},
		{TaskID: "task-b"},
		{TaskID: "task-c", Runnable: true},
	}
	dependencies := []Dependency{
		dependency("dep-a-b", "task-a", "task-b", "group-a", DependencyAny, 0),
		dependency("dep-a-c", "task-a", "task-c", "group-a", DependencyAny, 0),
		dependency("dep-b-a", "task-b", "task-a", "group-b", DependencyAll, 0),
	}
	deadlocked, err := DetectDeadlockedTasks(tasks, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if len(deadlocked) != 0 {
		t.Fatalf("deadlocked = %v, want none", deadlocked)
	}
}

func TestDetectDeadlockedTasksHonorsExternalEscape(t *testing.T) {
	t.Parallel()
	tasks := []TaskLiveness{{TaskID: "task-a", ExternalEscape: true}, {TaskID: "task-b"}}
	dependencies := []Dependency{
		dependency("dep-a-b", "task-a", "task-b", "group-a", DependencyAll, 0),
		dependency("dep-b-a", "task-b", "task-a", "group-b", DependencyAll, 0),
	}
	deadlocked, err := DetectDeadlockedTasks(tasks, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if len(deadlocked) != 0 {
		t.Fatalf("deadlocked = %v, want none", deadlocked)
	}
}

func TestDetectDeadlockedTasksRejectsImpossibleQuorum(t *testing.T) {
	t.Parallel()
	tasks := []TaskLiveness{{TaskID: "task-a"}, {TaskID: "task-b"}}
	dependencies := []Dependency{
		dependency("dep-a-b", "task-a", "task-b", "group-a", DependencyQuorum, 2),
	}
	if _, err := DetectDeadlockedTasks(tasks, dependencies); err == nil {
		t.Fatal("DetectDeadlockedTasks() error = nil, want impossible quorum error")
	}
}

func acceptedAssignment(t *testing.T, assignee Participant, base time.Time) Assignment {
	t.Helper()
	def := definition("offer-parent", "assignment-parent", "task-parent", assignee.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:1", "service:orchestrator", def.TaskID, def.AssignmentID, base)
	offerAuth.TargetParticipantID = assignee.ParticipantID
	offered, err := Offer(def, assignee, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	at := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID: "accept-parent", Kind: OperationAccept, ExpectedRevision: 1, At: at,
		Auth: auth(OperationAccept, assignee.ParticipantID, "runtime:assignee", def.TaskID, def.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}
	return accepted.Assignment
}

func participant(id string, kind ParticipantKind, mayDelegate bool, at time.Time) Participant {
	return Participant{
		Schema:        ParticipantSchemaV1,
		ParticipantID: id,
		Kind:          kind,
		IdentityRef:   "identity:" + id,
		Status:        ParticipantActive,
		MayDelegate:   mayDelegate,
		RegisteredAt:  at,
	}
}

func definition(eventID, assignmentID, taskID, participantID, parentID, authorityDigest string, at time.Time) AssignmentDefinition {
	return AssignmentDefinition{
		EventID:            eventID,
		AssignmentID:       assignmentID,
		TaskID:             taskID,
		ParticipantID:      participantID,
		Role:               RoleAssignee,
		AuthorityDigest:    authorityDigest,
		ParentAssignmentID: parentID,
		OfferedAt:          at,
	}
}

func auth(kind OperationKind, participantID, actorID, taskID, assignmentID string, at time.Time) AuthenticatedOperation {
	return AuthenticatedOperation{
		ActorID:         actorID,
		ParticipantID:   participantID,
		AuthorizationID: "authorization:1",
		ProofID:         "proof:1",
		Operation:       kind,
		TaskID:          taskID,
		AssignmentID:    assignmentID,
		VerifierNonce:   "nonce:1",
		IssuedAt:        at.Add(-time.Second),
		ExpiresAt:       at.Add(time.Minute),
	}
}

func interactionDefinition(eventID, interactionID, taskID, assignmentID string, kind InteractionKind, at time.Time) InteractionEventDefinition {
	return InteractionEventDefinition{
		EventID:       eventID,
		InteractionID: interactionID,
		TaskID:        taskID,
		AssignmentID:  assignmentID,
		Kind:          kind,
		ContentRef:    "urn:content:" + eventID,
		ContentDigest: digest('c'),
		At:            at,
	}
}

func interactionAuth(def InteractionEventDefinition, participantID, actorID string) AuthenticatedInteraction {
	return AuthenticatedInteraction{
		ActorID:         actorID,
		ParticipantID:   participantID,
		AuthorizationID: "authorization:interaction-1",
		ProofID:         "proof:interaction-1",
		EventID:         def.EventID,
		InteractionID:   def.InteractionID,
		TaskID:          def.TaskID,
		AssignmentID:    def.AssignmentID,
		Kind:            def.Kind,
		InReplyTo:       def.InReplyTo,
		Supersedes:      def.Supersedes,
		Finality:        def.Finality,
		ContentRef:      def.ContentRef,
		ContentDigest:   def.ContentDigest,
		EvidenceRef:     def.EvidenceRef,
		At:              def.At,
		VerifierNonce:   "nonce:interaction-1",
		IssuedAt:        def.At.Add(-time.Second),
		ExpiresAt:       def.At.Add(time.Minute),
	}
}

func interactionEvent(t *testing.T, def InteractionEventDefinition, participantID, actorID string) InteractionEvent {
	t.Helper()
	event, err := NewInteractionEvent(def, interactionAuth(def, participantID, actorID))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func dependency(id, from, to, group string, mode DependencyMode, quorum uint32) Dependency {
	return Dependency{
		Schema:       DependencySchemaV1,
		DependencyID: id,
		FromTaskID:   from,
		ToTaskID:     to,
		GroupID:      group,
		Mode:         mode,
		Quorum:       quorum,
		Active:       true,
	}
}

func digest(r rune) string {
	return strings.Repeat(string(r), 64)
}
