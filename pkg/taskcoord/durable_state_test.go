// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestDurableTaskStatePreservesHistoryAndDeduplication(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, offered, accepted := durableTaskFixture(t)
	at := accepted.Record.At.Add(time.Second)
	question := interactionEvent(t, interactionDefinition("question:stored", "interaction:stored", accepted.Assignment.TaskID,
		accepted.Assignment.AssignmentID, InteractionQuestion, at), accepted.Assignment.ParticipantID, "service:gateway")
	if err := store.AppendInteractionEvent(ctx, question); err != nil {
		t.Fatal(err)
	}
	responseDef := interactionDefinition("response:stored", question.InteractionID, question.TaskID, question.AssignmentID, InteractionResponse, at.Add(time.Second))
	responseDef.InReplyTo = question.EventID
	responseDef.Finality = ResponseFinal
	response := interactionEvent(t, responseDef, accepted.Assignment.ParticipantID, "service:gateway")
	if err := store.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatal(err)
	}
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMemoryStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatalf("historical offer retry after restore: %v", err)
	}
	if err := restored.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatalf("acceptance retry after restore: %v", err)
	}
	if err := restored.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatalf("interaction retry after restore: %v", err)
	}
	history, err := restored.ListInteractionEvents(ctx, question.InteractionID)
	if err != nil || !reflect.DeepEqual(history, []InteractionEvent{question, response}) {
		t.Fatalf("interaction order/provenance changed: %+v, %v", history, err)
	}
	changed := response
	changed.ProofID = "proof:different"
	if err := restored.AppendInteractionEvent(ctx, changed); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("changed interaction proof accepted: %v", err)
	}
	assignments := restored.Assignments()
	assignments[0].AcceptedAt = nil
	assignments[0].LastTransition.ProofID = "proof:changed"
	got, err := restored.LoadAssignment(ctx, accepted.Assignment.AssignmentID)
	if err != nil || !reflect.DeepEqual(got, accepted.Assignment) {
		t.Fatalf("exported Assignment aliases authoritative data: %+v, %v", got, err)
	}
	roundTrip, err := restored.ExportState()
	if err != nil || string(roundTrip) != string(raw) {
		t.Fatalf("stored canonical state changed after restore: %v", err)
	}
}

func TestDurableTaskStateRejectsCorruption(t *testing.T) {
	t.Parallel()
	store, _, accepted := durableTaskFixture(t)
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*durableTaskState){
		"version":     func(s *durableTaskState) { s.Schema = "asb.taskcoord-store/v2" },
		"missing map": func(s *durableTaskState) { s.Events = nil },
		"lost event":  func(s *durableTaskState) { delete(s.Events, accepted.Record.EventID) },
		"changed historical hash": func(s *durableTaskState) {
			for id, event := range s.Events {
				event.SnapshotHash = digest('f')
				s.Events[id] = event
				break
			}
		},
		"unindexed interaction": func(s *durableTaskState) { s.InteractionEvents["orphan"] = InteractionEvent{} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var state durableTaskState
			if err := json.Unmarshal(raw, &state); err != nil {
				t.Fatal(err)
			}
			mutate(&state)
			changed, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RestoreMemoryStore(changed); err == nil {
				t.Fatal("corrupt state was restored")
			}
		})
	}
	for _, bad := range [][]byte{
		[]byte("null"), []byte("{}"), append(append([]byte(nil), raw...), []byte(" {}")...),
		append([]byte(`{"schema":"duplicate",`), raw[1:]...),
		append([]byte(`{"unknown":true,`), raw[1:]...),
	} {
		if _, err := RestoreMemoryStore(bad); err == nil {
			t.Fatalf("malformed state was restored: %q", bad)
		}
	}
	if empty, err := RestoreMemoryStore(nil); err != nil || len(empty.Assignments()) != 0 {
		t.Fatalf("empty store: %v", err)
	}
}

func TestDurableTaskStatePreservesDelegationAfterParentRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, _, accepted := durableTaskFixture(t)
	parent, err := store.LoadParticipant(ctx, accepted.Assignment.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	at := accepted.Record.At.Add(time.Second)
	child := participant("human:child", ParticipantHuman, false, at)
	if err := store.RegisterParticipant(ctx, child); err != nil {
		t.Fatal(err)
	}
	def := definition("event:offer:child", "assignment:child", "task:child", child.ParticipantID, accepted.Assignment.AssignmentID, digest('b'), at)
	delegateAuth := auth(OperationDelegate, parent.ParticipantID, "service:gateway", accepted.Assignment.TaskID, accepted.Assignment.AssignmentID, at)
	delegateAuth.TargetTaskID, delegateAuth.TargetAssignmentID, delegateAuth.TargetParticipantID = def.TaskID, def.AssignmentID, def.ParticipantID
	delegated, err := Delegate(accepted.Assignment, parent, child, def, Event{
		ID: "event:delegate:stored", Kind: OperationDelegate, ExpectedRevision: 2, At: at, Auth: delegateAuth,
	}, VerifiedDelegation{
		DecisionID: "decision:stored", ParentAssignmentID: accepted.Assignment.AssignmentID, ChildAssignmentID: def.AssignmentID,
		FromParticipantID: parent.ParticipantID, ToParticipantID: child.ParticipantID,
		ParentAuthorityDigest: accepted.Assignment.AuthorityDigest, ChildAuthorityDigest: def.AuthorityDigest,
		PolicyRef: "urn:policy:stored", EvidenceRef: "urn:evidence:stored", VerifiedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitDelegation(ctx, 2, delegated); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Second)
	revoked, err := Apply(delegated.Parent, Event{
		ID: "event:revoke:stored", Kind: OperationRevoke, ExpectedRevision: 3, At: at,
		Auth: auth(OperationRevoke, parent.ParticipantID, "service:gateway", delegated.Parent.TaskID, delegated.Parent.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 3, revoked.Assignment, revoked.Record); err != nil {
		t.Fatal(err)
	}
	raw, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMemoryStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.CommitDelegation(ctx, 2, delegated); err != nil {
		t.Fatalf("historical delegation retry: %v", err)
	}
	got, err := restored.LoadDelegation(ctx, delegated.Delegation.EventID)
	if err != nil || !reflect.DeepEqual(got, delegated.Delegation) {
		t.Fatalf("delegation provenance changed: %+v, %v", got, err)
	}
	current, err := restored.LoadAssignment(ctx, accepted.Assignment.AssignmentID)
	if err != nil || current.Status != AssignmentRevoked {
		t.Fatalf("historical delegation changed current responsibility: %+v, %v", current, err)
	}
}

func durableTaskFixture(t *testing.T) (*MemoryStore, Transition, Transition) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 9, 20, 8, 0, 0, 0, time.UTC)
	human := participant("human:stored", ParticipantHuman, true, at)
	store := NewMemoryStore()
	if err := store.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}
	def := definition("event:offer:stored", "assignment:stored", "task:stored", human.ParticipantID, "", digest('a'), at)
	offerAuth := auth(OperationOffer, "human:owner", "service:gateway", def.TaskID, def.AssignmentID, at)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(def, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	at = at.Add(time.Second)
	accepted, err := Apply(offered.Assignment, Event{
		ID: "event:accept:stored", Kind: OperationAccept, ExpectedRevision: 1, At: at,
		Auth: auth(OperationAccept, human.ParticipantID, "service:gateway", def.TaskID, def.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
	return store, offered, accepted
}
