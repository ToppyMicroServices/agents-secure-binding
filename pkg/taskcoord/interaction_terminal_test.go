// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestTerminalAssignmentAllowsAuthorizedInteractionAppend(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	owner := participant("agent:terminal-owner", ParticipantAgent, false, base)
	human := participant("human:terminal-assignee", ParticipantHuman, false, base)
	other := participant("human:terminal-other", ParticipantHuman, false, base)
	store := NewMemoryStore()
	for _, candidate := range []Participant{owner, human, other} {
		if err := store.RegisterParticipant(ctx, candidate); err != nil {
			t.Fatal(err)
		}
	}

	definition := definition(
		"event:terminal:offer",
		"assignment:terminal-history",
		"task:terminal-history",
		human.ParticipantID,
		"",
		digest('d'),
		base,
	)
	offerAuth := auth(
		OperationOffer,
		owner.ParticipantID,
		"runtime:terminal-owner",
		definition.TaskID,
		definition.AssignmentID,
		base,
	)
	offerAuth.TargetParticipantID = human.ParticipantID
	offered, err := Offer(definition, human, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}

	acceptedAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID:               "event:terminal:accept",
		Kind:             OperationAccept,
		ExpectedRevision: offered.Assignment.Revision,
		At:               acceptedAt,
		Auth: auth(
			OperationAccept,
			human.ParticipantID,
			"service:human-gateway",
			definition.TaskID,
			definition.AssignmentID,
			acceptedAt,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(
		ctx,
		offered.Assignment.Revision,
		accepted.Assignment,
		accepted.Record,
	); err != nil {
		t.Fatal(err)
	}

	fulfilledAt := base.Add(2 * time.Minute)
	fulfilled, err := Apply(accepted.Assignment, Event{
		ID:               "event:terminal:fulfill",
		Kind:             OperationFulfill,
		ExpectedRevision: accepted.Assignment.Revision,
		At:               fulfilledAt,
		Auth: auth(
			OperationFulfill,
			human.ParticipantID,
			"service:human-gateway",
			definition.TaskID,
			definition.AssignmentID,
			fulfilledAt,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(
		ctx,
		accepted.Assignment.Revision,
		fulfilled.Assignment,
		fulfilled.Record,
	); err != nil {
		t.Fatal(err)
	}
	if !fulfilled.Assignment.Status.Terminal() {
		t.Fatalf("Assignment status = %s, want terminal", fulfilled.Assignment.Status)
	}
	terminalSnapshot := fulfilled.Assignment

	questionDefinition := interactionDefinition(
		"event:terminal:question",
		"interaction:terminal-history",
		definition.TaskID,
		definition.AssignmentID,
		InteractionQuestion,
		base.Add(3*time.Minute),
	)
	question := interactionEvent(t, questionDefinition, owner.ParticipantID, "runtime:terminal-owner")
	if err := store.AppendInteractionEvent(ctx, question); err != nil {
		t.Fatalf("append question after terminal Assignment: %v", err)
	}

	badLineageDefinition := interactionDefinition(
		"event:terminal:bad-lineage",
		question.InteractionID,
		definition.TaskID,
		definition.AssignmentID,
		InteractionResponse,
		base.Add(4*time.Minute),
	)
	badLineageDefinition.InReplyTo = "event:terminal:missing"
	badLineageDefinition.Finality = ResponseFinal
	badLineage := interactionEvent(t, badLineageDefinition, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, badLineage); !errors.Is(err, ErrInvalidInteraction) {
		t.Fatalf("bad lineage error = %v, want ErrInvalidInteraction", err)
	}

	responseDefinition := interactionDefinition(
		"event:terminal:response",
		question.InteractionID,
		definition.TaskID,
		definition.AssignmentID,
		InteractionResponse,
		base.Add(5*time.Minute),
	)
	responseDefinition.InReplyTo = question.EventID
	responseDefinition.Finality = ResponseFinal
	response := interactionEvent(t, responseDefinition, human.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, response); err != nil {
		t.Fatalf("append response after terminal Assignment: %v", err)
	}

	wrongAuthorDefinition := interactionDefinition(
		"event:terminal:wrong-author",
		question.InteractionID,
		definition.TaskID,
		definition.AssignmentID,
		InteractionCorrection,
		base.Add(6*time.Minute),
	)
	wrongAuthorDefinition.InReplyTo = question.EventID
	wrongAuthorDefinition.Supersedes = response.EventID
	wrongAuthorDefinition.Finality = ResponseFinal
	wrongAuthor := interactionEvent(t, wrongAuthorDefinition, other.ParticipantID, "service:human-gateway")
	if err := store.AppendInteractionEvent(ctx, wrongAuthor); !errors.Is(err, ErrInvalidInteraction) {
		t.Fatalf("wrong author error = %v, want ErrInvalidInteraction", err)
	}

	history, err := store.ListInteractionEvents(ctx, question.InteractionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[0].EventID != question.EventID || history[1].EventID != response.EventID {
		t.Fatalf("terminal interaction history = %+v", history)
	}
	storedAssignment, err := store.LoadAssignment(ctx, definition.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(storedAssignment, terminalSnapshot) {
		t.Fatalf(
			"interaction append mutated terminal Assignment: got %+v, want %+v",
			storedAssignment,
			terminalSnapshot,
		)
	}
}
