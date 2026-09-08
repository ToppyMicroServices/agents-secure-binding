// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestOutboxEventBindsCanonicalAssignmentTransition(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	human := participant("human:outbox", ParticipantHuman, false, base)
	def := definition("offer-outbox", "assignment-outbox", "task-outbox", human.ParticipantID, "", digest('a'), base)
	authorization := auth(OperationOffer, "owner:outbox", "gateway:outbox", def.TaskID, def.AssignmentID, base)
	authorization.TargetParticipantID = human.ParticipantID
	transition, err := Offer(def, human, authorization)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(transition)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	event := OutboxEvent{
		Schema: OutboxEventSchemaV1, EventID: transition.Record.EventID,
		Kind: OutboxAssignmentTransition, TaskID: transition.Assignment.TaskID,
		AssignmentID: transition.Assignment.AssignmentID, ParticipantID: transition.Assignment.ParticipantID,
		Payload: payload, PayloadDigest: hex.EncodeToString(sum[:]), OccurredAt: transition.Record.At,
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	tampered := event
	tampered.Payload = append(json.RawMessage(nil), payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if err := tampered.Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("tampered Validate() error = %v, want ErrInvalidEvent", err)
	}
}

func TestValidateInteractionAppendRejectsTimestampRegression(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	human := participant("human:interaction", ParticipantHuman, false, base)
	assignment := acceptedAssignment(t, human, base)
	questionDef := interactionDefinition("question-outbox", "interaction-outbox", assignment.TaskID, assignment.AssignmentID, InteractionQuestion, base.Add(3*time.Minute))
	question := interactionEvent(t, questionDef, "agent:owner", "runtime:owner")
	responseDef := interactionDefinition("response-outbox", question.InteractionID, assignment.TaskID, assignment.AssignmentID, InteractionResponse, base.Add(2*time.Minute))
	responseDef.InReplyTo = question.EventID
	responseDef.Finality = ResponseFinal
	response := interactionEvent(t, responseDef, human.ParticipantID, "gateway:human")
	if err := ValidateInteractionAppend(response, assignment, human, &question, nil); !errors.Is(err, ErrInvalidInteraction) {
		t.Fatalf("ValidateInteractionAppend() error = %v, want ErrInvalidInteraction", err)
	}
}

func TestOutboxRequestValidationIsBounded(t *testing.T) {
	t.Parallel()
	if err := (OutboxPoll{ConsumerID: "publisher:1", LeaseID: "lease:1", Limit: 1, LeaseDuration: time.Second}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (OutboxPoll{ConsumerID: "publisher:1", LeaseID: "lease:1", Limit: 0, LeaseDuration: time.Second}).Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("zero-limit error = %v", err)
	}
	if err := (OutboxAcknowledgement{DeliveryID: "delivery:1", ConsumerID: "publisher:1", LeaseID: "lease:1"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (OutboxAcknowledgement{DeliveryID: "delivery:1", LeaseID: "lease:1"}).Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("missing-consumer error = %v, want ErrInvalidEvent", err)
	}
}
