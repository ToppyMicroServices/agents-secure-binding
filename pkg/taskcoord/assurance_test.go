// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestAssuranceProvenanceAcceptsOnlyImplementedProfilePair(t *testing.T) {
	t.Parallel()
	if err := (AssuranceProvenance{
		ProfileID:      HumanRequestProfileV1,
		AssuranceLevel: HumanAssuranceGatewayAssertedForHuman,
	}).Validate(); err != nil {
		t.Fatalf("implemented assurance rejected: %v", err)
	}

	for name, provenance := range map[string]AssuranceProvenance{
		"missing profile": {
			AssuranceLevel: HumanAssuranceGatewayAssertedForHuman,
		},
		"missing level": {
			ProfileID: HumanRequestProfileV1,
		},
		"unsupported profile": {
			ProfileID:      "asb.other-human-profile/v1",
			AssuranceLevel: HumanAssuranceGatewayAssertedForHuman,
		},
		"unimplemented elevation": {
			ProfileID:      HumanRequestProfileV1,
			AssuranceLevel: HumanAssuranceHumanHeldKeyExactRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := provenance.Validate(); err == nil {
				t.Fatal("unsupported assurance provenance was accepted")
			}
		})
	}
}

func TestAssuranceProvenanceFlowsIntoDetachedAuditRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	at := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	human := participant("human:assurance", ParticipantHuman, false, at.Add(-time.Hour))
	store := NewMemoryStore()
	if err := store.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}

	def := definition("event:assurance:offer", "assignment:assurance", "task:assurance", human.ParticipantID, "", digest('a'), at)
	operation := auth(OperationOffer, "owner:assurance", "gateway:assurance", def.TaskID, def.AssignmentID, at)
	operation.TargetParticipantID = human.ParticipantID
	operation.Assurance = GatewayAssertedForHumanProvenance()
	offered, err := Offer(def, human, operation)
	if err != nil {
		t.Fatal(err)
	}
	if offered.Record.Assurance == nil || *offered.Record.Assurance != *operation.Assurance {
		t.Fatalf("offer assurance = %#v", offered.Record.Assurance)
	}
	if offered.Record.Assurance == operation.Assurance {
		t.Fatal("durable record aliases trusted projection assurance")
	}
	operation.Assurance.AssuranceLevel = HumanAssuranceHumanHeldKeyExactRequest
	if offered.Record.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatal("projection mutation changed durable record")
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadAssignment(ctx, def.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LastTransition.Assurance == nil ||
		loaded.LastTransition.Assurance.ProfileID != HumanRequestProfileV1 ||
		loaded.LastTransition.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatalf("stored transition assurance = %#v", loaded.LastTransition.Assurance)
	}
	loaded.LastTransition.Assurance.AssuranceLevel = HumanAssuranceHumanHeldKeyExactRequest
	reloaded, err := store.LoadAssignment(ctx, def.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.LastTransition.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatal("loaded snapshot aliases stored assurance")
	}

	interactionDef := interactionDefinition(
		"event:assurance:question", "interaction:assurance", def.TaskID, def.AssignmentID,
		InteractionQuestion, at.Add(time.Minute),
	)
	interactionAuthorization := interactionAuth(interactionDef, human.ParticipantID, "gateway:assurance")
	interactionAuthorization.Assurance = GatewayAssertedForHumanProvenance()
	event, err := NewInteractionEvent(interactionDef, interactionAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AppendInteractionEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	storedEvent, err := store.LoadInteractionEvent(ctx, event.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if storedEvent.Assurance == nil || *storedEvent.Assurance != *interactionAuthorization.Assurance {
		t.Fatalf("stored interaction assurance = %#v", storedEvent.Assurance)
	}
	storedEvent.Assurance.AssuranceLevel = HumanAssuranceAuthenticatedHumanEvidence
	reloadedEvent, err := store.LoadInteractionEvent(ctx, event.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedEvent.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatal("loaded interaction aliases stored assurance")
	}
}

func TestAssuranceProvenanceFlowsIntoDetachedDelegationRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	delegator := participant("agent:assurance-delegator", ParticipantAgent, true, base.Add(-time.Hour))
	target := participant("human:assurance-target", ParticipantHuman, false, base.Add(-time.Hour))
	store := NewMemoryStore()
	for _, value := range []Participant{delegator, target} {
		if err := store.RegisterParticipant(ctx, value); err != nil {
			t.Fatal(err)
		}
	}

	parentDef := definition("event:assurance:parent-offer", "assignment:assurance-parent", "task:assurance-parent", delegator.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:assurance", "gateway:assurance", parentDef.TaskID, parentDef.AssignmentID, base)
	offerAuth.TargetParticipantID = delegator.ParticipantID
	offered, err := Offer(parentDef, delegator, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}

	acceptedAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID:               "event:assurance:parent-accept",
		Kind:             OperationAccept,
		ExpectedRevision: offered.Assignment.Revision,
		At:               acceptedAt,
		Auth:             auth(OperationAccept, delegator.ParticipantID, "runtime:assurance", parentDef.TaskID, parentDef.AssignmentID, acceptedAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, offered.Assignment.Revision, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}

	delegatedAt := acceptedAt.Add(time.Minute)
	childDef := definition("event:assurance:child-offer", "assignment:assurance-child", "task:assurance-child", target.ParticipantID, accepted.Assignment.AssignmentID, digest('b'), delegatedAt)
	delegateAuth := auth(OperationDelegate, delegator.ParticipantID, "gateway:assurance", accepted.Assignment.TaskID, accepted.Assignment.AssignmentID, delegatedAt)
	delegateAuth.TargetTaskID = childDef.TaskID
	delegateAuth.TargetAssignmentID = childDef.AssignmentID
	delegateAuth.TargetParticipantID = childDef.ParticipantID
	delegateAuth.Assurance = GatewayAssertedForHumanProvenance()
	transition, err := Delegate(
		accepted.Assignment,
		delegator,
		target,
		childDef,
		Event{ID: "event:assurance:delegate", Kind: OperationDelegate, ExpectedRevision: accepted.Assignment.Revision, At: delegatedAt, Auth: delegateAuth},
		VerifiedDelegation{
			DecisionID:            "decision:assurance:delegate",
			ParentAssignmentID:    accepted.Assignment.AssignmentID,
			ChildAssignmentID:     childDef.AssignmentID,
			FromParticipantID:     delegator.ParticipantID,
			ToParticipantID:       target.ParticipantID,
			ParentAuthorityDigest: accepted.Assignment.AuthorityDigest,
			ChildAuthorityDigest:  childDef.AuthorityDigest,
			PolicyRef:             "urn:policy:assurance:delegation",
			EvidenceRef:           "urn:evidence:assurance:delegation",
			VerifiedAt:            delegatedAt,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, provenance := range map[string]*AssuranceProvenance{
		"parent transition": transition.ParentRecord.Assurance,
		"child transition":  transition.ChildRecord.Assurance,
		"delegation edge":   transition.Delegation.Assurance,
	} {
		if provenance == nil || *provenance != *delegateAuth.Assurance {
			t.Fatalf("%s assurance = %#v", name, provenance)
		}
		if provenance == delegateAuth.Assurance {
			t.Fatalf("%s aliases trusted projection assurance", name)
		}
	}
	delegateAuth.Assurance.AssuranceLevel = HumanAssuranceHumanHeldKeyExactRequest
	if transition.Delegation.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatal("projection mutation changed delegation assurance")
	}

	mismatched := transition
	mismatched.Delegation.Assurance = nil
	if err := store.CommitDelegation(ctx, accepted.Assignment.Revision, mismatched); !errors.Is(err, ErrInvalidDelegation) {
		t.Fatalf("CommitDelegation(mismatched assurance) error = %v, want ErrInvalidDelegation", err)
	}
	if err := store.CommitDelegation(ctx, accepted.Assignment.Revision, transition); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitDelegation(ctx, accepted.Assignment.Revision, transition); err != nil {
		t.Fatalf("exact delegation retry failed: %v", err)
	}
	loaded, err := store.LoadDelegation(ctx, transition.Delegation.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Assurance == nil || *loaded.Assurance != *transition.Delegation.Assurance {
		t.Fatalf("stored delegation assurance = %#v", loaded.Assurance)
	}
	if loaded.Assurance == transition.Delegation.Assurance {
		t.Fatal("loaded delegation aliases caller record assurance")
	}
	loaded.Assurance.AssuranceLevel = HumanAssuranceAuthenticatedHumanEvidence
	reloaded, err := store.LoadDelegation(ctx, transition.Delegation.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Assurance.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		t.Fatal("loaded delegation aliases stored assurance")
	}
}

func TestAssuranceProvenanceJSONKeepsLegacyRecordsUnspecified(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	record := TransitionRecord{
		EventID: "event:legacy", AssignmentID: "assignment:legacy", TaskID: "task:legacy",
		Revision: 1, Kind: OperationOffer, To: AssignmentOffered,
		Reason: Reason{Code: OperationOffer}, At: at, ActorID: "actor:legacy",
		ParticipantID: "participant:legacy", AuthorizationID: "authorization:legacy", ProofID: "proof:legacy",
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"assurance"`)) {
		t.Fatalf("legacy record acquired assurance: %s", raw)
	}
	var decoded TransitionRecord
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Assurance != nil {
		t.Fatalf("legacy assurance = %#v, want nil", decoded.Assurance)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("legacy record rejected: %v", err)
	}

	invalid := record
	invalid.Assurance = &AssuranceProvenance{
		ProfileID:      HumanRequestProfileV1,
		AssuranceLevel: HumanAssuranceHumanHeldKeyExactRequest,
	}
	if err := invalid.Validate(); err == nil {
		t.Fatal("durable record accepted an unimplemented assurance elevation")
	}
	operation := auth(OperationOffer, "participant:legacy", "actor:legacy", record.TaskID, record.AssignmentID, at)
	operation.TargetParticipantID = "human:legacy"
	operation.Assurance = invalid.Assurance
	human := participant("human:legacy", ParticipantHuman, false, at.Add(-time.Hour))
	def := definition(record.EventID, record.AssignmentID, record.TaskID, human.ParticipantID, "", digest('a'), at)
	if _, err := Offer(def, human, operation); !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("Offer() error = %v, want ErrAuthenticationRequired", err)
	}
}
