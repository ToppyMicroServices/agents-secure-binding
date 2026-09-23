// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestDelegatedChildOfferRetryDoesNotPublishAnotherMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	parent, offered := offerFixture(t)
	parent.MayDelegate = true
	if err := s.RegisterParticipant(ctx, parent); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	accepted, err := taskcoord.Apply(offered.Assignment, taskEvent(offered.Assignment, taskcoord.OperationAccept, base.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
	child := parent
	child.ParticipantID, child.IdentityRef, child.MayDelegate = "human:child", "urn:identity:child", false
	if err := s.RegisterParticipant(ctx, child); err != nil {
		t.Fatal(err)
	}
	definition := taskcoord.AssignmentDefinition{
		EventID: "event:child", AssignmentID: "assignment:child", TaskID: "task:child",
		ParticipantID: child.ParticipantID, ParentAssignmentID: accepted.Assignment.AssignmentID,
		Role: taskcoord.RoleReviewer, AuthorityDigest: strings.Repeat("b", 64), OfferedAt: s.now(),
	}
	event := taskEvent(accepted.Assignment, taskcoord.OperationDelegate, s.now())
	event.Auth.TargetTaskID, event.Auth.TargetAssignmentID, event.Auth.TargetParticipantID = definition.TaskID, definition.AssignmentID, definition.ParticipantID
	delegated, err := taskcoord.Delegate(accepted.Assignment, parent, child, definition, event, taskcoord.VerifiedDelegation{
		DecisionID: "decision:child", ParentAssignmentID: accepted.Assignment.AssignmentID, ChildAssignmentID: definition.AssignmentID,
		FromParticipantID: parent.ParticipantID, ToParticipantID: child.ParticipantID,
		ParentAuthorityDigest: accepted.Assignment.AuthorityDigest, ChildAuthorityDigest: definition.AuthorityDigest,
		PolicyRef: "urn:policy:delegate", EvidenceRef: "urn:evidence:delegate", VerifiedAt: s.now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitDelegation(ctx, 2, delegated); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path, base.Add(3*time.Second))
	if err := s.CommitAssignment(ctx, 0, delegated.Child, delegated.ChildRecord); err != nil {
		t.Fatalf("historical delegated child retry: %v", err)
	}
	if err := s.CommitDelegation(ctx, 2, delegated); err != nil {
		t.Fatalf("historical delegation retry: %v", err)
	}
	if err := s.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatalf("historical parent offer retry: %v", err)
	}
	changedChild, changedRecord := delegated.Child, delegated.ChildRecord
	changedRecord.ProofID = "proof:changed"
	changedChild.LastTransition = changedRecord
	if err := s.CommitAssignment(ctx, 0, changedChild, changedRecord); !errors.Is(err, taskcoord.ErrEventConflict) {
		t.Fatalf("changed proof bypassed retry validation: %v", err)
	}
	deliveries, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:retry", LeaseID: "lease:retry", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 3 {
		t.Fatalf("expected parent offer, parent acceptance, and delegation only; got %d: %v", len(deliveries), err)
	}
	for _, delivery := range deliveries {
		if delivery.Event.EventID == delegated.ChildRecord.EventID {
			t.Fatal("retry published a standalone child offer after atomic delegation")
		}
		if err := s.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{
			DeliveryID: delivery.DeliveryID, ConsumerID: "worker:retry", LeaseID: "lease:retry",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CommitAssignment(ctx, 0, delegated.Child, delegated.ChildRecord); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitDelegation(ctx, 2, delegated); err != nil {
		t.Fatal(err)
	}
	deliveries, err = s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:retry", LeaseID: "lease:retry-again", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("retry republished acknowledged mutations: %d, %v", len(deliveries), err)
	}
}
