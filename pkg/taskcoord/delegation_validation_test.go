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

const (
	testOtherAgent = "agent:other"
)

func TestValidateAssignmentTransitionRejectsSnapshotAndHistoryRewrite(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:assignee", ParticipantAgent, false, base)
	current := acceptedAssignment(t, agent, base)
	at := current.UpdatedAt.Add(time.Minute)
	release, err := Apply(current, Event{
		ID: "release:validated", Kind: OperationRelease, ExpectedRevision: current.Revision, At: at,
		Auth: auth(OperationRelease, agent.ParticipantID, "runtime:assignee", current.TaskID, current.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*Transition)
	}{
		{name: "authority", mutate: func(got *Transition) {
			got.Assignment.AuthorityDigest = digest('f')
		}},
		{name: "task identity", mutate: func(got *Transition) {
			got.Assignment.TaskID = "task:rewritten"
			got.Record.TaskID = got.Assignment.TaskID
			got.Assignment.LastTransition = got.Record
		}},
		{name: "participant identity", mutate: func(got *Transition) {
			got.Assignment.ParticipantID = "agent:rewritten"
			got.Record.ParticipantID = got.Assignment.ParticipantID
			got.Assignment.LastTransition = got.Record
		}},
		{name: "offering participant", mutate: func(got *Transition) {
			got.Assignment.OfferedByParticipantID = "owner:rewritten"
		}},
		{name: "role", mutate: func(got *Transition) {
			got.Assignment.Role = RoleReviewer
		}},
		{name: "parent link", mutate: func(got *Transition) {
			got.Assignment.ParentAssignmentID = "assignment:invented-parent"
		}},
		{name: "created timestamp", mutate: func(got *Transition) {
			got.Assignment.CreatedAt = got.Assignment.CreatedAt.Add(-time.Second)
		}},
		{name: "accepted timestamp", mutate: func(got *Transition) {
			changed := current.AcceptedAt.Add(time.Second)
			got.Assignment.AcceptedAt = &changed
		}},
		{name: "due timestamp", mutate: func(got *Transition) {
			changed := got.Assignment.UpdatedAt.Add(time.Hour)
			got.Assignment.DueAt = &changed
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mutated := release
			test.mutate(&mutated)
			if err := mutated.Assignment.Validate(); err != nil {
				t.Fatalf("mutated fixture is not standalone-valid: %v", err)
			}
			if err := ValidateAssignmentTransition(current, mutated.Assignment, mutated.Record); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("ValidateAssignmentTransition() error = %v, want ErrInvalidTransition", err)
			}
		})
	}

	revoked, err := Apply(current, Event{
		ID: "revoke:forged-history", Kind: OperationRevoke, ExpectedRevision: current.Revision, At: at,
		Auth: auth(OperationRevoke, "owner:assignment", "gateway:orchestrator", current.TaskID, current.AssignmentID, at),
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked.Record.From = AssignmentOffered
	revoked.Assignment.AcceptedAt = nil
	revoked.Assignment.LastTransition = revoked.Record
	if err := revoked.Assignment.Validate(); err != nil {
		t.Fatalf("history-rewrite fixture is not standalone-valid: %v", err)
	}
	if err := ValidateAssignmentTransition(current, revoked.Assignment, revoked.Record); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("history rewrite error = %v, want ErrInvalidTransition", err)
	}
}

func TestMemoryStoreRejectsAssignmentAndDelegationParentRewrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:store-delegator", ParticipantAgent, true, base)
	human := participant("human:store-delegate", ParticipantHuman, false, base)
	store := NewMemoryStore()
	for _, candidate := range []Participant{agent, human} {
		if err := store.RegisterParticipant(ctx, candidate); err != nil {
			t.Fatal(err)
		}
	}
	parentDefinition := definition("offer:store-parent", "assignment:store-parent", "task:store-parent", agent.ParticipantID, "", digest('a'), base)
	offerAuth := auth(OperationOffer, "owner:store-parent", "gateway:orchestrator", parentDefinition.TaskID, parentDefinition.AssignmentID, base)
	offerAuth.TargetParticipantID = agent.ParticipantID
	offered, err := Offer(parentDefinition, agent, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	acceptedAt := base.Add(time.Minute)
	accepted, err := Apply(offered.Assignment, Event{
		ID: "accept:store-parent", Kind: OperationAccept, ExpectedRevision: offered.Assignment.Revision, At: acceptedAt,
		Auth: auth(OperationAccept, agent.ParticipantID, "runtime:store-delegator", offered.Assignment.TaskID, offered.Assignment.AssignmentID, acceptedAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, offered.Assignment.Revision, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}

	releasedAt := acceptedAt.Add(time.Minute)
	released, err := Apply(accepted.Assignment, Event{
		ID: "release:store-parent", Kind: OperationRelease, ExpectedRevision: accepted.Assignment.Revision, At: releasedAt,
		Auth: auth(OperationRelease, agent.ParticipantID, "runtime:store-delegator", accepted.Assignment.TaskID, accepted.Assignment.AssignmentID, releasedAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	released.Assignment.AuthorityDigest = digest('e')
	if err := store.CommitAssignment(ctx, accepted.Assignment.Revision, released.Assignment, released.Record); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("CommitAssignment(rewrite) error = %v, want ErrInvalidTransition", err)
	}

	delegatedAt := acceptedAt.Add(2 * time.Minute)
	childDefinition := definition("offer:store-child", "assignment:store-child", "task:store-child", human.ParticipantID, accepted.Assignment.AssignmentID, digest('b'), delegatedAt)
	delegationAuth := auth(OperationDelegate, agent.ParticipantID, "runtime:store-delegator", accepted.Assignment.TaskID, accepted.Assignment.AssignmentID, delegatedAt)
	delegationAuth.TargetTaskID = childDefinition.TaskID
	delegationAuth.TargetAssignmentID = childDefinition.AssignmentID
	delegationAuth.TargetParticipantID = childDefinition.ParticipantID
	delegation, err := Delegate(accepted.Assignment, agent, human, childDefinition,
		Event{ID: "delegate:store", Kind: OperationDelegate, ExpectedRevision: accepted.Assignment.Revision, At: delegatedAt, Auth: delegationAuth},
		VerifiedDelegation{
			DecisionID: "decision:store", ParentAssignmentID: accepted.Assignment.AssignmentID, ChildAssignmentID: childDefinition.AssignmentID,
			FromParticipantID: agent.ParticipantID, ToParticipantID: human.ParticipantID,
			ParentAuthorityDigest: accepted.Assignment.AuthorityDigest, ChildAuthorityDigest: childDefinition.AuthorityDigest,
			PolicyRef: "policy:store", EvidenceRef: "evidence:store", VerifiedAt: delegatedAt,
		})
	if err != nil {
		t.Fatal(err)
	}
	delegation.Parent.AuthorityDigest = digest('e')
	delegation.Delegation.ParentAuthorityDigest = digest('e')
	if err := store.CommitDelegation(ctx, accepted.Assignment.Revision, delegation); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("CommitDelegation(parent rewrite) error = %v, want ErrInvalidTransition", err)
	}
	stored, err := store.LoadAssignment(ctx, accepted.Assignment.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, accepted.Assignment) {
		t.Fatal("rejected rewrites changed the stored parent snapshot")
	}
}

func TestValidateDelegationCommitRejectsMutatedProvenanceBindings(t *testing.T) {
	t.Parallel()
	transition := validDelegationTransition(t)
	later := transition.Delegation.At.Add(time.Second)
	earlier := transition.Delegation.At.Add(-time.Second)

	tests := []struct {
		name   string
		mutate func(*DelegationTransition)
	}{
		{name: "parent task", mutate: func(got *DelegationTransition) {
			got.Delegation.ParentTaskID = "task:other-parent"
		}},
		{name: "child task", mutate: func(got *DelegationTransition) {
			got.Delegation.ChildTaskID = "task:other-child"
		}},
		{name: "from participant", mutate: func(got *DelegationTransition) {
			got.Delegation.FromParticipantID = testOtherAgent
		}},
		{name: "to participant", mutate: func(got *DelegationTransition) {
			got.Delegation.ToParticipantID = "human:other"
		}},
		{name: "parent authority", mutate: func(got *DelegationTransition) {
			got.Delegation.ParentAuthorityDigest = digest('c')
		}},
		{name: "child authority", mutate: func(got *DelegationTransition) {
			got.Delegation.ChildAuthorityDigest = digest('d')
		}},
		{name: "delegation timestamp", mutate: func(got *DelegationTransition) {
			got.Delegation.At = later
		}},
		{name: "parent record timestamp", mutate: func(got *DelegationTransition) {
			got.ParentRecord.At = later
			got.Parent.UpdatedAt = later
			got.Parent.LastTransition = got.ParentRecord
		}},
		{name: "child record timestamp", mutate: func(got *DelegationTransition) {
			got.ChildRecord.At = later
			got.Child.CreatedAt = later
			got.Child.UpdatedAt = later
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child created timestamp", mutate: func(got *DelegationTransition) {
			got.Child.CreatedAt = earlier
		}},
		{name: "child offered by", mutate: func(got *DelegationTransition) {
			got.Child.OfferedByParticipantID = testOtherAgent
		}},
		{name: "parent record kind and state", mutate: func(got *DelegationTransition) {
			got.ParentRecord.Kind = OperationRelease
			got.ParentRecord.To = AssignmentReleased
			got.ParentRecord.Reason.Code = OperationRelease
			got.Parent.Status = AssignmentReleased
			got.Parent.LastTransition = got.ParentRecord
		}},
		{name: "parent record origin", mutate: func(got *DelegationTransition) {
			got.ParentRecord.From = AssignmentOffered
			got.Parent.LastTransition = got.ParentRecord
		}},
		{name: "parent record participant", mutate: func(got *DelegationTransition) {
			got.ParentRecord.ParticipantID = testOtherAgent
			got.Parent.LastTransition = got.ParentRecord
		}},
		{name: "child record participant", mutate: func(got *DelegationTransition) {
			got.ChildRecord.ParticipantID = testOtherAgent
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child record actor", mutate: func(got *DelegationTransition) {
			got.ChildRecord.ActorID = "runtime:other"
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child record authorization", mutate: func(got *DelegationTransition) {
			got.ChildRecord.AuthorizationID = "authorization:other"
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child record proof", mutate: func(got *DelegationTransition) {
			got.ChildRecord.ProofID = "proof:other"
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child record reason detail", mutate: func(got *DelegationTransition) {
			got.ChildRecord.Reason.Detail = "injected"
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "child record evidence", mutate: func(got *DelegationTransition) {
			got.ChildRecord.EvidenceRef = "evidence:injected"
			got.Child.LastTransition = got.ChildRecord
		}},
		{name: "delegation event", mutate: func(got *DelegationTransition) {
			got.Delegation.EventID = "delegate:other"
		}},
		{name: "parent assignment", mutate: func(got *DelegationTransition) {
			got.Delegation.ParentAssignmentID = "assignment:other-parent"
		}},
		{name: "child assignment", mutate: func(got *DelegationTransition) {
			got.Delegation.ChildAssignmentID = "assignment:other-child"
		}},
		{name: "child parent link", mutate: func(got *DelegationTransition) {
			got.Child.ParentAssignmentID = "assignment:other-parent"
		}},
		{name: "reused child event", mutate: func(got *DelegationTransition) {
			got.ChildRecord.EventID = got.ParentRecord.EventID
			got.Child.LastTransition = got.ChildRecord
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			mutated := transition
			test.mutate(&mutated)
			if err := ValidateDelegationCommit(transition.Parent.Revision-1, mutated); !errors.Is(err, ErrInvalidDelegation) && !errors.Is(err, ErrInvalidAssignment) {
				t.Fatalf("ValidateDelegationCommit() error = %v, want invalid delegation or assignment", err)
			}
		})
	}
}

func validDelegationTransition(t *testing.T) DelegationTransition {
	t.Helper()
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	agent := participant("agent:delegator", ParticipantAgent, true, base)
	human := participant("human:delegate", ParticipantHuman, false, base)
	parent := acceptedAssignment(t, agent, base)
	at := parent.UpdatedAt.Add(time.Minute)
	child := definition("offer-child-validation", "assignment-child-validation", "task-child-validation", human.ParticipantID, parent.AssignmentID, digest('b'), at)
	operation := auth(OperationDelegate, agent.ParticipantID, "runtime:delegator", parent.TaskID, parent.AssignmentID, at)
	operation.AuthorizationID = "authorization:delegation"
	operation.ProofID = "proof:delegation"
	operation.TargetTaskID = child.TaskID
	operation.TargetAssignmentID = child.AssignmentID
	operation.TargetParticipantID = child.ParticipantID
	transition, err := Delegate(parent, agent, human, child,
		Event{ID: "delegate:validation", Kind: OperationDelegate, ExpectedRevision: parent.Revision, At: at, Auth: operation},
		VerifiedDelegation{
			DecisionID:            "decision:validation",
			ParentAssignmentID:    parent.AssignmentID,
			ChildAssignmentID:     child.AssignmentID,
			FromParticipantID:     agent.ParticipantID,
			ToParticipantID:       human.ParticipantID,
			ParentAuthorityDigest: parent.AuthorityDigest,
			ChildAuthorityDigest:  child.AuthorityDigest,
			PolicyRef:             "policy:delegation-validation",
			EvidenceRef:           "evidence:delegation-validation",
			VerifiedAt:            at,
		})
	if err != nil {
		t.Fatalf("Delegate() error = %v", err)
	}
	if err := ValidateDelegationCommit(parent.Revision, transition); err != nil {
		t.Fatalf("ValidateDelegationCommit(valid) error = %v", err)
	}
	return transition
}
