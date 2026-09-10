// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilegebinding

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	otherAssignmentID = "assignment-other"
	otherTaskID       = "task-other"
)

type bindingFixture struct {
	now        time.Time
	problem    lp.Problem
	solution   lp.Solution
	mandate    lp.Mandate
	capability lp.Capability
	key        ed25519.PublicKey
	privateKey ed25519.PrivateKey
	delegation Delegation
	uses       *lp.MemoryUseStore
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	f := bindingFixture{
		now: time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC),
		problem: lp.Problem{
			Schema:      lp.ProblemSchemaV1,
			Permissions: []lp.Permission{{ID: "read", Cost: 1}, {ID: "write", Cost: 10}},
			Grants:      []lp.Grant{{ID: "reader", Permissions: []string{"read"}}, {ID: "writer", Permissions: []string{"read", "write"}}},
			Required:    []string{"read"}, Allowed: []string{"read", "write"},
		},
	}
	var err error
	f.solution, err = lp.Solve(context.Background(), f.problem, 4)
	if err != nil {
		t.Fatal(err)
	}
	child, err := EffectiveAuthorityDigest(f.solution.ProblemDigest, f.solution.Effective)
	if err != nil {
		t.Fatal(err)
	}
	f.delegation = Delegation{
		ParentAssignmentID: "assignment-parent", ChildAssignmentID: "assignment-child",
		ParentTaskID: "task-parent", ChildTaskID: "task-child",
		FromParticipantID: "agent:a", ToParticipantID: "agent:b",
		ParentAuthorityDigest: strings.TrimPrefix(f.solution.ProblemDigest, "sha256:"), ChildAuthorityDigest: child,
	}
	f.key, f.privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.mandate = lp.Mandate{
		ID: "mandate:delegation-1", PolicyRef: "policy:preapproved-read", ActorID: "runtime:agent-a",
		TaskID: f.delegation.ParentTaskID, ProblemDigest: f.solution.ProblemDigest,
		NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), MaxTTLSeconds: 120, AllowAutomatic: true,
	}
	f.issue(t)
	f.uses, err = lp.NewMemoryUseStore(10)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *bindingFixture) issue(t *testing.T) {
	t.Helper()
	action, err := Action(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	f.mandate.ActionDigest, err = lp.DigestAction(action)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := lp.NewAuthorizer(lp.AuthorizerConfig{
		Problem: f.problem, Mandate: f.mandate, SigningKey: f.privateKey, MaxEvaluations: 4, Clock: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.capability, err = authorizer.Authorize(context.Background(), lp.Request{
		ActorID: f.mandate.ActorID, TaskID: f.delegation.ParentTaskID, Action: action,
	}, f.solution)
	if err != nil {
		t.Fatal(err)
	}
}

func fixtureAuth(kind taskcoord.OperationKind, participant, actor, task, assignment string, at time.Time) taskcoord.AuthenticatedOperation {
	return taskcoord.AuthenticatedOperation{
		ActorID: actor, ParticipantID: participant, AuthorizationID: "authorization:1", ProofID: "proof:1",
		Operation: kind, TaskID: task, AssignmentID: assignment, VerifierNonce: "nonce:1",
		IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
	}
}

func TestVerifiedCapabilityProjectionEvidence(t *testing.T) {
	f := newBindingFixture(t)
	ctx := context.Background()
	verified, err := Verify(ctx, f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := lp.DigestCapability(f.capability)
	if err != nil {
		t.Fatal(err)
	}
	if verified.DecisionID != f.capability.Claims.ID || verified.PolicyRef != f.mandate.PolicyRef ||
		verified.EvidenceRef != "urn:asb:least-privilege:"+evidence || !verified.VerifiedAt.Equal(f.now) {
		t.Fatalf("incorrect policy evidence projection: %+v", verified)
	}
}

func taskCoordInput(t *testing.T, f bindingFixture) (Input, *taskcoord.MemoryStore) {
	t.Helper()
	ctx := context.Background()
	base := f.now.Add(-2 * time.Minute)
	from := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: f.delegation.FromParticipantID,
		Kind: taskcoord.ParticipantAgent, IdentityRef: "identity:agent-a", Status: taskcoord.ParticipantActive, MayDelegate: true, RegisteredAt: base,
	}
	to := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: f.delegation.ToParticipantID,
		Kind: taskcoord.ParticipantAgent, IdentityRef: "identity:agent-b", Status: taskcoord.ParticipantActive, RegisteredAt: base,
	}
	store := taskcoord.NewMemoryStore()
	for _, participant := range []taskcoord.Participant{from, to} {
		if err := store.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}
	parentDef := taskcoord.AssignmentDefinition{
		EventID: "offer-parent", AssignmentID: f.delegation.ParentAssignmentID,
		TaskID: f.delegation.ParentTaskID, ParticipantID: from.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: f.delegation.ParentAuthorityDigest, OfferedAt: base,
	}
	offerAuth := fixtureAuth(taskcoord.OperationOffer, "owner:1", "service:orchestrator", parentDef.TaskID, parentDef.AssignmentID, base)
	offerAuth.TargetParticipantID = from.ParticipantID
	offered, err := taskcoord.Offer(parentDef, from, offerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	acceptAt := base.Add(time.Minute)
	accepted, err := taskcoord.Apply(offered.Assignment, taskcoord.Event{
		ID: "accept-parent", Kind: taskcoord.OperationAccept, ExpectedRevision: 1, At: acceptAt,
		Auth: fixtureAuth(taskcoord.OperationAccept, from.ParticipantID, f.mandate.ActorID, parentDef.TaskID, parentDef.AssignmentID, acceptAt),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
	childDef := taskcoord.AssignmentDefinition{
		EventID: "offer-child", AssignmentID: f.delegation.ChildAssignmentID,
		TaskID: f.delegation.ChildTaskID, ParticipantID: to.ParticipantID, ParentAssignmentID: parentDef.AssignmentID,
		Role: taskcoord.RoleAssignee, AuthorityDigest: f.delegation.ChildAuthorityDigest, OfferedAt: f.now,
	}
	delegateAuth := fixtureAuth(taskcoord.OperationDelegate, from.ParticipantID, f.mandate.ActorID, parentDef.TaskID, parentDef.AssignmentID, f.now)
	delegateAuth.TargetTaskID, delegateAuth.TargetAssignmentID, delegateAuth.TargetParticipantID = childDef.TaskID, childDef.AssignmentID, to.ParticipantID
	return Input{Parent: accepted.Assignment, Delegator: from, Target: to, Child: childDef, Event: taskcoord.Event{
		ID: "delegate-1", Kind: taskcoord.OperationDelegate, ExpectedRevision: accepted.Assignment.Revision, At: f.now, Auth: delegateAuth,
	}}, store
}

func TestVerifiedCapabilityCommitsTaskCoordDelegation(t *testing.T) {
	f := newBindingFixture(t)
	ctx := context.Background()
	in, store := taskCoordInput(t, f)
	transition, err := Delegate(ctx, in, f.capability, f.key, f.mandate, f.now, f.uses)
	if err != nil {
		t.Fatalf("checked proof rejected by TaskCoord: %v", err)
	}
	if err := store.CommitDelegation(ctx, in.Parent.Revision, transition); err != nil {
		t.Fatal(err)
	}
	child, err := store.LoadAssignment(ctx, in.Child.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.LoadAssignment(ctx, in.Parent.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Status != taskcoord.AssignmentAccepted || child.Status != taskcoord.AssignmentOffered ||
		child.ParentAssignmentID != parent.AssignmentID || child.AuthorityDigest != f.delegation.ChildAuthorityDigest {
		t.Fatalf("wrong committed responsibility/authority: parent=%+v, child=%+v", parent, child)
	}
	if _, err := Verify(ctx, f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses); !errors.Is(err, lp.ErrReplay) {
		t.Fatalf("used capability was accepted again: %v", err)
	}
}

func TestBindingTamperingDoesNotConsumeMandate(t *testing.T) {
	tests := map[string]func(*Delegation){
		"parent assignment":  func(d *Delegation) { d.ParentAssignmentID = otherAssignmentID },
		"child assignment":   func(d *Delegation) { d.ChildAssignmentID = otherAssignmentID },
		"parent task":        func(d *Delegation) { d.ParentTaskID = otherTaskID },
		"child task":         func(d *Delegation) { d.ChildTaskID = otherTaskID },
		"source participant": func(d *Delegation) { d.FromParticipantID = "agent:other" },
		"target participant": func(d *Delegation) { d.ToParticipantID = "agent:other" },
		"parent authority":   func(d *Delegation) { d.ParentAuthorityDigest = strings.Repeat("a", 64) },
		"child authority":    func(d *Delegation) { d.ChildAuthorityDigest = strings.Repeat("b", 64) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBindingFixture(t)
			bad := f.delegation
			change(&bad)
			projection, err := Verify(context.Background(), f.capability, f.key, f.mandate, f.mandate.ActorID, bad, f.now, f.uses)
			if !errors.Is(err, lp.ErrBinding) || projection.DecisionID != "" {
				t.Fatalf("changed binding accepted: %+v, %v", projection, err)
			}
			if _, err := Verify(context.Background(), f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses); err != nil {
				t.Fatalf("bad binding consumed valid mandate: %v", err)
			}
		})
	}
	f := newBindingFixture(t)
	if _, err := Verify(context.Background(), f.capability, f.key, f.mandate, "runtime:other", f.delegation, f.now, f.uses); !errors.Is(err, lp.ErrBinding) {
		t.Fatalf("different authenticated actor accepted: %v", err)
	}
	if _, err := Verify(context.Background(), f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses); err != nil {
		t.Fatalf("wrong actor consumed valid mandate: %v", err)
	}
}

func TestDelegateChecksActualTaskAndActorBindingsBeforeConsumption(t *testing.T) {
	tests := map[string]func(*Input){
		"child task and authenticated target": func(in *Input) {
			in.Child.TaskID, in.Event.Auth.TargetTaskID = otherTaskID, otherTaskID
		},
		"parent task and authenticated task": func(in *Input) {
			in.Parent.TaskID, in.Event.Auth.TaskID = otherTaskID, otherTaskID
		},
		"child assignment and authenticated target": func(in *Input) {
			in.Child.AssignmentID, in.Event.Auth.TargetAssignmentID = otherAssignmentID, otherAssignmentID
		},
		"actor":           func(in *Input) { in.Event.Auth.ActorID = "runtime:other" },
		"event timestamp": func(in *Input) { in.Event.At = in.Event.At.Add(time.Second) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f := newBindingFixture(t)
			in, _ := taskCoordInput(t, f)
			bad := in
			change(&bad)
			transition, err := Delegate(context.Background(), bad, f.capability, f.key, f.mandate, f.now, f.uses)
			if !errors.Is(err, lp.ErrBinding) || transition.Parent.AssignmentID != "" {
				t.Fatalf("actual execution binding substitution accepted: %+v, %v", transition, err)
			}
			if _, err := Delegate(context.Background(), in, f.capability, f.key, f.mandate, f.now, f.uses); err != nil {
				t.Fatalf("substituted execution consumed mandate: %v", err)
			}
		})
	}
}

func TestInvalidTaskCoordTransitionDoesNotConsumeMandate(t *testing.T) {
	f := newBindingFixture(t)
	in, _ := taskCoordInput(t, f)
	bad := in
	bad.Event.ExpectedRevision++
	transition, err := Delegate(context.Background(), bad, f.capability, f.key, f.mandate, f.now, f.uses)
	if !errors.Is(err, taskcoord.ErrRevisionConflict) || transition.Parent.AssignmentID != "" {
		t.Fatalf("stale TaskCoord transition accepted: %+v, %v", transition, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	transition, err = Delegate(ctx, in, f.capability, f.key, f.mandate, f.now, f.uses)
	if !errors.Is(err, context.Canceled) || transition.Parent.AssignmentID != "" {
		t.Fatalf("canceled admission exposed transition: %+v, %v", transition, err)
	}
	if _, err := Delegate(context.Background(), in, f.capability, f.key, f.mandate, f.now, f.uses); err != nil {
		t.Fatalf("failed transition consumed mandate: %v", err)
	}
}

func TestSignedButInconsistentAuthorityDoesNotConsumeMandate(t *testing.T) {
	for _, field := range []string{"parent", "child"} {
		t.Run(field, func(t *testing.T) {
			f := newBindingFixture(t)
			valid := f.delegation
			if field == "parent" {
				f.delegation.ParentAuthorityDigest = strings.Repeat("a", 64)
			} else {
				f.delegation.ChildAuthorityDigest = strings.Repeat("b", 64)
			}
			// The issuer checks an approved action and optimum. The binding layer
			// must additionally relate that action's digests to the optimum.
			f.issue(t)
			if _, err := Verify(context.Background(), f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses); !errors.Is(err, lp.ErrBinding) {
				t.Fatalf("signed inconsistent authority accepted: %v", err)
			}
			f.delegation = valid
			f.issue(t)
			if _, err := Verify(context.Background(), f.capability, f.key, f.mandate, f.mandate.ActorID, f.delegation, f.now, f.uses); err != nil {
				t.Fatalf("invalid authority consumed mandate: %v", err)
			}
		})
	}
}

func TestEffectiveAuthorityDigestCanonicalization(t *testing.T) {
	f := newBindingFixture(t)
	a, err := EffectiveAuthorityDigest(f.solution.ProblemDigest, []string{"write", "read"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := EffectiveAuthorityDigest(f.solution.ProblemDigest, []string{"read", "write"})
	if err != nil || a != b {
		t.Fatalf("set order changed authority digest: %s, %s, %v", a, b, err)
	}
	if _, err := EffectiveAuthorityDigest(f.solution.ProblemDigest, []string{"read", "read"}); !errors.Is(err, lp.ErrBinding) {
		t.Fatalf("duplicate authority set accepted: %v", err)
	}
	if _, err := EffectiveAuthorityDigest(strings.Repeat("a", 64), []string{"read"}); !errors.Is(err, lp.ErrBinding) {
		t.Fatalf("untyped problem digest accepted: %v", err)
	}
}
