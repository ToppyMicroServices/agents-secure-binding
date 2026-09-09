// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package leastprivilegebinding connects checked least-privilege capabilities to
// TaskCoord's external policy-verifier projection. Callers still supply freshly
// authenticated ASB operations and commit transitions through a TaskCoord Store.
package leastprivilegebinding

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// Delegation binds the parent and child assignment, task, participant and
// authority identities. ParentAuthorityDigest is this profile's problem digest
// without the sha256: prefix; ChildAuthorityDigest is EffectiveAuthorityDigest.
type Delegation struct {
	ParentAssignmentID    string `json:"parent_assignment_id"`
	ChildAssignmentID     string `json:"child_assignment_id"`
	ParentTaskID          string `json:"parent_task_id"`
	ChildTaskID           string `json:"child_task_id"`
	FromParticipantID     string `json:"from_participant_id"`
	ToParticipantID       string `json:"to_participant_id"`
	ParentAuthorityDigest string `json:"parent_authority_digest"`
	ChildAuthorityDigest  string `json:"child_authority_digest"`
}

// Action is the exact action the trusted mandate must bind before issuance.
func Action(d Delegation) (lp.Action, error) {
	if d.ParentTaskID == "" || d.ChildTaskID == "" || len(d.ParentTaskID) > 256 || len(d.ChildTaskID) > 256 {
		return lp.Action{}, lp.ErrBinding
	}
	v := projection(d, "check", "policy:check", "evidence:check", time.Unix(1, 0))
	if err := v.Validate(); err != nil {
		return lp.Action{}, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return lp.Action{}, err
	}
	return lp.Action{Operation: "taskcoord.delegate", Resource: d.ParentAssignmentID, Arguments: raw}, nil
}

// EffectiveAuthorityDigest binds a canonical permission set to its full model.
// It is an identifier, not evidence of feasibility, narrowing or optimality.
func EffectiveAuthorityDigest(problemDigest string, permissions []string) (string, error) {
	if len(problemDigest) != 71 || !strings.HasPrefix(problemDigest, "sha256:") ||
		strings.ToLower(problemDigest) != problemDigest || len(permissions) > lp.MaxPermissions {
		return "", lp.ErrBinding
	}
	if _, err := hex.DecodeString(problemDigest[7:]); err != nil {
		return "", lp.ErrBinding
	}
	ids := make([]string, len(permissions))
	copy(ids, permissions)
	slices.Sort(ids)
	for i, id := range ids {
		if id == "" || len(id) > lp.MaxIDBytes || (i > 0 && ids[i-1] == id) {
			return "", lp.ErrBinding
		}
	}
	raw, err := json.Marshal(struct {
		ProblemDigest string   `json:"problem_digest"`
		Permissions   []string `json:"permissions"`
	}{problemDigest, ids})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("asb.least-privilege.effective-authority/v1\x00"), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// Verify consumes one capability and produces a trusted policy projection. The
// caller must use d's exact task/assignment bindings in the following TaskCoord
// operation. A failed later state commit does not refund the consumed mandate.
func Verify(ctx context.Context, cap lp.Capability, key ed25519.PublicKey, current lp.Mandate,
	actorID string, d Delegation, now time.Time, uses lp.UseStore,
) (taskcoord.VerifiedDelegation, error) {
	v, req, err := verifyProjection(cap, key, current, actorID, d, now)
	if err != nil {
		return taskcoord.VerifiedDelegation{}, err
	}
	if err := lp.ConsumeCapability(ctx, cap, key, current, req, now, uses); err != nil {
		return taskcoord.VerifiedDelegation{}, err
	}
	return v, nil
}

// Input contains actual TaskCoord state and an already authenticated operation.
// Event.At and Child.OfferedAt must use the trusted execution timestamp now.
type Input struct {
	Parent    taskcoord.Assignment
	Delegator taskcoord.Participant
	Target    taskcoord.Participant
	Child     taskcoord.AssignmentDefinition
	Event     taskcoord.Event
}

// Delegate checks the actual task, assignment, participant, authority and actor
// bindings before calling TaskCoord. Prefer this to manually using a projection:
// TaskCoord's projection type does not itself carry task or actor IDs.
// This returns an uncommitted transition. Store.CommitDelegation is still
// required, and a commit failure after consumption requires reconciliation.
func Delegate(ctx context.Context, in Input, cap lp.Capability, key ed25519.PublicKey,
	current lp.Mandate, now time.Time, uses lp.UseStore,
) (taskcoord.DelegationTransition, error) {
	if !in.Event.At.Equal(now) {
		return taskcoord.DelegationTransition{}, lp.ErrBinding
	}
	d := Delegation{
		ParentAssignmentID: in.Parent.AssignmentID, ChildAssignmentID: in.Child.AssignmentID,
		ParentTaskID: in.Parent.TaskID, ChildTaskID: in.Child.TaskID,
		FromParticipantID: in.Parent.ParticipantID, ToParticipantID: in.Child.ParticipantID,
		ParentAuthorityDigest: in.Parent.AuthorityDigest, ChildAuthorityDigest: in.Child.AuthorityDigest,
	}
	v, req, err := verifyProjection(cap, key, current, in.Event.Auth.ActorID, d, now)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	transition, err := taskcoord.Delegate(in.Parent, in.Delegator, in.Target, in.Child, in.Event, v)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	if err := lp.ConsumeCapability(ctx, cap, key, current, req, now, uses); err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	return transition, nil
}

func verifyProjection(cap lp.Capability, key ed25519.PublicKey, current lp.Mandate,
	actorID string, d Delegation, now time.Time,
) (taskcoord.VerifiedDelegation, lp.Request, error) {
	action, err := Action(d)
	if err != nil {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, err
	}
	req := lp.Request{ActorID: actorID, TaskID: d.ParentTaskID, Action: action}
	if err := lp.CheckCapability(cap, key, current, req, now); err != nil {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, err
	}
	child, err := EffectiveAuthorityDigest(cap.Claims.Solution.ProblemDigest, cap.Claims.Solution.Effective)
	if err != nil {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, err
	}
	if d.ParentAuthorityDigest != strings.TrimPrefix(cap.Claims.Solution.ProblemDigest, "sha256:") || d.ChildAuthorityDigest != child {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, lp.ErrBinding
	}
	evidence, err := lp.DigestCapability(cap)
	if err != nil {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, err
	}
	v := projection(d, cap.Claims.ID, current.PolicyRef, "urn:asb:least-privilege:"+evidence, now)
	if err := v.Validate(); err != nil {
		return taskcoord.VerifiedDelegation{}, lp.Request{}, err
	}
	return v, req, nil
}

func projection(d Delegation, decision, policy, evidence string, at time.Time) taskcoord.VerifiedDelegation {
	return taskcoord.VerifiedDelegation{
		DecisionID: decision, ParentAssignmentID: d.ParentAssignmentID,
		ChildAssignmentID: d.ChildAssignmentID, FromParticipantID: d.FromParticipantID, ToParticipantID: d.ToParticipantID,
		ParentAuthorityDigest: d.ParentAuthorityDigest, ChildAuthorityDigest: d.ChildAuthorityDigest,
		PolicyRef: policy, EvidenceRef: evidence, VerifiedAt: at,
	}
}
