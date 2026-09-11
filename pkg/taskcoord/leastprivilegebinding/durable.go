// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilegebinding

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// DelegateAndCommit persists admission before committing a TaskCoord transition.
// Callers supply freshly authenticated Input and hold the current-policy guard.
// A commit error is recorded as UNKNOWN: it never returns a usable uncommitted
// transition or silently retries a possibly committed delegation. Use a durable
// TaskCoord Store in deployments; the in-memory development stub is insufficient.
func DelegateAndCommit(ctx context.Context, in Input, cap lp.Capability, key ed25519.PublicKey, current lp.Mandate, now time.Time, journal *lp.DurableStore, store taskcoord.Store) (lp.ExecutionRecord, error) {
	if journal == nil || store == nil || !in.Event.At.Equal(now) {
		return lp.ExecutionRecord{}, lp.ErrBinding
	}
	d := Delegation{
		ParentAssignmentID: in.Parent.AssignmentID, ChildAssignmentID: in.Child.AssignmentID,
		ParentTaskID: in.Parent.TaskID, ChildTaskID: in.Child.TaskID,
		FromParticipantID: in.Parent.ParticipantID, ToParticipantID: in.Child.ParticipantID,
		ParentAuthorityDigest: in.Parent.AuthorityDigest, ChildAuthorityDigest: in.Child.AuthorityDigest,
	}
	v, request, err := verifyProjection(cap, key, current, in.Event.Auth.ActorID, d, now)
	if err != nil {
		return lp.ExecutionRecord{}, err
	}
	transition, err := taskcoord.Delegate(in.Parent, in.Delegator, in.Target, in.Child, in.Event, v)
	if err != nil {
		return lp.ExecutionRecord{}, err
	}
	return journal.Run(ctx, in.Event.ID, cap, key, current, request, now, func(ctx context.Context, id string, exact lp.Request) (lp.EffectResult, error) {
		// The closure can commit only this checked transition. The request copy
		// supplied by Run is additionally checked against the prepared action.
		ad, err := lp.DigestAction(exact.Action)
		if err != nil || id != transition.Delegation.EventID || ad != current.ActionDigest {
			return lp.EffectResult{}, lp.ErrBinding
		}
		if err := store.CommitDelegation(ctx, in.Parent.Revision, transition); err != nil {
			return lp.EffectResult{}, err
		}
		evidence, err := delegationEvidence(transition.Delegation)
		return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: evidence}, err
	})
}

// ReconcileDelegation performs a read-only authoritative lookup of the immutable
// TaskCoord event. Missing data or an unavailable store leaves UNKNOWN intact;
// this function never retries CommitDelegation. The caller must authenticate and
// authorize the reconciliation separately under current policy. original is the
// exact historical mandate bound to the journal, not a new execution grant.
func ReconcileDelegation(ctx context.Context, operationID string, original lp.Mandate, request lp.Request, journal *lp.DurableStore, store taskcoord.Store) (lp.ExecutionRecord, error) {
	if journal == nil || store == nil {
		return lp.ExecutionRecord{}, lp.ErrBinding
	}
	digest, err := lp.DigestExecution(operationID, original, request)
	if err != nil {
		return lp.ExecutionRecord{}, err
	}
	r, err := journal.Lookup(ctx, operationID, digest)
	if err != nil {
		return lp.ExecutionRecord{}, err
	}
	if r.Terminal() {
		return r, nil
	}
	if r.State == lp.ExecutionAccepted {
		return r, lp.ErrExecutionConflict
	}
	edge, err := store.LoadDelegation(ctx, operationID)
	if err != nil {
		return r, errors.Join(lp.ErrOutcomeUnknown, err)
	}
	action, err := Action(Delegation{
		ParentAssignmentID: edge.ParentAssignmentID, ChildAssignmentID: edge.ChildAssignmentID,
		ParentTaskID: edge.ParentTaskID, ChildTaskID: edge.ChildTaskID,
		FromParticipantID: edge.FromParticipantID, ToParticipantID: edge.ToParticipantID,
		ParentAuthorityDigest: edge.ParentAuthorityDigest, ChildAuthorityDigest: edge.ChildAuthorityDigest,
	})
	if err != nil {
		return r, errors.Join(lp.ErrOutcomeUnknown, err)
	}
	ad, err := lp.DigestAction(action)
	if err != nil || edge.EventID != operationID || edge.PolicyRef != original.PolicyRef || ad != original.ActionDigest {
		return r, errors.Join(lp.ErrOutcomeUnknown, lp.ErrBinding)
	}
	evidence, err := delegationEvidence(edge)
	if err != nil {
		return r, errors.Join(lp.ErrOutcomeUnknown, err)
	}
	return journal.Complete(ctx, operationID, digest, lp.ExecutionSucceeded, evidence)
}

func delegationEvidence(edge taskcoord.DelegationRecord) (string, error) {
	raw, err := json.Marshal(edge)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("asb.least-privilege.taskcoord-result/v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
