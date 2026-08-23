// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"context"
)

// Store is the trusted durable authority-quorum boundary. It accepts only
// approvals created after ASB verification; it must not be exposed as a peer
// JSON ingress API.
//
// AppendApproval must atomically bind a DecisionID to one policy and operation,
// deduplicate ApprovalID, and allow at most one approval per AuthorityID,
// PrincipalTag, and CredentialTag. It must check current policy and approval
// freshness with the store transaction's trusted clock before commit.
// A retry of the same verified proof returns the first stored record, including
// its original ApprovedAt; any conflicting reuse fails.
//
// ConsumeQuorum must recheck the complete current policy, revocation state,
// approval membership, freshness, the three distinctness keys, and threshold in the same
// transaction that records a globally unique ConsumptionID and the selected
// evidence set. Only its fresh committed return value is an authorization
// result. A same-ID retry before AcceptedUntil is idempotent; reuse for another
// decision or a different consume after success fails.
//
// RevokeDecision must be called only after application-specific authentication.
// It must be durable and serialized with append and consume. A
// production implementation is expected to use a cross-process database
// transaction or equivalent linearizable CAS. Store failure must fail closed.
type Store interface {
	AppendApproval(context.Context, VerifiedPolicy, Approval) (Approval, error)
	ConsumeQuorum(context.Context, VerifiedPolicy, ConsumeRequest) (VerifiedQuorum, error)
	RevokeDecision(context.Context, DecisionRevocation) error
}
