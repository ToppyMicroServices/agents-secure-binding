// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"fmt"
	"time"
)

// NewApproval compares the application request with accepted ASB authority
// facts and returns one immutable approval record.
func NewApproval(request ApprovalRequest, accepted AcceptedAuthority, approvedAt time.Time) (Approval, error) {
	if err := request.Validate(); err != nil {
		return Approval{}, err
	}
	digest, err := ApprovalDigest(request)
	if err != nil {
		return Approval{}, err
	}
	if accepted.ApprovalDigest != digest {
		return Approval{}, ErrAuthenticatedBindingMismatch
	}
	for field, value := range map[string]string{
		"authority_id":     accepted.AuthorityID,
		"authorization_id": accepted.AuthorizationID,
		"proof_issuer":     accepted.ProofIssuer,
		"proof_id":         accepted.ProofID,
		"proof_signer_key": accepted.ProofSignerKey,
	} {
		if err := validateID(field, value); err != nil {
			return Approval{}, fmt.Errorf("%w: %v", ErrInvalidApproval, err)
		}
	}
	for field, value := range map[string]string{
		"authority_map_digest": accepted.AuthorityMapDigest,
		"principal_digest":     accepted.PrincipalDigest,
		"credential_digest":    accepted.CredentialDigest,
	} {
		if err := validateDigest(field, value); err != nil {
			return Approval{}, fmt.Errorf("%w: %v", ErrInvalidApproval, err)
		}
	}
	if err := validateAudience(accepted.Audience); err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrInvalidApproval, err)
	}
	if approvedAt.IsZero() || accepted.IssuedAt.IsZero() || accepted.ExpiresAt.IsZero() {
		return Approval{}, fmt.Errorf("%w: complete verifier times are required", ErrInvalidApproval)
	}
	if approvedAt.Before(accepted.IssuedAt) {
		return Approval{}, ErrNotYetValid
	}
	if !approvedAt.Before(accepted.ExpiresAt) {
		return Approval{}, ErrExpired
	}
	approval := Approval{
		Schema: ApprovalSchemaV1, ApprovalID: approvalRecordID(accepted),
		DecisionID: request.DecisionID, PolicyDigest: request.PolicyDigest,
		OperationDigest: request.OperationDigest, Audience: accepted.Audience,
		AuthorityID:      accepted.AuthorityID,
		PrincipalTag:     approvalTag(principalTagDomain, request, accepted.PrincipalDigest),
		CredentialTag:    approvalTag(credentialTagDomain, request, accepted.CredentialDigest),
		AuthorizationTag: approvalTag(authorizationTagDomain, request, accepted.AuthorizationID),
		ApprovedAt:       approvedAt, ExpiresAt: accepted.ExpiresAt,
	}
	if err := approval.Validate(); err != nil {
		return Approval{}, err
	}
	return approval, nil
}
