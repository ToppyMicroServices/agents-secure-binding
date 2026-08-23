// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidPolicy                = errors.New("authorityquorum: invalid policy")
	ErrInvalidRequest               = errors.New("authorityquorum: invalid request")
	ErrInvalidApproval              = errors.New("authorityquorum: invalid approval")
	ErrInvalidRevocation            = errors.New("authorityquorum: invalid revocation")
	ErrInvalidQuorum                = errors.New("authorityquorum: invalid verified quorum")
	ErrMissingStore                 = errors.New("authorityquorum: missing store")
	ErrMissingPolicyResolver        = errors.New("authorityquorum: missing policy resolver")
	ErrAuthenticatedBindingMismatch = errors.New("authorityquorum: authenticated request binding mismatch")
	ErrPolicyMismatch               = errors.New("authorityquorum: policy mismatch")
	ErrPolicyConflict               = errors.New("authorityquorum: policy digest redefined")
	ErrAuthorityNotAllowed          = errors.New("authorityquorum: authority is not a policy member")
	ErrApprovalConflict             = errors.New("authorityquorum: approval identifier conflict")
	ErrConsumptionConflict          = errors.New("authorityquorum: consumption identifier conflict")
	ErrAuthorityAlreadyApproved     = errors.New("authorityquorum: authority already approved decision")
	ErrPrincipalAlreadyApproved     = errors.New("authorityquorum: principal already approved decision")
	ErrCredentialAlreadyApproved    = errors.New("authorityquorum: credential already approved decision")
	ErrDecisionConflict             = errors.New("authorityquorum: decision binding conflict")
	ErrBelowThreshold               = errors.New("authorityquorum: below threshold")
	ErrDecisionConsumed             = errors.New("authorityquorum: decision already consumed")
	ErrDecisionRevoked              = errors.New("authorityquorum: decision revoked")
	ErrNotFound                     = errors.New("authorityquorum: decision not found")
	ErrExpired                      = errors.New("authorityquorum: expired")
	ErrNotYetValid                  = errors.New("authorityquorum: not yet valid")
)

const (
	maxIDBytes       = 256
	maxAudienceBytes = 512
)

func (b DecisionBinding) Validate() error {
	if err := validateID("decision_id", b.DecisionID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateDigest("policy_digest", b.PolicyDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if err := validateDigest("operation_digest", b.OperationDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return nil
}

func (r ApprovalRequest) Validate() error {
	return r.Binding().Validate()
}

func (p VerifiedPolicy) Validate() error {
	if p.Schema != PolicySchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidPolicy)
	}
	if err := p.validateDefinition(); err != nil {
		return err
	}
	digest, err := computePolicyDigest(p)
	if err != nil {
		return err
	}
	if p.PolicyDigest != digest {
		return fmt.Errorf("%w: policy_digest does not match policy", ErrInvalidPolicy)
	}
	return nil
}

func (p VerifiedPolicy) validateDefinition() error {
	if err := validateID("policy_id", p.PolicyID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if err := validateAudience(p.Audience); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if err := validateDigest("authority_map_digest", p.AuthorityMapDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	if p.Epoch == 0 {
		return fmt.Errorf("%w: epoch must be positive", ErrInvalidPolicy)
	}
	if len(p.AuthorityIDs) == 0 || len(p.AuthorityIDs) > MaxAuthorities {
		return fmt.Errorf("%w: authority count must be between 1 and %d", ErrInvalidPolicy, MaxAuthorities)
	}
	if p.Threshold == 0 || int(p.Threshold) > len(p.AuthorityIDs) {
		return fmt.Errorf("%w: threshold must be between 1 and authority count", ErrInvalidPolicy)
	}
	for index, authorityID := range p.AuthorityIDs {
		if err := validateID("authority_id", authorityID); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
		}
		if index > 0 && p.AuthorityIDs[index-1] >= authorityID {
			return fmt.Errorf("%w: authority_ids must be unique and sorted", ErrInvalidPolicy)
		}
	}
	if p.ValidFrom.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.ValidFrom) {
		return fmt.Errorf("%w: invalid policy validity interval", ErrInvalidPolicy)
	}
	return nil
}

func (p VerifiedPolicy) ValidateAt(now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("%w: verifier time is required", ErrInvalidPolicy)
	}
	if now.Before(p.ValidFrom) {
		return ErrNotYetValid
	}
	if !now.Before(p.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

func (p VerifiedPolicy) Allows(authorityID string) bool {
	_, found := slices.BinarySearch(p.AuthorityIDs, authorityID)
	return found
}

func (a Approval) Validate() error {
	if a.Schema != ApprovalSchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidApproval)
	}
	for field, value := range map[string]string{
		"approval_id":  a.ApprovalID,
		"authority_id": a.AuthorityID,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidApproval, err)
		}
	}
	if err := a.Binding().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidApproval, err)
	}
	for field, value := range map[string]string{
		"principal_tag":     a.PrincipalTag,
		"credential_tag":    a.CredentialTag,
		"authorization_tag": a.AuthorizationTag,
	} {
		if err := validateDigest(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidApproval, err)
		}
	}
	if err := validateAudience(a.Audience); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidApproval, err)
	}
	if a.ApprovedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.ApprovedAt) {
		return fmt.Errorf("%w: invalid approval validity interval", ErrInvalidApproval)
	}
	return nil
}

func (r DecisionRevocation) Validate() error {
	if r.Schema != RevocationSchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidRevocation)
	}
	if err := validateID("revocation_id", r.RevocationID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRevocation, err)
	}
	if err := validateID("decision_id", r.DecisionID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRevocation, err)
	}
	if r.RevokedAt.IsZero() {
		return fmt.Errorf("%w: revoked_at is required", ErrInvalidRevocation)
	}
	return nil
}

func (r ConsumeRequest) Validate() error {
	if err := validateID("consumption_id", r.ConsumptionID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	return r.Binding.Validate()
}

func (q VerifiedQuorum) Validate() error {
	if q.Schema != QuorumSchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidQuorum)
	}
	for field, value := range map[string]string{
		"consumption_id": q.ConsumptionID,
		"decision_id":    q.DecisionID,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
		}
	}
	for field, value := range map[string]string{
		"policy_digest":    q.PolicyDigest,
		"operation_digest": q.OperationDigest,
	} {
		if err := validateDigest(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
		}
	}
	if err := validateAudience(q.Audience); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidQuorum, err)
	}
	if q.Threshold == 0 || q.ApprovalCount < q.Threshold || q.ApprovalCount > MaxAuthorities {
		return fmt.Errorf("%w: invalid approval count", ErrInvalidQuorum)
	}
	if q.ConsumedAt.IsZero() || q.AcceptedUntil.IsZero() || !q.AcceptedUntil.After(q.ConsumedAt) {
		return fmt.Errorf("%w: invalid acceptance interval", ErrInvalidQuorum)
	}
	return nil
}

// ValidateAt checks whether a committed quorum may authorize a first external
// effect at now. Historical JSON decoding and structural Validate are not an
// authorization check.
func (q VerifiedQuorum) ValidateAt(now time.Time) error {
	if err := q.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("%w: verifier time is required", ErrInvalidQuorum)
	}
	if now.Before(q.ConsumedAt) {
		return ErrNotYetValid
	}
	if !now.Before(q.AcceptedUntil) {
		return ErrExpired
	}
	return nil
}

func validateID(field, value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxIDBytes || !utf8.ValidString(value) {
		return fmt.Errorf("%s is missing or invalid", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("%s contains whitespace or control characters", field)
		}
	}
	return nil
}

func validateAudience(value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxAudienceBytes || !utf8.ValidString(value) {
		return errors.New("audience is missing or invalid")
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return errors.New("audience contains whitespace or control characters")
		}
	}
	return nil
}

func validateDigest(field, value string) error {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("%s must be sha256 followed by 64 lowercase hex characters", field)
	}
	hexPart := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(hexPart)
	if err != nil || len(decoded) != 32 || strings.ToLower(hexPart) != hexPart {
		return fmt.Errorf("%s must be sha256 followed by 64 lowercase hex characters", field)
	}
	return nil
}
