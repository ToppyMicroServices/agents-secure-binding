// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import "time"

const (
	PolicySchemaV1     = "asb.authority-quorum-policy/v1"
	ApprovalSchemaV1   = "asb.authority-approval/v1"
	RevocationSchemaV1 = "asb.authority-decision-revocation/v1"
	QuorumSchemaV1     = "asb.verified-authority-quorum/v1"

	MaxDocumentBytes = 1 << 20
	MaxAuthorities   = 128
)

// DecisionBinding names one immutable application decision. OperationDigest
// is produced by an application profile and must cover every field that may
// change the authorized effect.
type DecisionBinding struct {
	DecisionID      string `json:"decision_id"`
	PolicyDigest    string `json:"policy_digest"`
	OperationDigest string `json:"operation_digest"`
}

// VerifiedPolicy is trusted verifier-local policy, not peer input.
// AuthorityIDs are stable policy slots. They are not key IDs, certificates,
// processes, or replica names.
type VerifiedPolicy struct {
	Schema             string    `json:"schema"`
	PolicyID           string    `json:"policy_id"`
	PolicyDigest       string    `json:"policy_digest"`
	AuthorityMapDigest string    `json:"authority_map_digest"`
	Audience           string    `json:"audience"`
	Epoch              uint64    `json:"epoch"`
	Threshold          uint32    `json:"threshold"`
	AuthorityIDs       []string  `json:"authority_ids"`
	ValidFrom          time.Time `json:"valid_from"`
	ExpiresAt          time.Time `json:"expires_at"`
}

// ApprovalRequest is the only application-controlled input needed to bind an
// approval. The ASB adapter derives authority and proof fields separately.
type ApprovalRequest struct {
	DecisionID      string `json:"decision_id"`
	PolicyDigest    string `json:"policy_digest"`
	OperationDigest string `json:"operation_digest"`
}

func (r ApprovalRequest) Binding() DecisionBinding {
	return DecisionBinding{
		DecisionID:      r.DecisionID,
		PolicyDigest:    r.PolicyDigest,
		OperationDigest: r.OperationDigest,
	}
}

// AcceptedAuthority is a verifier projection. AuthorityID must be resolved
// from an accepted ASB identity by trusted local configuration.
type AcceptedAuthority struct {
	ApprovalDigest     Digest
	AuthorityMapDigest string
	PrincipalDigest    string
	CredentialDigest   string
	AuthorityID        string
	AuthorizationID    string
	ProofIssuer        string
	ProofID            string
	ProofSignerKey     string
	Audience           string
	IssuedAt           time.Time
	ExpiresAt          time.Time
}

// Approval is an immutable durable record. ApprovalID is derived from verified
// proof facts and the exact request digest.
type Approval struct {
	Schema           string    `json:"schema"`
	ApprovalID       string    `json:"approval_id"`
	DecisionID       string    `json:"decision_id"`
	PolicyDigest     string    `json:"policy_digest"`
	OperationDigest  string    `json:"operation_digest"`
	Audience         string    `json:"audience"`
	AuthorityID      string    `json:"authority_id"`
	PrincipalTag     string    `json:"principal_tag"`
	CredentialTag    string    `json:"credential_tag"`
	AuthorizationTag string    `json:"authorization_tag"`
	ApprovedAt       time.Time `json:"approved_at"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (a Approval) Binding() DecisionBinding {
	return DecisionBinding{
		DecisionID:      a.DecisionID,
		PolicyDigest:    a.PolicyDigest,
		OperationDigest: a.OperationDigest,
	}
}

// DecisionRevocation blocks future approval and quorum consumption. It cannot
// undo an external effect that already followed a consumed quorum.
type DecisionRevocation struct {
	Schema       string    `json:"schema"`
	RevocationID string    `json:"revocation_id"`
	DecisionID   string    `json:"decision_id"`
	RevokedAt    time.Time `json:"revoked_at"`
}

// ConsumeRequest names an idempotent final quorum consumption.
type ConsumeRequest struct {
	ConsumptionID string          `json:"consumption_id"`
	Binding       DecisionBinding `json:"binding"`
}

// VerifiedQuorum is the reduced projection returned only after atomic
// consumption. It deliberately omits authority, actor, proof, key, signature,
// nonce, fragment, and contact information. It is not a signed portable proof;
// decoded peer input must not be treated as authorization.
type VerifiedQuorum struct {
	Schema          string    `json:"schema"`
	ConsumptionID   string    `json:"consumption_id"`
	DecisionID      string    `json:"decision_id"`
	PolicyDigest    string    `json:"policy_digest"`
	OperationDigest string    `json:"operation_digest"`
	Audience        string    `json:"audience"`
	Threshold       uint32    `json:"threshold"`
	ApprovalCount   uint32    `json:"approval_count"`
	ConsumedAt      time.Time `json:"consumed_at"`
	AcceptedUntil   time.Time `json:"accepted_until"`
}
