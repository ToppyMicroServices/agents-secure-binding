// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const (
	policyDigestDomain        = "ASB-AUTHORITY-QUORUM-POLICY-v1"
	approvalDigestDomain      = "ASB-AUTHORITY-QUORUM-APPROVAL-v1"
	approvalIDDomain          = "ASB-AUTHORITY-QUORUM-APPROVAL-ID-v1"
	principalTagDomain        = "ASB-AUTHORITY-QUORUM-PRINCIPAL-TAG-v1"
	credentialTagDomain       = "ASB-AUTHORITY-QUORUM-CREDENTIAL-TAG-v1"
	authorizationTagDomain    = "ASB-AUTHORITY-QUORUM-AUTHORIZATION-TAG-v1"
	requestContextDomain      = "ASB-AUTHORITY-QUORUM-CONTEXT-v1"
	AuthorizationDetailPrefix = "urn:asb:authority-quorum-approval:v1:sha256:"
)

type Digest [sha256.Size]byte

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

// NewVerifiedPolicy canonicalizes authority slots and computes the policy
// digest. Duplicate slots are rejected instead of silently collapsed.
func NewVerifiedPolicy(
	policyID string,
	audience string,
	authorityMapDigest string,
	epoch uint64,
	threshold uint32,
	authorityIDs []string,
	validFrom time.Time,
	expiresAt time.Time,
) (VerifiedPolicy, error) {
	authorities := append([]string(nil), authorityIDs...)
	sort.Strings(authorities)
	for index := 1; index < len(authorities); index++ {
		if authorities[index-1] == authorities[index] {
			return VerifiedPolicy{}, fmt.Errorf("%w: duplicate authority slot %s", ErrInvalidPolicy, authorities[index])
		}
	}
	policy := VerifiedPolicy{
		Schema: PolicySchemaV1, PolicyID: policyID, Audience: audience,
		AuthorityMapDigest: authorityMapDigest,
		Epoch:              epoch, Threshold: threshold, AuthorityIDs: authorities,
		ValidFrom: validFrom, ExpiresAt: expiresAt,
	}
	if err := policy.validateDefinition(); err != nil {
		return VerifiedPolicy{}, err
	}
	digest, err := computePolicyDigest(policy)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	policy.PolicyDigest = digest
	return policy, nil
}

func computePolicyDigest(policy VerifiedPolicy) (string, error) {
	if err := policy.validateDefinition(); err != nil {
		return "", err
	}
	encoder := newEncoder(policyDigestDomain)
	encoder.add("schema", policy.Schema)
	encoder.add("policy_id", policy.PolicyID)
	encoder.add("audience", policy.Audience)
	encoder.add("authority_map_digest", policy.AuthorityMapDigest)
	encoder.add("epoch", strconv.FormatUint(policy.Epoch, 10))
	encoder.add("threshold", strconv.FormatUint(uint64(policy.Threshold), 10))
	encoder.add("valid_from", policy.ValidFrom.UTC().Format(time.RFC3339Nano))
	encoder.add("expires_at", policy.ExpiresAt.UTC().Format(time.RFC3339Nano))
	for _, authorityID := range policy.AuthorityIDs {
		encoder.add("authority_id", authorityID)
	}
	return encoder.sha256(), nil
}

// ApprovalDigest is the exact transcript authorized by each ASB grant and
// session proof.
func ApprovalDigest(request ApprovalRequest) (Digest, error) {
	if err := request.Validate(); err != nil {
		return Digest{}, err
	}
	encoder := newEncoder(approvalDigestDomain)
	encoder.add("decision_id", request.DecisionID)
	encoder.add("policy_digest", request.PolicyDigest)
	encoder.add("operation_digest", request.OperationDigest)
	return encoder.digest(), nil
}

func approvalRecordID(accepted AcceptedAuthority) string {
	encoder := newEncoder(approvalIDDomain)
	encoder.add("authority_map_digest", accepted.AuthorityMapDigest)
	encoder.add("principal_digest", accepted.PrincipalDigest)
	encoder.add("credential_digest", accepted.CredentialDigest)
	encoder.add("authorization_id", accepted.AuthorizationID)
	encoder.add("proof_issuer", accepted.ProofIssuer)
	encoder.add("proof_id", accepted.ProofID)
	encoder.add("proof_signer_key", accepted.ProofSignerKey)
	encoder.add("audience", accepted.Audience)
	encoder.addBytes("approval_digest", accepted.ApprovalDigest[:])
	return "approval:" + encoder.digest().String()
}

func approvalTag(domain string, request ApprovalRequest, value string) string {
	encoder := newEncoder(domain)
	encoder.add("decision_id", request.DecisionID)
	encoder.add("policy_digest", request.PolicyDigest)
	encoder.add("operation_digest", request.OperationDigest)
	encoder.add("value", value)
	return encoder.sha256()
}

func AuthorizationDetail(digest Digest) string {
	return AuthorizationDetailPrefix + digest.String()
}

func RequestContext(digest Digest) []byte {
	encoder := newEncoder(requestContextDomain)
	encoder.addBytes("approval_digest", digest[:])
	return append([]byte(nil), encoder.buffer.Bytes()...)
}

func RequestContextSHA256(digest Digest) string {
	sum := sha256.Sum256(RequestContext(digest))
	return hex.EncodeToString(sum[:])
}

type transcriptEncoder struct {
	buffer bytes.Buffer
}

func newEncoder(domain string) *transcriptEncoder {
	encoder := &transcriptEncoder{}
	encoder.buffer.WriteString(domain)
	encoder.buffer.WriteByte(0)
	return encoder
}

func (e *transcriptEncoder) add(name, value string) {
	e.addBytes(name, []byte(value))
}

func (e *transcriptEncoder) addBytes(name string, value []byte) {
	writeLengthPrefixed(&e.buffer, []byte(name))
	writeLengthPrefixed(&e.buffer, value)
}

func (e *transcriptEncoder) digest() Digest {
	return sha256.Sum256(e.buffer.Bytes())
}

func (e *transcriptEncoder) sha256() string {
	digest := e.digest()
	return "sha256:" + digest.String()
}

func writeLengthPrefixed(buffer *bytes.Buffer, value []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	buffer.Write(value)
}
