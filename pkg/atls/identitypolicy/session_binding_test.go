// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
)

const testManagerKeyID = "manager-key-1"

func TestNewAssertionFromSessionBindingAcceptsGrantConfirmationKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)

	assertion, err := NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
	if assertion.Issuer != grant.Issuer {
		t.Fatalf("Assertion.Issuer = %q, want %q", assertion.Issuer, grant.Issuer)
	}
	if assertion.Values.Agent != grant.Values.Agent {
		t.Fatalf("Assertion.Values.Agent = %q, want %q", assertion.Values.Agent, grant.Values.Agent)
	}
	if assertion.Binding.LeafPublicKeySHA256 != statement.Binding.LeafPublicKeySHA256 {
		t.Fatalf("Assertion.Binding.LeafPublicKeySHA256 = %q, want %q",
			assertion.Binding.LeafPublicKeySHA256, statement.Binding.LeafPublicKeySHA256)
	}
}

func TestNewAssertionFromSessionBindingAcceptsGrantAgentPublicKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ConfirmationKey = ""
	statement := testSessionBindingStatement(now)
	statement.SignerKey = grant.Values.AgentPublicKey

	assertion, err := NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}

	policy := Policy{
		Require:  Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: Values{Service: "payments", Agent: "agent-a", TaskID: "task-1", Scopes: []string{"orders:read"}},
	}
	if err := ValidateAssertion(policy, assertion, statement.Binding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingRejectsArbitraryEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.SignerKey = "endpoint-key-not-in-grant"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsIssuerKeyAsBindingKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.IssuerKey = testManagerKeyID
	grant.ConfirmationKey = testManagerKeyID
	statement := testSessionBindingStatement(now)
	statement.SignerKey = testManagerKeyID

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsGrantWithoutBindingKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ConfirmationKey = ""
	grant.Values.AgentPublicKey = ""
	grant.AuthorizedEndpointKeys = nil
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMissingExpected)
	}
	if !errors.Is(err, ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnauthorizedBindingKey)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeGrantValue(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.Values.Service = "<script>"
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeAuthorizedEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.AuthorizedEndpointKeys = []string{"<script>"}
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestNewAssertionFromSessionBindingAcceptsAuthorizedEndpointKey(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.AuthorizedEndpointKeys = []string{"endpoint-key-bound-by-policy"}
	statement := testSessionBindingStatement(now)
	statement.SignerKey = "endpoint-key-bound-by-policy"

	if _, err := NewAssertionFromSessionBinding(grant, statement, now); err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingWithOptionsRejectsReplay(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	cache := newTestReplayCache()
	opts := SessionBindingOptions{Now: now, ReplayCache: cache}

	if _, err := NewAssertionFromSessionBindingWithOptions(grant, statement, opts); err != nil {
		t.Fatalf("NewAssertionFromSessionBindingWithOptions() first error = %v", err)
	}
	_, err := NewAssertionFromSessionBindingWithOptions(grant, statement, opts)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("NewAssertionFromSessionBindingWithOptions() replay error = %v, want %v", err, ErrReplayDetected)
	}
}

func TestNewAssertionFromSessionBindingReplayKeyIncludesContext(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	cache := newTestReplayCache()
	opts := SessionBindingOptions{Now: now, ReplayCache: cache}

	if _, err := NewAssertionFromSessionBindingWithOptions(grant, statement, opts); err != nil {
		t.Fatalf("NewAssertionFromSessionBindingWithOptions() error = %v", err)
	}
	want := statement.GrantHash + "\x00" +
		statement.Audience + "\x00" +
		statement.Binding.TLSExporterSHA256 + "\x00" +
		statement.Binding.RequestContextSHA256 + "\x00" +
		statement.Binding.Nonce
	if len(cache.keys) != 1 {
		t.Fatalf("replay cache keys = %d, want 1", len(cache.keys))
	}
	if cache.keys[0] != want {
		t.Fatalf("replay cache key = %q, want %q", cache.keys[0], want)
	}
}

type l2BindingVector struct {
	Profile                  string `json:"profile"`
	ExporterLabel            string `json:"exporter_label"`
	ExporterLength           int    `json:"exporter_length"`
	Role                     string `json:"role"`
	ProtocolID               string `json:"protocol_id"`
	Audience                 string `json:"aud"`
	GrantHash                string `json:"grant_hash"`
	TaskContext              string `json:"task_context"`
	VerifierNonceOrAttemptID string `json:"verifier_nonce_or_attempt_id"`
	ContextHex               string `json:"context_hex"`
	LeafSPKIHex              string `json:"leaf_spki_hex"`
	TLSExporterHex           string `json:"tls_exporter_hex"`
	LeafPublicKeySHA256      string `json:"leaf_public_key_sha256"`
	TLSExporterSHA256        string `json:"tls_exporter_sha256"`
	RequestContextSHA256     string `json:"request_context_sha256"`
	AttestationBinderSHA256  string `json:"attestation_binder_sha256"`
	SessionBindingNonce      string `json:"session_binding_nonce"`
}

func TestL2BindingVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/l2_binding_vector.json")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var vector l2BindingVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if vector.Profile != "hwtls-l2-context-v1" {
		t.Fatalf("profile = %q, want hwtls-l2-context-v1", vector.Profile)
	}
	if vector.ExporterLabel != eaattestation.ExporterLabelAttestation {
		t.Fatalf("exporter_label = %q, want %q", vector.ExporterLabel, eaattestation.ExporterLabelAttestation)
	}
	if vector.ExporterLength != 32 {
		t.Fatalf("exporter_length = %d, want 32", vector.ExporterLength)
	}

	contextBytes := mustDecodeHex(t, vector.ContextHex)
	leafSPKI := mustDecodeHex(t, vector.LeafSPKIHex)
	tlsExporter := mustDecodeHex(t, vector.TLSExporterHex)

	requireSHA256(t, "leaf_public_key_sha256", leafSPKI, vector.LeafPublicKeySHA256)
	requireSHA256(t, "tls_exporter_sha256", tlsExporter, vector.TLSExporterSHA256)
	requireSHA256(t, "request_context_sha256", contextBytes, vector.RequestContextSHA256)

	attestationBindingInput := append(append([]byte{}, leafSPKI...), tlsExporter...)
	attestationBinding := sha256.Sum256(attestationBindingInput)
	requireSHA256(t, "attestation_binder_sha256", attestationBinding[:], vector.AttestationBinderSHA256)

	now := time.Unix(1700000000, 0)
	grant := testVerifiedGrant(now)
	grant.Audience = vector.Audience
	grant.GrantHash = vector.GrantHash
	statement := testSessionBindingStatement(now)
	statement.Audience = vector.Audience
	statement.GrantHash = vector.GrantHash
	statement.Binding = Binding{
		LeafPublicKeySHA256:     vector.LeafPublicKeySHA256,
		TLSExporterSHA256:       vector.TLSExporterSHA256,
		RequestContextSHA256:    vector.RequestContextSHA256,
		AttestationBinderSHA256: vector.AttestationBinderSHA256,
		Nonce:                   vector.SessionBindingNonce,
		ExpiresAt:               now.Add(time.Minute),
	}

	assertion, err := NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
	policy := Policy{Require: Requirements{L3: true, L4: true, L5: true, L6: true}, Expected: grant.Values}
	if err := ValidateAssertion(policy, assertion, statement.Binding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}

	mismatchedBinding := statement.Binding
	mismatchedBinding.TLSExporterSHA256 = "different-exporter"
	err = ValidateAssertion(policy, assertion, mismatchedBinding, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("ValidateAssertion() exporter mismatch error = %v, want %v", err, ErrMismatch)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q) error = %v", value, err)
	}
	return out
}

func requireSHA256(t *testing.T, name string, input []byte, want string) {
	t.Helper()
	sum := sha256.Sum256(input)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func TestNewAssertionFromSessionBindingRejectsGrantHashMismatch(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.GrantHash = "sha256:other-grant"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMismatch)
	}
}

type testReplayCache struct {
	seen map[string]time.Time
	keys []string
}

func newTestReplayCache() *testReplayCache {
	return &testReplayCache{seen: make(map[string]time.Time)}
}

func (c *testReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return ErrReplayDetected
	}
	c.seen[key] = expiresAt
	c.keys = append(c.keys, key)
	return nil
}

func TestNewAssertionFromSessionBindingRejectsAudienceMismatch(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Audience = "other-client"

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMismatch)
	}
}

func TestNewAssertionFromSessionBindingRejectsMissingRequiredBindingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerifiedSessionBindingStatement)
	}{
		{
			name: "leaf public key hash",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.LeafPublicKeySHA256 = ""
			},
		},
		{
			name: "tls exporter hash",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.TLSExporterSHA256 = ""
			},
		},
		{
			name: "request context hash",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.RequestContextSHA256 = ""
			},
		},
		{
			name: "nonce",
			mutate: func(statement *VerifiedSessionBindingStatement) {
				statement.Binding.Nonce = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			grant := testVerifiedGrant(now)
			statement := testSessionBindingStatement(now)
			tt.mutate(&statement)

			_, err := NewAssertionFromSessionBinding(grant, statement, now)
			if !errors.Is(err, ErrMissingBinding) {
				t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrMissingBinding)
			}
		})
	}
}

func TestNewAssertionFromSessionBindingAcceptsMissingOptionalAttestationBinder(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.AttestationBinderSHA256 = ""

	if _, err := NewAssertionFromSessionBinding(grant, statement, now); err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}
}

func TestNewAssertionFromSessionBindingRejectsExpiredGrant(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.ExpiresAt = now.Add(-time.Minute)
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsExpiredStatement(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.ExpiresAt = now.Add(-time.Minute)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsFutureStatementIssueTime(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	statement := testSessionBindingStatement(now)
	statement.Binding.IssuedAt = now.Add(time.Minute)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrFutureAssertion) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrFutureAssertion)
	}
}

func TestNewAssertionFromSessionBindingRejectsUnsafeGrantIssuer(t *testing.T) {
	now := time.Now()
	grant := testVerifiedGrant(now)
	grant.Issuer = "<script>"
	statement := testSessionBindingStatement(now)

	_, err := NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func testVerifiedGrant(now time.Time) VerifiedGrant {
	return VerifiedGrant{
		Issuer:          "manager-key-1",
		Audience:        "relying-client",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-confirmation-key",
		Values: Values{
			Service:        "payments",
			Tenant:         "tenant-a",
			Deployment:     "prod",
			Agent:          "agent-a",
			AgentPublicKey: "agent-key",
			TaskID:         "task-1",
			Scopes:         []string{"orders:read"},
		},
		IssuedAt:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func testSessionBindingStatement(now time.Time) VerifiedSessionBindingStatement {
	return VerifiedSessionBindingStatement{
		GrantHash: "sha256:grant",
		Audience:  "relying-client",
		SignerKey: "agent-confirmation-key",
		Binding: Binding{
			LeafPublicKeySHA256:     "sha256:leaf",
			TLSExporterSHA256:       "sha256:exporter",
			RequestContextSHA256:    "sha256:context",
			AttestationBinderSHA256: "sha256:binder",
			Nonce:                   "binding-nonce",
			IssuedAt:                now.Add(-time.Minute),
			ExpiresAt:               now.Add(time.Minute),
		},
	}
}
