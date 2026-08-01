// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptedBindingV2RequiresLocalMandatoryValues(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	observed := testBindingV2(now)

	tests := []struct {
		name  string
		field string
		clear func(*BindingV2)
	}{
		{"endpoint role", FieldEndpointRole, func(binding *BindingV2) { binding.EndpointRole = "" }},
		{"interaction type", FieldInteractionType, func(binding *BindingV2) { binding.InteractionType = "" }},
		{"endpoint SPKI", FieldAcceptedEndpointSPKIHash, func(binding *BindingV2) { binding.AcceptedEndpointSPKISHA256 = "" }},
		{"TLS exporter", FieldTLSExporterHash, func(binding *BindingV2) { binding.TLSExporterSHA256 = "" }},
		{"binding context", FieldBindingContextHash, func(binding *BindingV2) { binding.BindingContextSHA256 = "" }},
		{"verifier nonce", FieldVerifierNonce, func(binding *BindingV2) { binding.VerifierNonce = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := observed
			tt.clear(&expected)
			err := ValidateAcceptedBindingV2(observed, expected, now)
			if !errors.Is(err, ErrMissingExpected) {
				t.Fatalf("ValidateAcceptedBindingV2() error = %v, want %v", err, ErrMissingExpected)
			}
			var validationErrs ValidationErrors
			if !errors.As(err, &validationErrs) || !validationErrs.Has("binding", tt.field, ErrMissingExpected) {
				t.Fatalf("ValidateAcceptedBindingV2() errors do not include binding %s missing expected", tt.field)
			}
		})
	}
}

func TestValidateAcceptedBindingV2RequiresExactOptionalPresence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := testBindingV2(now)

	tests := []struct {
		name     string
		observed BindingV2
		expected BindingV2
		field    string
	}{
		{
			name: "unexpected binder",
			observed: func() BindingV2 {
				binding := base
				binding.AttestationBinderSHA256 = "binder"
				return binding
			}(),
			expected: base,
			field:    FieldAttestationBinderHash,
		},
		{
			name:     "missing binder",
			observed: base,
			expected: func() BindingV2 {
				binding := base
				binding.AttestationBinderSHA256 = "binder"
				return binding
			}(),
			field: FieldAttestationBinderHash,
		},
		{
			name: "unexpected attempt ID",
			observed: func() BindingV2 {
				binding := base
				binding.AttemptID = "attempt-1"
				return binding
			}(),
			expected: base,
			field:    FieldAttemptID,
		},
		{
			name:     "missing attempt ID",
			observed: base,
			expected: func() BindingV2 {
				binding := base
				binding.AttemptID = "attempt-1"
				return binding
			}(),
			field: FieldAttemptID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAcceptedBindingV2(tt.observed, tt.expected, now)
			if err == nil {
				t.Fatal("ValidateAcceptedBindingV2() error = nil, want rejection")
			}
			var validationErrs ValidationErrors
			if !errors.As(err, &validationErrs) || !validationErrs.Has("binding", tt.field, nil) {
				t.Fatalf("ValidateAcceptedBindingV2() errors do not include binding %s", tt.field)
			}
		})
	}
}

func TestV2LifetimeUsesHalfOpenExpiration(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	binding := testBindingV2(now)
	binding.ExpiresAt = now

	err := ValidateAcceptedBindingV2(binding, binding, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("ValidateAcceptedBindingV2() error = %v, want %v", err, ErrExpiredAssertion)
	}

	grant := testVerifiedGrantV2(now)
	grant.ExpiresAt = now
	statement := testSessionBindingStatementV2(now)
	statement.Binding.ExpiresAt = now.Add(time.Minute)
	err = ValidateSessionBindingStatementV2(grant, statement, now)
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("ValidateSessionBindingStatementV2() grant error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestV2LifetimeFailsClosedWithoutCurrentTime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	binding := testBindingV2(now)
	err := ValidateAcceptedBindingV2(binding, binding, time.Time{})
	if !errors.Is(err, ErrMissingCurrentTimeV2) {
		t.Fatalf("ValidateAcceptedBindingV2() error = %v, want %v", err, ErrMissingCurrentTimeV2)
	}
}

func TestValidateSessionBindingStatementV2RejectsProofBeyondGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	statement.Binding.ExpiresAt = grant.ExpiresAt.Add(time.Nanosecond)

	err := ValidateSessionBindingStatementV2(grant, statement, now)
	if !errors.Is(err, ErrInvalidLifetimeV2) {
		t.Fatalf("ValidateSessionBindingStatementV2() error = %v, want %v", err, ErrInvalidLifetimeV2)
	}
}

func TestValidateSessionBindingStatementV2AuthorizesConfirmationKeyOnly(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	baseGrant := testVerifiedGrantV2(now)
	baseStatement := testSessionBindingStatementV2(now)

	tests := []struct {
		name   string
		mutate func(*VerifiedGrantV2, *VerifiedSessionBindingStatementV2)
	}{
		{
			name: "D4 agent public key is not a proof key",
			mutate: func(grant *VerifiedGrantV2, statement *VerifiedSessionBindingStatementV2) {
				grant.Values.AgentPublicKey = "agent-public-key"
				statement.SignerKey = grant.Values.AgentPublicKey
			},
		},
		{
			name: "role-agnostic endpoint list is not a proof authorization",
			mutate: func(grant *VerifiedGrantV2, statement *VerifiedSessionBindingStatementV2) {
				grant.AuthorizedEndpointKeys = []string{"endpoint-key"}
				statement.SignerKey = grant.AuthorizedEndpointKeys[0]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grant := baseGrant
			statement := baseStatement
			tt.mutate(&grant, &statement)
			err := ValidateSessionBindingStatementV2(grant, statement, now)
			if !errors.Is(err, ErrUnauthorizedBindingKey) {
				t.Fatalf("ValidateSessionBindingStatementV2() error = %v, want %v", err, ErrUnauthorizedBindingKey)
			}
		})
	}
}

func TestValidateSessionBindingStatementV2RejectsReplacementCharacter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	grant.Values.Service = "document\ufffdservice"

	err := ValidateSessionBindingStatementV2(grant, testSessionBindingStatementV2(now), now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("ValidateSessionBindingStatementV2() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func TestSessionReplayKeyV2CoversMinimumTupleAndHidesNonce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := testSessionBindingStatementV2(now)
	base.Binding.AttemptID = "attempt-1"
	baseKey, err := SessionReplayKeyV2(base)
	if err != nil {
		t.Fatalf("SessionReplayKeyV2() error = %v", err)
	}
	if strings.Contains(baseKey, base.Binding.VerifierNonce) {
		t.Fatal("SessionReplayKeyV2() exposed the verifier nonce")
	}
	if !strings.HasPrefix(baseKey, "sbaip-replay-v2:") {
		t.Fatalf("SessionReplayKeyV2() = %q, want domain-separated prefix", baseKey)
	}

	mutations := map[string]func(*VerifiedSessionBindingStatementV2){
		"grant hash":       func(v *VerifiedSessionBindingStatementV2) { v.GrantHash = "grant-hash-2" },
		"audience":         func(v *VerifiedSessionBindingStatementV2) { v.Audience = "audience-2" },
		"endpoint role":    func(v *VerifiedSessionBindingStatementV2) { v.Binding.EndpointRole = "server-tls-endpoint" },
		"interaction type": func(v *VerifiedSessionBindingStatementV2) { v.Binding.InteractionType = "agent-to-tool" },
		"TLS exporter":     func(v *VerifiedSessionBindingStatementV2) { v.Binding.TLSExporterSHA256 = "exporter-2" },
		"binding context":  func(v *VerifiedSessionBindingStatementV2) { v.Binding.BindingContextSHA256 = "context-2" },
		"verifier nonce":   func(v *VerifiedSessionBindingStatementV2) { v.Binding.VerifierNonce = "nonce-2" },
		"attempt ID":       func(v *VerifiedSessionBindingStatementV2) { v.Binding.AttemptID = "attempt-2" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			changedKey, err := SessionReplayKeyV2(changed)
			if err != nil {
				t.Fatalf("SessionReplayKeyV2() error = %v", err)
			}
			if changedKey == baseKey {
				t.Fatalf("SessionReplayKeyV2() unchanged after %s mutation", name)
			}
		})
	}
}

func TestMarkSessionBindingUsedV2FailsClosedWithoutCache(t *testing.T) {
	statement := testSessionBindingStatementV2(time.Unix(1_700_000_000, 0))

	tests := []struct {
		name  string
		cache ReplayCache
	}{
		{name: "nil interface", cache: nil},
		{name: "typed nil", cache: (*v2RecordingReplayCache)(nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MarkSessionBindingUsedV2(tt.cache, statement)
			if !errors.Is(err, ErrMissingReplayCacheV2) {
				t.Fatalf("MarkSessionBindingUsedV2() error = %v, want %v", err, ErrMissingReplayCacheV2)
			}
		})
	}
}

func TestMarkSessionBindingUsedV2RejectsReplay(t *testing.T) {
	statement := testSessionBindingStatementV2(time.Unix(1_700_000_000, 0))
	cache := &v2RecordingReplayCache{seen: make(map[string]struct{})}
	if err := MarkSessionBindingUsedV2(cache, statement); err != nil {
		t.Fatalf("MarkSessionBindingUsedV2() first error = %v", err)
	}
	if err := MarkSessionBindingUsedV2(cache, statement); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("MarkSessionBindingUsedV2() replay error = %v, want %v", err, ErrReplayDetected)
	}
}

func TestMarkSessionBindingUsedV2ClassifiesReplayStoreFailure(t *testing.T) {
	statement := testSessionBindingStatementV2(time.Unix(1_700_000_000, 0))
	cache := &v2RecordingReplayCache{fail: true}
	err := MarkSessionBindingUsedV2(cache, statement)
	if !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("MarkSessionBindingUsedV2() error = %v, want %v", err, ErrReplayUnavailable)
	}
}

type v2RecordingReplayCache struct {
	seen map[string]struct{}
	fail bool
}

func (cache *v2RecordingReplayCache) MarkUsed(key string, _ time.Time) error {
	if cache.fail {
		return errors.New("store unavailable")
	}
	if _, ok := cache.seen[key]; ok {
		return ErrReplayDetected
	}
	cache.seen[key] = struct{}{}
	return nil
}

func testBindingV2(now time.Time) BindingV2 {
	return BindingV2{
		EndpointRole:               "client-tls-endpoint",
		InteractionType:            "agent-to-agent",
		AcceptedEndpointSPKISHA256: "spki-hash",
		TLSExporterSHA256:          "exporter-hash",
		BindingContextSHA256:       "context-hash",
		VerifierNonce:              "nonce-1",
		IssuedAt:                   now.Add(-time.Second),
		ExpiresAt:                  now.Add(time.Minute),
	}
}

func testVerifiedGrantV2(now time.Time) VerifiedGrantV2 {
	return VerifiedGrantV2{
		VerifiedGrant: VerifiedGrant{
			Issuer:          "policy-authority",
			IssuerKey:       "authority-key",
			Audience:        "agent-b",
			GrantHash:       "grant-hash",
			ConfirmationKey: "agent-a-key",
			Values: Values{
				Service:              "document-service",
				Agent:                "agent-a",
				TaskID:               "task-1",
				CapabilityRef:        "cap:summarize",
				OntologyID:           "ontology:documents",
				Scopes:               []string{"document:read", "document:export"},
				Resources:            []string{"document-records", "audit-log"},
				AuthorizationDetails: []string{"summarize", "export"},
			},
			IssuedAt:  now.Add(-time.Minute),
			ExpiresAt: now.Add(5 * time.Minute),
		},
		Target: TargetV2{Resource: "document-api", Operation: "summarize"},
	}
}

func testSessionBindingStatementV2(now time.Time) VerifiedSessionBindingStatementV2 {
	return VerifiedSessionBindingStatementV2{
		GrantHash: "grant-hash",
		Audience:  "agent-b",
		SignerKey: "agent-a-key",
		Binding:   testBindingV2(now),
	}
}
