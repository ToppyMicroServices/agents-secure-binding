// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testV2ManagerKeyID = "manager-key-v2"
	testV2AgentKeyID   = "agent-key-v2"
	testV2AlternateKey = "alternate-key-v2"
	testV2Target       = "queue:documents"
)

var (
	testV2ManagerSecret      = []byte("manager-secret-v2")
	testV2AgentSecret        = []byte("agent-secret-v2")
	testV2AlternateKeySecret = []byte("alternate-secret-v2")
)

type jwtV2Fixture struct {
	now     time.Time
	binding identitypolicy.BindingV2
}

func newJWTV2Fixture() jwtV2Fixture {
	now := time.Unix(1_800_000_000, 0).UTC()
	return jwtV2Fixture{
		now: now,
		binding: identitypolicy.BindingV2{
			EndpointRole:               "client-tls-endpoint",
			InteractionType:            "agent-to-agent",
			AcceptedEndpointSPKISHA256: testV2Hash("1"),
			TLSExporterSHA256:          testV2Hash("2"),
			BindingContextSHA256:       testV2Hash("3"),
			AttestationBinderSHA256:    testV2Hash("4"),
			VerifierNonce:              base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
			AttemptID:                  base64.RawURLEncoding.EncodeToString([]byte("attempt-12345678")),
			IssuedAt:                   now,
			ExpiresAt:                  now.Add(time.Minute),
		},
	}
}

func TestIdentityGrantDigestPreservesV1Hash(t *testing.T) {
	const token = "header.payload.signature"
	const want = "sha256:0ad2e4b3203517d005caef419525a8d2845a5e95927cba22d81d69c0f9e8f3eb"

	if got := IdentityGrantHash(token); got != want {
		t.Fatalf("IdentityGrantHash() = %q, want %q", got, want)
	}
	digest := IdentityGrantDigest(token)
	if got := "sha256:" + strings.ToLower(base16(digest[:])); got != want {
		t.Fatalf("IdentityGrantDigest() = %q, want %q", got, want)
	}
}

func TestVerifyIdentityGrantJWTV2ExtractsTargetWithoutChangingAuthorization(t *testing.T) {
	fixture := newJWTV2Fixture()
	claims := fixture.grantClaims()
	claims["target_resource"] = testV2Target
	claims["target_operation"] = "message:send"
	claims["resource"] = "records:read"
	claims["x-non-critical"] = "ignored"
	token := signJWTV2(t, testV2ManagerKeyID, testV2ManagerSecret, IdentityGrantJWTTypeV2, claims, nil)

	grant, err := VerifyIdentityGrantJWTV2(token, fixture.grantOptions())
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWTV2() error = %v", err)
	}
	if grant.Target.Resource != testV2Target || grant.Target.Operation != "message:send" {
		t.Fatalf("Target = %#v", grant.Target)
	}
	if grant.JWTID != "grant-v2-1" {
		t.Fatalf("JWTID = %q, want grant-v2-1", grant.JWTID)
	}
	if len(grant.Values.Resources) != 1 || grant.Values.Resources[0] != "records:read" {
		t.Fatalf("D7 Resources = %#v", grant.Values.Resources)
	}
	if grant.GrantHash != IdentityGrantHash(token) {
		t.Fatalf("GrantHash = %q, want exact token digest", grant.GrantHash)
	}
}

func TestVerifyIdentityGrantJWTV2KeepsV1AliasPathSeparate(t *testing.T) {
	fixture := newJWTV2Fixture()
	claims := fixture.grantClaims()
	delete(claims, ClaimTokenType)
	delete(claims, ClaimProfileVersion)
	claims[LegacyClaimTokenType] = TokenTypeIdentityGrant
	claims[LegacyClaimProfileVersion] = ProfileVersion
	token := signJWTV2(t, testV2ManagerKeyID, testV2ManagerSecret, IdentityGrantJWTTypeV2, claims, nil)

	if _, err := VerifyIdentityGrantJWT(token, fixture.grantOptions()); err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() changed legacy v1 behavior: %v", err)
	}
	if _, err := VerifyIdentityGrantJWTV2(token, fixture.grantOptions()); !errors.Is(err, ErrInvalidJWTMember) {
		t.Fatalf("VerifyIdentityGrantJWTV2() error = %v, want ErrInvalidJWTMember", err)
	}
}

func TestVerifyIdentityGrantJWTV2RejectsAmbiguousWireForms(t *testing.T) {
	fixture := newJWTV2Fixture()

	tests := []struct {
		name         string
		mutateClaims func(jwt.MapClaims)
		header       map[string]any
		want         error
	}{
		{
			name: "audience array",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["aud"] = []string{"agent-b"}
			},
			want: ErrInvalidAudience,
		},
		{
			name: "case alias",
			mutateClaims: func(claims jwt.MapClaims) {
				delete(claims, "target_resource")
				claims["Target_Resource"] = testV2Target
			},
			want: ErrInvalidJWTMember,
		},
		{
			name: "missing issued at",
			mutateClaims: func(claims jwt.MapClaims) {
				delete(claims, "iat")
			},
			want: ErrMissingIssuedAt,
		},
		{
			name: "missing target resource",
			mutateClaims: func(claims jwt.MapClaims) {
				delete(claims, "target_resource")
			},
			want: ErrMissingTargetField,
		},
		{
			name: "missing target operation",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["target_operation"] = ""
			},
			want: ErrMissingTargetField,
		},
		{
			name: "unsafe target",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["target_resource"] = "queue:<script>"
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "scope alias collision",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["scopes"] = []string{"document:write"}
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "resource alias collision",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["resources"] = []string{"document:redacted"}
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "non-canonical scope separator",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["scope"] = "document:write\tdocument:read"
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "replacement character in decision value",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["service"] = "document\ufffdservice"
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "nested confirmation case alias",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["cnf"] = map[string]any{"KID": testV2AgentKeyID}
			},
			want: ErrInvalidJWTMember,
		},
		{
			name:         "extra protected header",
			mutateClaims: func(jwt.MapClaims) {},
			header:       map[string]any{"x-extra": "rejected"},
			want:         ErrInvalidProtectedHeader,
		},
		{
			name:         "wrong protected type",
			mutateClaims: func(jwt.MapClaims) {},
			header:       map[string]any{"typ": "jwt"},
			want:         ErrInvalidProtectedHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := fixture.grantClaims()
			test.mutateClaims(claims)
			token := signJWTV2(t, testV2ManagerKeyID, testV2ManagerSecret, IdentityGrantJWTTypeV2, claims, test.header)
			if _, err := VerifyIdentityGrantJWTV2(token, fixture.grantOptions()); !errors.Is(err, test.want) {
				t.Fatalf("VerifyIdentityGrantJWTV2() error = %v, want %v", err, test.want)
			}
		})
	}

	valid := fixture.signGrant(t, nil)
	unpairedSurrogate := rewriteJWTV2Payload(t, valid, testV2ManagerSecret, func(payload string) string {
		const member = `"service":"document-service"`
		if !strings.Contains(payload, member) {
			t.Fatalf("test payload does not contain %s", member)
		}
		return strings.Replace(payload, member, `"service":"\ud800"`, 1)
	})
	if _, err := VerifyIdentityGrantJWTV2(unpairedSurrogate, fixture.grantOptions()); !errors.Is(err, ErrInvalidClaimEncoding) {
		t.Fatalf("unpaired surrogate error = %v, want ErrInvalidClaimEncoding", err)
	}
}

func TestVerifyIdentityGrantJWTV2KeepsSingularResourceAtomic(t *testing.T) {
	fixture := newJWTV2Fixture()
	token := fixture.signGrant(t, func(claims jwt.MapClaims) {
		claims["resource"] = "document record"
	})

	grant, err := VerifyIdentityGrantJWTV2(token, fixture.grantOptions())
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWTV2() error = %v", err)
	}
	if len(grant.Values.Resources) != 1 || grant.Values.Resources[0] != "document record" {
		t.Fatalf("Resources = %#v, want one exact singular value", grant.Values.Resources)
	}
}

func TestV2AuthorizationAliasRulesDoNotChangeV1Parsing(t *testing.T) {
	fixture := newJWTV2Fixture()
	claims := fixture.grantClaims()
	claims["scopes"] = []string{"document:read"}
	token := signJWTV2(t, testV2ManagerKeyID, testV2ManagerSecret, IdentityGrantJWTTypeV2, claims, nil)

	if _, err := VerifyIdentityGrantJWT(token, fixture.grantOptions()); err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() changed v1 alias behavior: %v", err)
	}
	if _, err := VerifyIdentityGrantJWTV2(token, fixture.grantOptions()); !errors.Is(err, ErrInvalidClaimEncoding) {
		t.Fatalf("VerifyIdentityGrantJWTV2() error = %v, want ErrInvalidClaimEncoding", err)
	}
}

func TestVerifySessionBindingJWTV2AcceptsCanonicalProof(t *testing.T) {
	fixture := newJWTV2Fixture()
	grantToken := fixture.signGrant(t, nil)
	proofToken := fixture.signProof(t, grantToken, nil, nil)

	statement, err := VerifySessionBindingJWTV2(proofToken, fixture.proofOptions())
	if err != nil {
		t.Fatalf("VerifySessionBindingJWTV2() error = %v", err)
	}
	if statement.GrantHash != IdentityGrantHash(grantToken) {
		t.Fatalf("GrantHash = %q", statement.GrantHash)
	}
	if statement.JWTID != "proof-v2-1" {
		t.Fatalf("JWTID = %q, want proof-v2-1", statement.JWTID)
	}
	if !equalBindingV2(statement.Binding, fixture.binding) {
		t.Fatalf("Binding = %#v, want %#v", statement.Binding, fixture.binding)
	}
}

func TestVerifySessionBindingJWTV2RejectsNonCanonicalClaims(t *testing.T) {
	fixture := newJWTV2Fixture()
	grantToken := fixture.signGrant(t, nil)

	tests := []struct {
		name         string
		mutateClaims func(jwt.MapClaims)
		header       map[string]any
		want         error
	}{
		{
			name: "unknown proof member",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["unexpected"] = true
			},
			want: ErrInvalidJWTMember,
		},
		{
			name: "case alias",
			mutateClaims: func(claims jwt.MapClaims) {
				delete(claims, "endpoint_role")
				claims["Endpoint_Role"] = "client-tls-endpoint"
			},
			want: ErrInvalidJWTMember,
		},
		{
			name: "audience array",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["aud"] = []string{"agent-b"}
			},
			want: ErrInvalidAudience,
		},
		{
			name: "uppercase hash",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["binding_context_sha256"] = "sha256:" + strings.Repeat("A", 64)
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "padded nonce",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["verifier_nonce"] = base64.URLEncoding.EncodeToString([]byte("0123456789abcdef"))
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "short nonce",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["verifier_nonce"] = base64.RawURLEncoding.EncodeToString([]byte("short"))
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "empty optional attempt id",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["attempt_id"] = ""
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "empty optional attestation binder",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["attestation_binder_sha256"] = ""
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "missing issued at",
			mutateClaims: func(claims jwt.MapClaims) {
				delete(claims, "iat")
			},
			want: ErrMissingIssuedAt,
		},
		{
			name: "replacement character in proof id",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["jti"] = "proof\ufffdid"
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name: "control character in interaction type",
			mutateClaims: func(claims jwt.MapClaims) {
				claims["interaction_type"] = "agent-to-agent\n"
			},
			want: ErrInvalidClaimEncoding,
		},
		{
			name:         "extra protected header",
			mutateClaims: func(jwt.MapClaims) {},
			header:       map[string]any{"crit": []string{"x"}, "x": true},
			want:         ErrInvalidProtectedHeader,
		},
		{
			name:         "wrong protected type",
			mutateClaims: func(jwt.MapClaims) {},
			header:       map[string]any{"typ": "JWT"},
			want:         ErrInvalidProtectedHeader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := fixture.signProof(t, grantToken, test.mutateClaims, test.header)
			if _, err := VerifySessionBindingJWTV2(token, fixture.proofOptions()); !errors.Is(err, test.want) {
				t.Fatalf("VerifySessionBindingJWTV2() error = %v, want %v", err, test.want)
			}
		})
	}

	valid := fixture.signProof(t, grantToken, nil, nil)
	parts := strings.Split(valid, ".")
	parts[0] += "="
	if _, err := VerifySessionBindingJWTV2(strings.Join(parts, "."), fixture.proofOptions()); !errors.Is(err, ErrInvalidJWTEncoding) {
		t.Fatalf("padded compact segment error = %v, want ErrInvalidJWTEncoding", err)
	}

	duplicate := rewriteJWTV2Payload(t, valid, testV2AgentSecret, func(payload string) string {
		const member = `"aud":"agent-b"`
		if !strings.Contains(payload, member) {
			t.Fatalf("test payload does not contain %s", member)
		}
		return strings.Replace(payload, member, member+","+member, 1)
	})
	if _, err := VerifySessionBindingJWTV2(duplicate, fixture.proofOptions()); !errors.Is(err, ErrDuplicateJWTMember) {
		t.Fatalf("duplicate member error = %v, want ErrDuplicateJWTMember", err)
	}
}

func TestVerifySessionIdentityJWTV2AttestationAndReplayOrder(t *testing.T) {
	fixture := newJWTV2Fixture()
	grantToken := fixture.signGrant(t, nil)
	proofToken := fixture.signProof(t, grantToken, nil, nil)

	t.Run("binding mismatch precedes attestation", func(t *testing.T) {
		replay := &v2ReplaySpy{}
		opts := fixture.sessionOptions(replay)
		opts.ExpectedBinding.TLSExporterSHA256 = testV2Hash("5")
		called := false
		opts.AttestationVerifier = func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			called = true
			return fixture.attestationResult(), nil
		}
		if _, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts); err == nil {
			t.Fatal("VerifySessionIdentityJWTV2() error = nil, want binding rejection")
		}
		if called {
			t.Fatal("attestation callback ran before accepted-binding comparison")
		}
		if replay.calls != 0 {
			t.Fatalf("replay calls = %d, want 0", replay.calls)
		}
	})

	t.Run("missing verifier fails before replay", func(t *testing.T) {
		replay := &v2ReplaySpy{}
		opts := fixture.sessionOptions(replay)
		opts.AttestationVerifier = nil
		_, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
		if !errors.Is(err, ErrMissingAttestationVerifier) {
			t.Fatalf("error = %v, want ErrMissingAttestationVerifier", err)
		}
		if replay.calls != 0 {
			t.Fatalf("replay calls = %d, want 0", replay.calls)
		}
	})

	t.Run("rejected attestation fails before policy and replay", func(t *testing.T) {
		replay := &v2ReplaySpy{}
		opts := fixture.sessionOptions(replay)
		want := errors.New("attestation rejected")
		opts.AttestationVerifier = func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			return identitypolicy.VerifiedAttestationResultV2{}, want
		}
		_, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want wrapped attestation error", err)
		}
		if replay.calls != 0 {
			t.Fatalf("replay calls = %d, want 0", replay.calls)
		}
	})

	t.Run("callback precedes D3 rejection", func(t *testing.T) {
		replay := &v2ReplaySpy{}
		opts := fixture.sessionOptions(replay)
		opts.Policy.Expected.Service = "wrong-service"
		called := false
		opts.AttestationVerifier = func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			called = true
			return fixture.attestationResult(), nil
		}
		if _, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts); err == nil {
			t.Fatal("VerifySessionIdentityJWTV2() error = nil, want D3 rejection")
		}
		if !called {
			t.Fatal("attestation callback was not called before D3")
		}
		if replay.calls != 0 {
			t.Fatalf("replay calls = %d, want 0", replay.calls)
		}
	})

	t.Run("success commits replay last", func(t *testing.T) {
		replay := &v2ReplaySpy{}
		opts := fixture.sessionOptions(replay)
		attestationCalled := false
		opts.AttestationVerifier = func(grant identitypolicy.VerifiedGrantV2, statement identitypolicy.VerifiedSessionBindingStatementV2, expected identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			attestationCalled = true
			if grant.GrantHash != statement.GrantHash || !equalBindingV2(statement.Binding, expected) {
				return identitypolicy.VerifiedAttestationResultV2{}, errors.New("attestation inputs did not match accepted binding")
			}
			return fixture.attestationResult(), nil
		}
		result, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
		if err != nil {
			t.Fatalf("VerifySessionIdentityJWTV2() error = %v", err)
		}
		if !attestationCalled || replay.calls != 1 {
			t.Fatalf("attestation called = %t, replay calls = %d", attestationCalled, replay.calls)
		}
		if result.Accepted.AcceptedProfile.BindingProfile != "draft06-v2" ||
			result.Accepted.Scope.BindingContextSHA256 != fixture.binding.BindingContextSHA256 ||
			result.Accepted.AcceptedChannel.EndpointRole != fixture.binding.EndpointRole ||
			result.Accepted.AcceptedActor.ID != "agent-a" ||
			result.Accepted.AcceptedAuthority.Issuer != "manager" ||
			result.Accepted.AcceptedInteraction.Type != "agent-to-agent" ||
			result.Accepted.AttestationResult == nil ||
			result.Accepted.ReplayCommit.State != identitypolicy.ReplayCommitStateCommittedV2 {
			t.Fatalf("accepted assertion is incomplete: %#v", result.Accepted)
		}
		if result.Accepted.AcceptedTarget == nil || result.Accepted.AcceptedTarget.Resource != testV2Target || result.Accepted.EffectiveAuthorization.CapabilityRef != "cap:summarize" {
			t.Fatalf("result = %#v", result)
		}
		if result.Accepted.AcceptedInteraction.Service != "document-service" || result.Accepted.AcceptedInteraction.TaskID != "task-1" || result.Accepted.AcceptedInteraction.ThreadID != "" {
			t.Fatalf("accepted interaction exposes surplus grant fields: %#v", result.Accepted.AcceptedInteraction)
		}
		if !result.Accepted.Expiry.Equal(fixture.binding.ExpiresAt) {
			t.Fatalf("accepted expiry = %v, want %v", result.Accepted.Expiry, fixture.binding.ExpiresAt)
		}
		if !replay.expiresAt.Equal(result.Accepted.ReplayCommit.RetainUntil) || replay.expiresAt.Before(result.Accepted.Expiry) || strings.Contains(replay.key, fixture.binding.VerifierNonce) {
			t.Fatalf("replay store = %q/%v, assertion = %#v", replay.key, replay.expiresAt, result.Accepted.ReplayCommit)
		}
	})

	t.Run("expiry crossed during replay commit returns no assertion", func(t *testing.T) {
		current := fixture.now
		replay := &v2ReplaySpy{onMark: func() { current = fixture.binding.ExpiresAt }}
		opts := fixture.sessionOptions(replay)
		opts.Clock = func() time.Time { return current }
		result, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
		if !errors.Is(err, identitypolicy.ErrExpiredAssertion) {
			t.Fatalf("error = %v, want %v", err, identitypolicy.ErrExpiredAssertion)
		}
		if replay.calls != 1 || !result.Accepted.Expiry.IsZero() || result.Accepted.ReplayCommit.State != "" {
			t.Fatalf("replay calls = %d, accepted = %#v", replay.calls, result.Accepted)
		}
	})
}

func TestVerifySessionIdentityJWTV2RejectsNonConfirmationProofKeys(t *testing.T) {
	fixture := newJWTV2Fixture()
	tests := []struct {
		name       string
		grantClaim string
	}{
		{name: "agent public key", grantClaim: "agent_public_key"},
		{name: "role-agnostic endpoint key", grantClaim: "authorized_endpoint_keys"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantToken := fixture.signGrant(t, func(claims jwt.MapClaims) {
				if tt.grantClaim == "authorized_endpoint_keys" {
					claims[tt.grantClaim] = []string{testV2AlternateKey}
				} else {
					claims[tt.grantClaim] = testV2AlternateKey
				}
			})
			proofToken := signJWTV2(t, testV2AlternateKey, testV2AlternateKeySecret, SessionBindingJWTTypeV2, fixture.proofClaims(grantToken), nil)
			replay := &v2ReplaySpy{}
			opts := fixture.sessionOptions(replay)
			opts.SessionBinding.KeyFunc = clientTestKeyFunc(map[string][]byte{testV2AlternateKey: testV2AlternateKeySecret})

			_, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
			if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
				t.Fatalf("VerifySessionIdentityJWTV2() error = %v, want ErrUnauthorizedBindingKey", err)
			}
			if replay.calls != 0 {
				t.Fatalf("replay calls = %d, want 0", replay.calls)
			}
		})
	}
}

func TestVerifySessionIdentityJWTV2TypedNilReplayFailsClosed(t *testing.T) {
	fixture := newJWTV2Fixture()
	grantToken := fixture.signGrant(t, nil)
	proofToken := fixture.signProof(t, grantToken, nil, nil)
	var replay *v2ReplaySpy
	opts := fixture.sessionOptions(replay)

	_, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
	if !errors.Is(err, identitypolicy.ErrMissingReplayCacheV2) {
		t.Fatalf("error = %v, want ErrMissingReplayCacheV2", err)
	}
}

func TestVerifySessionIdentityJWTV2AllowsNoAttestationWhenNotSelected(t *testing.T) {
	fixture := newJWTV2Fixture()
	fixture.binding.AttestationBinderSHA256 = ""
	grantToken := fixture.signGrant(t, nil)
	proofToken := fixture.signProof(t, grantToken, nil, nil)
	replay := &v2ReplaySpy{}
	opts := fixture.sessionOptions(replay)
	opts.AttestationVerifier = nil

	if _, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts); err != nil {
		t.Fatalf("VerifySessionIdentityJWTV2() error = %v", err)
	}
	if replay.calls != 1 {
		t.Fatalf("replay calls = %d, want 1", replay.calls)
	}
}

func TestVerifySessionIdentityJWTV2ConfiguredVerifierRequiresBinder(t *testing.T) {
	fixture := newJWTV2Fixture()
	fixture.binding.AttestationBinderSHA256 = ""
	grantToken := fixture.signGrant(t, nil)
	proofToken := fixture.signProof(t, grantToken, nil, nil)
	replay := &v2ReplaySpy{}
	opts := fixture.sessionOptions(replay)
	called := false
	opts.AttestationVerifier = func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
		called = true
		return fixture.attestationResult(), nil
	}

	_, err := VerifySessionIdentityJWTV2(grantToken, proofToken, opts)
	if !errors.Is(err, ErrMissingAttestationBinder) {
		t.Fatalf("VerifySessionIdentityJWTV2() error = %v, want ErrMissingAttestationBinder", err)
	}
	if called || replay.calls != 0 {
		t.Fatalf("attestation called = %t, replay calls = %d, want false/0", called, replay.calls)
	}
}

type v2ReplaySpy struct {
	calls     int
	key       string
	expiresAt time.Time
	err       error
	onMark    func()
}

func (r *v2ReplaySpy) MarkUsed(key string, expiresAt time.Time) error {
	if r == nil {
		return errors.New("typed-nil replay method called")
	}
	r.calls++
	r.key = key
	r.expiresAt = expiresAt
	if r.onMark != nil {
		r.onMark()
	}
	return r.err
}

func (f jwtV2Fixture) grantClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                   "manager",
		"sub":                   "agent-a",
		"aud":                   "agent-b",
		"jti":                   "grant-v2-1",
		"iat":                   f.now.Unix(),
		"exp":                   f.now.Add(time.Minute).Unix(),
		ClaimTokenType:          TokenTypeIdentityGrant,
		ClaimProfileVersion:     ProfileVersion,
		"cnf":                   map[string]any{"kid": testV2AgentKeyID},
		"service":               "document-service",
		"agent":                 "agent-a",
		"task_id":               "task-1",
		"thread_id":             "thread-1",
		"target_resource":       testV2Target,
		"target_operation":      "message:send",
		"capability_ref":        "cap:summarize",
		"scope":                 "document:write",
		"resource":              "document:redacted",
		"authorization_details": []string{"document:submit"},
	}
}

func (f jwtV2Fixture) proofClaims(grantToken string) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss":                           "agent-a",
		"aud":                           "agent-b",
		"jti":                           "proof-v2-1",
		"iat":                           f.now.Unix(),
		"exp":                           f.now.Add(time.Minute).Unix(),
		ClaimTokenType:                  TokenTypeSessionBinding,
		ClaimProfileVersion:             ProfileVersionV2,
		"grant_hash":                    IdentityGrantHash(grantToken),
		"endpoint_role":                 f.binding.EndpointRole,
		"interaction_type":              f.binding.InteractionType,
		"accepted_endpoint_spki_sha256": f.binding.AcceptedEndpointSPKISHA256,
		"tls_exporter_sha256":           f.binding.TLSExporterSHA256,
		"binding_context_sha256":        f.binding.BindingContextSHA256,
		"verifier_nonce":                f.binding.VerifierNonce,
	}
	if f.binding.AttestationBinderSHA256 != "" {
		claims["attestation_binder_sha256"] = f.binding.AttestationBinderSHA256
	}
	if f.binding.AttemptID != "" {
		claims["attempt_id"] = f.binding.AttemptID
	}
	return claims
}

func (f jwtV2Fixture) signGrant(t *testing.T, mutate func(jwt.MapClaims)) string {
	t.Helper()
	claims := f.grantClaims()
	if mutate != nil {
		mutate(claims)
	}
	return signJWTV2(t, testV2ManagerKeyID, testV2ManagerSecret, IdentityGrantJWTTypeV2, claims, nil)
}

func (f jwtV2Fixture) signProof(t *testing.T, grantToken string, mutate func(jwt.MapClaims), header map[string]any) string {
	t.Helper()
	claims := f.proofClaims(grantToken)
	if mutate != nil {
		mutate(claims)
	}
	return signJWTV2(t, testV2AgentKeyID, testV2AgentSecret, SessionBindingJWTTypeV2, claims, header)
}

func (f jwtV2Fixture) grantOptions() JWTVerifyOptions {
	return JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "agent-b",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          clientTestKeyFunc(map[string][]byte{testV2ManagerKeyID: testV2ManagerSecret}),
		Now:              f.now,
	}
}

func (f jwtV2Fixture) proofOptions() JWTVerifyOptions {
	return JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "agent-b",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          clientTestKeyFunc(map[string][]byte{testV2AgentKeyID: testV2AgentSecret}),
		Now:              f.now,
	}
}

func (f jwtV2Fixture) sessionOptions(replay identitypolicy.ReplayCache) SessionIdentityJWTOptionsV2 {
	return SessionIdentityJWTOptionsV2{
		Grant:           f.grantOptions(),
		SessionBinding:  f.proofOptions(),
		ExpectedBinding: f.binding,
		AcceptedProfile: identitypolicy.ProfileSelectionV2{
			ProfileType: TokenTypeSessionBinding, ProfileVersion: ProfileVersionV2,
			BindingProfile: "draft06-v2", ProtocolID: "urn:test:a2a-http-json:v2",
		},
		Freshness: identitypolicy.FreshnessInputsV2{
			EndpointCredentialExpiresAt: f.now.Add(10 * time.Minute),
			EvidenceChallengeExpiresAt:  f.now.Add(2 * time.Minute),
			LocalPolicyExpiresAt:        f.now.Add(3 * time.Minute),
		},
		ReplayCache: replay,
		Clock:       func() time.Time { return f.now },
		Now:         f.now,
		Policy: identitypolicy.PolicyV2{
			Mode:    identitypolicy.ModeRequired,
			SetMode: identitypolicy.SetModeContainsAll,
			Require: identitypolicy.RequirementsV2{D3: true, D4: true, D5: true, D6: true, D7: true},
			Expected: identitypolicy.Values{
				Service: "document-service", Agent: "agent-a", TaskID: "task-1",
			},
			ExpectedTarget: identitypolicy.TargetV2{
				Resource:  testV2Target,
				Operation: "message:send",
			},
			ExpectedAuthorization: identitypolicy.AuthorizationV2{
				CapabilityRef:        "cap:summarize",
				Scopes:               []string{"document:write"},
				Resources:            []string{"document:redacted"},
				AuthorizationDetails: []string{"document:submit"},
			},
		},
		AttestationVerifier: func(identitypolicy.VerifiedGrantV2, identitypolicy.VerifiedSessionBindingStatementV2, identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			return f.attestationResult(), nil
		},
	}
}

func (f jwtV2Fixture) attestationResult() identitypolicy.VerifiedAttestationResultV2 {
	return identitypolicy.VerifiedAttestationResultV2{
		ProfileType:       "sbaip.attestation-result",
		ProfileVersion:    "2",
		ResultID:          "attestation-result-v2-1",
		Issuer:            "attestation-verifier",
		Subject:           "agent-a",
		SignerKeyID:       "attestation-verifier-key",
		Audience:          "agent-b",
		AppraisalPolicyID: "urn:test:attestation-policy:v2",
		BinderSHA256:      f.binding.AttestationBinderSHA256,
		IssuedAt:          f.now.Add(-time.Second),
		ExpiresAt:         f.now.Add(2 * time.Minute),
	}
}

func signJWTV2(t *testing.T, keyID string, secret []byte, typ string, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = typ
	for name, value := range header {
		token.Header[name] = value
	}
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func rewriteJWTV2Payload(t *testing.T, tokenString string, secret []byte, rewrite func(string) string) string {
	t.Helper()
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWT has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(rewrite(string(payload))))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	parts[2] = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return strings.Join(parts, ".")
}

func testV2Hash(hexDigit string) string {
	return "sha256:" + strings.Repeat(hexDigit, 64)
}

func base16(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2] = alphabet[b>>4]
		out[i*2+1] = alphabet[b&0x0f]
	}
	return string(out)
}

func equalBindingV2(left, right identitypolicy.BindingV2) bool {
	return left.EndpointRole == right.EndpointRole &&
		left.InteractionType == right.InteractionType &&
		left.AcceptedEndpointSPKISHA256 == right.AcceptedEndpointSPKISHA256 &&
		left.TLSExporterSHA256 == right.TLSExporterSHA256 &&
		left.BindingContextSHA256 == right.BindingContextSHA256 &&
		left.AttestationBinderSHA256 == right.AttestationBinderSHA256 &&
		left.VerifierNonce == right.VerifierNonce &&
		left.AttemptID == right.AttemptID &&
		left.IssuedAt.Equal(right.IssuedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}
