// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/authorityquorum"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

const testAudience = "reveal.example"

func TestProfileStoresExactASBBoundApprovalAndDeduplicatesReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	resolver, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "quorum-policy-authority",
			ActorID: "broker:a", ProofIssuer: "quorum-broker", SignerKey: "broker-a-key",
			CredentialDigest: testCredentialDigest(t, "actor-secret-for-authority-quorum-tests"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t, now, resolver.AuthorityMapDigest())
	current := now
	store := authorityquorum.NewMemoryStoreWithClock(func() time.Time { return current })
	service := authorityquorum.Service{
		Store: store,
		Policies: authorityquorum.PolicyResolverFunc(func(context.Context, string) (authorityquorum.VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return current },
	}
	profile := Profile{Service: service, Authorities: resolver}
	request := authorityquorum.ApprovalRequest{
		DecisionID: "decision:1", PolicyDigest: policy.PolicyDigest,
		OperationDigest: "sha256:" + strings.Repeat("a", 64),
	}
	digest, err := authorityquorum.ApprovalDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, "broker:a", "broker-a-key", digest, digest)
	approval, err := profile.Submit(context.Background(), request, evidence)
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if approval.AuthorityID != "authority:a" || !strings.HasPrefix(approval.ApprovalID, "approval:") ||
		approval.ApprovalID == "proof:broker:a" {
		t.Fatalf("approval projection = %+v", approval)
	}
	current = current.Add(5 * time.Second)
	retried, err := profile.Submit(context.Background(), request, evidence)
	if err != nil {
		t.Fatalf("exact replay should be idempotent: %v", err)
	}
	if !retried.ApprovedAt.Equal(approval.ApprovedAt) {
		t.Fatalf("retry changed approved_at: %s / %s", approval.ApprovedAt, retried.ApprovedAt)
	}
}

func TestProfileRejectsMutatedRequestAndUnknownAuthority(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	resolver, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "quorum-policy-authority",
			ActorID: "broker:a", ProofIssuer: "quorum-broker", SignerKey: "broker-a-key",
			CredentialDigest: testCredentialDigest(t, "actor-secret-for-authority-quorum-tests"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t, now, resolver.AuthorityMapDigest())
	service := authorityquorum.Service{
		Store: authorityquorum.NewMemoryStoreWithClock(func() time.Time { return now }),
		Policies: authorityquorum.PolicyResolverFunc(func(context.Context, string) (authorityquorum.VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return now },
	}
	profile := Profile{Service: service, Authorities: resolver}
	original := authorityquorum.ApprovalRequest{
		DecisionID: "decision:1", PolicyDigest: policy.PolicyDigest,
		OperationDigest: "sha256:" + strings.Repeat("b", 64),
	}
	digest, err := authorityquorum.ApprovalDigest(original)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, "broker:a", "broker-a-key", digest, digest)
	mutated := original
	mutated.OperationDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := profile.Submit(context.Background(), mutated, evidence); !errors.Is(err, ErrRequestContextMismatch) {
		t.Fatalf("mutated request error = %v", err)
	}

	unknownEvidence := testEvidence(t, now, "broker:unknown", "unknown-key", digest, digest)
	if _, err := profile.Submit(context.Background(), original, unknownEvidence); !errors.Is(err, ErrUnknownAuthority) {
		t.Fatalf("unknown authority error = %v", err)
	}

	wrongTransport := evidence
	wrongTransport.Options.ExpectedBinding.TLSExporterSHA256 = strings.Repeat("3", 64)
	if _, err := profile.Submit(context.Background(), original, wrongTransport); err == nil {
		t.Fatal("mismatched TLS exporter was accepted")
	}
	invalidMode := evidence
	invalidMode.Options.Policy.Mode = identitypolicy.Mode("unsupported")
	if _, err := profile.Submit(context.Background(), original, invalidMode); !errors.Is(err, ErrAmbiguousPolicy) {
		t.Fatalf("invalid policy mode error = %v", err)
	}
	revokedProof := evidence
	revokedProof.Options.SessionBinding.RevokedJWTIDs = []string{"proof:broker:a"}
	if _, err := profile.Submit(context.Background(), original, revokedProof); err == nil {
		t.Fatal("revoked session proof was accepted")
	}
}

func TestProfileResamplesTimeAfterAuthorityResolution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	resolver, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "quorum-policy-authority",
			ActorID: "broker:a", ProofIssuer: "quorum-broker", SignerKey: "broker-a-key",
			CredentialDigest: testCredentialDigest(t, "actor-secret-for-authority-quorum-tests"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(t, now, resolver.AuthorityMapDigest())
	current := now
	store := authorityquorum.NewMemoryStoreWithClock(func() time.Time { return current })
	service := authorityquorum.Service{
		Store: store,
		Policies: authorityquorum.PolicyResolverFunc(func(context.Context, string) (authorityquorum.VerifiedPolicy, error) {
			return policy, nil
		}),
		Now: func() time.Time { return current },
	}
	delayedResolver := AuthorityResolverFunc(func(ctx context.Context, actor VerifiedActor) (ResolvedAuthority, error) {
		current = now.Add(2 * time.Minute)
		return resolver.ResolveAuthority(ctx, actor)
	})
	profile := Profile{Service: service, Authorities: delayedResolver}
	request := authorityquorum.ApprovalRequest{
		DecisionID: "decision:delayed", PolicyDigest: policy.PolicyDigest,
		OperationDigest: "sha256:" + strings.Repeat("d", 64),
	}
	digest, err := authorityquorum.ApprovalDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	evidence := testEvidence(t, now, "broker:a", "broker-a-key", digest, digest)
	if _, err := profile.Submit(context.Background(), request, evidence); !errors.Is(err, authorityquorum.ErrExpired) {
		t.Fatalf("delayed authority resolution error = %v", err)
	}
}

func TestStaticResolverPreventsKeyInflationAndCollapsesRotation(t *testing.T) {
	t.Parallel()
	if _, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "grant:a", ActorID: "broker:a", ProofIssuer: "issuer:a",
			SignerKey: "key-a", CredentialDigest: testCredentialDigest(t, "shared-key-material"),
		},
		{
			AuthorityID: "authority:b", GrantIssuer: "grant:b", ActorID: "broker:b", ProofIssuer: "issuer:b",
			SignerKey: "key-b", CredentialDigest: testCredentialDigest(t, "shared-key-material"),
		},
	}); err == nil {
		t.Fatal("same verification key assigned to two authority slots")
	}
	if _, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "grant:shared", ActorID: "broker:shared", ProofIssuer: "issuer:shared",
			SignerKey: "key-a", CredentialDigest: testCredentialDigest(t, "key-a-material"),
		},
		{
			AuthorityID: "authority:b", GrantIssuer: "grant:shared", ActorID: "broker:shared", ProofIssuer: "issuer:shared",
			SignerKey: "key-b", CredentialDigest: testCredentialDigest(t, "key-b-material"),
		},
	}); err == nil {
		t.Fatal("same verified actor assigned to two authority slots")
	}
	resolver, err := NewStaticAuthorityResolver([]AuthorityCredential{
		{
			AuthorityID: "authority:a", GrantIssuer: "grant:a", ActorID: "broker:a", ProofIssuer: "issuer:a",
			SignerKey: "old-key", CredentialDigest: testCredentialDigest(t, "old-key-material"),
		},
		{
			AuthorityID: "authority:a", GrantIssuer: "grant:a", ActorID: "broker:a", ProofIssuer: "issuer:a",
			SignerKey: "new-key", CredentialDigest: testCredentialDigest(t, "new-key-material"),
		},
		{
			AuthorityID: "authority:b", GrantIssuer: "grant:b", ActorID: "broker:b", ProofIssuer: "issuer:b",
			SignerKey: "old-key", CredentialDigest: testCredentialDigest(t, "independent-key-material"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"old-key", "new-key"} {
		resolved, err := resolver.ResolveAuthority(context.Background(), VerifiedActor{
			GrantIssuer: "grant:a", ActorID: "broker:a", ProofIssuer: "issuer:a", SignerKey: key,
			CredentialDigest: map[string]string{
				"old-key": testCredentialDigest(t, "old-key-material"),
				"new-key": testCredentialDigest(t, "new-key-material"),
			}[key],
		})
		if err != nil {
			t.Fatal(err)
		}
		if resolved.AuthorityID != "authority:a" || resolved.AuthorityMapDigest != resolver.AuthorityMapDigest() {
			t.Fatalf("rotation key %s resolved to %+v", key, resolved)
		}
	}
	resolved, err := resolver.ResolveAuthority(context.Background(), VerifiedActor{
		GrantIssuer: "grant:b", ActorID: "broker:b", ProofIssuer: "issuer:b", SignerKey: "old-key",
		CredentialDigest: testCredentialDigest(t, "independent-key-material"),
	})
	if err != nil || resolved.AuthorityID != "authority:b" {
		t.Fatalf("issuer-scoped key label resolved to %+v: %v", resolved, err)
	}
	if _, err := resolver.ResolveAuthority(context.Background(), VerifiedActor{
		GrantIssuer: "grant:b", ActorID: "broker:b", ProofIssuer: "issuer:b", SignerKey: "old-key",
		CredentialDigest: testCredentialDigest(t, "wrong-key-material"),
	}); !errors.Is(err, ErrUnknownAuthority) {
		t.Fatalf("credential fingerprint mismatch error = %v", err)
	}
}

func TestStaticResolverRejectsOrderDependentDuplicateTuple(t *testing.T) {
	t.Parallel()
	first := AuthorityCredential{
		AuthorityID: "authority:a", GrantIssuer: "grant:a", ActorID: "broker:a",
		ProofIssuer: "issuer:a", SignerKey: "current",
		CredentialDigest: testCredentialDigest(t, "first-key-material"),
	}
	second := first
	second.CredentialDigest = testCredentialDigest(t, "second-key-material")
	for _, credentials := range [][]AuthorityCredential{{first, second}, {second, first}} {
		if _, err := NewStaticAuthorityResolver(credentials); err == nil {
			t.Fatal("duplicate actor credential tuple was accepted")
		}
	}
}

func testPolicy(t *testing.T, now time.Time, authorityMapDigest string) authorityquorum.VerifiedPolicy {
	t.Helper()
	policy, err := authorityquorum.NewVerifiedPolicy(
		"policy:test", testAudience, authorityMapDigest, 1, 1, []string{"authority:a"},
		now.Add(-time.Minute), now.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testEvidence(
	t *testing.T,
	now time.Time,
	actorID string,
	actorKeyID string,
	authorizedDigest authorityquorum.Digest,
	contextDigest authorityquorum.Digest,
) Evidence {
	t.Helper()
	managerSecret := []byte("manager-secret-for-authority-quorum-tests")
	actorSecret := []byte("actor-secret-for-authority-quorum-tests")
	grant := signJWT(t, "manager-key", managerSecret, jwt.MapClaims{
		"iss": "quorum-policy-authority", "sub": actorID, "aud": testAudience,
		"jti": "authorization:" + actorID, "iat": now.Add(-2 * time.Minute).Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "profile_type": clients.TokenTypeIdentityGrant,
		"profile_version": clients.ProfileVersion, "cnf": map[string]any{"kid": actorKeyID},
		"authorization_details": []string{authorityquorum.AuthorizationDetail(authorizedDigest)},
	})
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256: strings.Repeat("1", 64), TLSExporterSHA256: strings.Repeat("2", 64),
		RequestContextSHA256: authorityquorum.RequestContextSHA256(contextDigest), Nonce: "nonce:" + actorID,
	}
	proof := signJWT(t, actorKeyID, actorSecret, jwt.MapClaims{
		"iss": "quorum-broker", "aud": testAudience, "jti": "proof:" + actorID,
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256, "nonce": binding.Nonce,
	})
	return Evidence{
		GrantJWT: grant, SessionBindingJWT: proof, AcceptedUntil: now.Add(time.Minute),
		Options: VerificationOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer: "quorum-policy-authority", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: "manager-key", Key: managerSecret}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer: "quorum-broker", ExpectedAudience: testAudience,
				ValidMethods: []string{"HS256"}, LocalKeys: []clients.LocalKey{{KeyID: actorKeyID, Key: actorSecret}},
			},
			ExpectedBinding: binding,
		},
	}
}

func testCredentialDigest(t *testing.T, value string) string {
	t.Helper()
	digest, err := VerificationKeyDigest([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func signJWT(t *testing.T, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
