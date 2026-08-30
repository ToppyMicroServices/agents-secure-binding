// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	attestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	testServicePayments     = "payments"
	testServiceAnalytics    = "analytics"
	testIntentOrdersSettle  = "urn:agtp:intent:orders:settle:v1"
	testCapabilitySettle    = "urn:agtp:capability:orders:settle"
	testOntologyOrders      = "urn:agtp:ontology:orders:v1"
	testResourceOrdersBatch = "urn:agtp:resource:orders:batch-42"
)

func TestVerifyIdentityGrantJWTMapsClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":               "manager",
		"sub":               "agent-a",
		"aud":               "client-a",
		"jti":               "grant-1",
		"iat":               now.Unix(),
		"exp":               now.Add(time.Minute).Unix(),
		ClaimTokenType:      TokenTypeIdentityGrant,
		ClaimProfileVersion: ProfileVersion,
		"cnf":               map[string]any{"kid": "agent-key-1"},
		"service":           testServicePayments,
		"tenant":            "tenant-a",
		"deployment":        "prod",
		"intent_ref":        testIntentOrdersSettle,
		"capability_ref":    testCapabilitySettle,
		"ontology_id":       testOntologyOrders,
		"scope":             "orders:read orders:write",
		"resource":          "orders",
	})

	grant, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}

	if grant.Issuer != "manager" || grant.Audience != "client-a" {
		t.Fatalf("grant issuer/audience = %q/%q", grant.Issuer, grant.Audience)
	}
	if grant.ConfirmationKey != "agent-key-1" {
		t.Fatalf("grant confirmation key = %q, want agent-key-1", grant.ConfirmationKey)
	}
	if grant.GrantHash != IdentityGrantHash(tokenString) {
		t.Fatalf("grant hash = %q, want profile hash", grant.GrantHash)
	}
	if grant.Values.Agent != "agent-a" {
		t.Fatalf("grant agent = %q, want sub fallback", grant.Values.Agent)
	}
	if grant.Values.IntentRef != testIntentOrdersSettle {
		t.Fatalf("grant intent ref = %q, want canonical intent ref", grant.Values.IntentRef)
	}
	if grant.Values.CapabilityRef != testCapabilitySettle {
		t.Fatalf("grant capability ref = %q, want canonical capability ref", grant.Values.CapabilityRef)
	}
	if grant.Values.OntologyID != testOntologyOrders {
		t.Fatalf("grant ontology id = %q, want canonical ontology id", grant.Values.OntologyID)
	}
	if !slices.Equal(grant.Values.Scopes, []string{"orders:read", "orders:write"}) {
		t.Fatalf("grant scopes = %#v", grant.Values.Scopes)
	}
	if !slices.Equal(grant.Values.Resources, []string{"orders"}) {
		t.Fatalf("grant resources = %#v", grant.Values.Resources)
	}
}

func TestIdentityGrantHashUsesSSOTDomainSeparator(t *testing.T) {
	tokenString := "header.payload.signature"
	sum := sha256.Sum256([]byte("sbaip.identity-grant.jwt.v1\x00" + tokenString))
	want := "sha256:" + hex.EncodeToString(sum[:])

	if got := IdentityGrantHash(tokenString); got != want {
		t.Fatalf("IdentityGrantHash() = %q, want %q", got, want)
	}
}

func TestVerifyIdentityGrantJWTAcceptsLegacyAGTPProfileClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":                     "manager",
		"sub":                     "agent-a",
		"aud":                     "client-a",
		"jti":                     "grant-1",
		"iat":                     now.Unix(),
		"exp":                     now.Add(time.Minute).Unix(),
		LegacyClaimTokenType:      LegacyTokenTypeIdentityGrant,
		LegacyClaimProfileVersion: ProfileVersion,
		"cnf":                     map[string]any{"kid": "agent-key-1"},
		"service":                 testServicePayments,
	})

	grant, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}
	if grant.GrantHash != IdentityGrantHash(tokenString) {
		t.Fatalf("grant hash = %q, want SSOT profile hash", grant.GrantHash)
	}
}

func TestVerifyIdentityGrantJWTAcceptsLocalKeySet(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	grant, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		Now: now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}
	if grant.ConfirmationKey != "agent-key-1" {
		t.Fatalf("grant confirmation key = %q, want agent-key-1", grant.ConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsDisabledLocalKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret"), Disabled: true},
		},
		Now: now,
	})
	if !errors.Is(err, ErrDisabledKeyID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrDisabledKeyID)
	}
}

func TestVerifyIdentityGrantJWTRejectsDisabledKeyFuncKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc: testKeyFunc(map[string][]byte{
			"manager-key": []byte("manager-secret"),
		}),
		DisabledKeyIDs: []string{"manager-key"},
		Now:            now,
	})
	if !errors.Is(err, ErrDisabledKeyID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrDisabledKeyID)
	}
}

func TestVerifyIdentityGrantJWTRejectsRevokedGrantID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		RevokedJWTIDs: []string{"grant-1"},
		Now:           now,
	})
	if !errors.Is(err, ErrRevokedJWTID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrRevokedJWTID)
	}
}

func TestVerifyIdentityGrantJWTRejectsAmbiguousKeySource(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		LocalKeys: []LocalKey{
			{KeyID: "manager-key", Key: []byte("manager-secret")},
		},
		Now: now,
	})
	if !errors.Is(err, ErrAmbiguousKeySource) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrAmbiguousKeySource)
	}
}

func TestVerifyIdentityGrantJWTRejectsMissingConfirmationKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingConfirmationKey) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsThumbprintOnlyConfirmation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"jkt": "agent-key-thumbprint"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingConfirmationKey) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingConfirmationKey)
	}
}

func TestVerifyIdentityGrantJWTRejectsWrongTokenType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeSessionBinding,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrInvalidTokenType) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrInvalidTokenType)
	}
}

func TestVerifyIdentityGrantJWTRejectsMissingJWTID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingJWTID) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrMissingJWTID)
	}
}

func TestVerifySessionBindingJWTFeedsIdentityPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      testServicePayments,
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	grant, err := VerifyIdentityGrantJWT(grantToken, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v", err)
	}

	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                       "agent-a",
		"aud":                       "client-a",
		"jti":                       "binding-1",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Minute).Unix(),
		"agtp_type":                 TokenTypeSessionBinding,
		"agtp_version":              ProfileVersion,
		"grant_hash":                grant.GrantHash,
		"leaf_public_key_sha256":    "sha256:leaf",
		"tls_exporter_sha256":       "sha256:exporter",
		"request_context_sha256":    "sha256:context",
		"attestation_binder_sha256": "sha256:binder",
		"nonce":                     "nonce-1",
	})
	statement, err := VerifySessionBindingJWT(bindingToken, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifySessionBindingJWT() error = %v", err)
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v", err)
	}

	policy := identitypolicy.Policy{
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service:    testServicePayments,
			Deployment: "prod",
			Agent:      "agent-a",
			TaskID:     "task-1",
			Scopes:     []string{"orders:read"},
		},
	}
	expectedBinding := identitypolicy.Binding{
		LeafPublicKeySHA256:     "sha256:leaf",
		TLSExporterSHA256:       "sha256:exporter",
		RequestContextSHA256:    "sha256:context",
		AttestationBinderSHA256: "sha256:binder",
		Nonce:                   "nonce-1",
	}
	if err := identitypolicy.ValidateAssertion(policy, assertion, expectedBinding, now); err != nil {
		t.Fatalf("ValidateAssertion() error = %v", err)
	}
}

func TestVerifySessionIdentityJWTAcceptsManagerGrantAndLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      testServicePayments,
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	grantHash := IdentityGrantHash(grantToken)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             grantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	result, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if err != nil {
		t.Fatalf("VerifySessionIdentityJWT() error = %v", err)
	}
	if result.Grant.GrantHash != grantHash {
		t.Fatalf("result grant hash = %q, want %q", result.Grant.GrantHash, grantHash)
	}
	if result.Assertion.Values.Service != testServicePayments {
		t.Fatalf("result service = %q, want payments", result.Assertion.Values.Service)
	}
}

func TestVerifySessionIdentityJWTAcceptsStrictSemanticAuthorization(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["intent_ref"] = testIntentOrdersSettle
	grantClaims["capability_ref"] = testCapabilitySettle
	grantClaims["ontology_id"] = testOntologyOrders
	grantClaims["scope"] = "orders:settle"
	grantClaims["resource"] = testResourceOrdersBatch
	grantClaims["authorization_details"] = []string{"purpose:monthly-settlement"}
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	opts := testSessionIdentityOptions(now)
	opts.Policy.SetMode = identitypolicy.SetModeExact
	opts.Policy.Expected.IntentRef = testIntentOrdersSettle
	opts.Policy.Expected.CapabilityRef = testCapabilitySettle
	opts.Policy.Expected.OntologyID = testOntologyOrders
	opts.Policy.Expected.Scopes = []string{"orders:settle"}
	opts.Policy.Expected.Resources = []string{testResourceOrdersBatch}
	opts.Policy.Expected.AuthorizationDetails = []string{"purpose:monthly-settlement"}

	result, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if err != nil {
		t.Fatalf("VerifySessionIdentityJWT() error = %v", err)
	}
	if result.Assertion.Values.CapabilityRef != testCapabilitySettle {
		t.Fatalf("assertion capability ref = %q, want strict capability ref", result.Assertion.Values.CapabilityRef)
	}
}

func TestVerifySessionIdentityJWTRejectsNaturalLanguageSemanticReference(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["intent_ref"] = "セリフ配布"
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, identitypolicy.ErrUnsafeValue) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrUnsafeValue)
	}
}

func TestVerifySessionIdentityJWTRejectsStrictSemanticAuthorizationDrift(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["intent_ref"] = testIntentOrdersSettle
	grantClaims["capability_ref"] = "urn:agtp:capability:orders:admin"
	grantClaims["ontology_id"] = testOntologyOrders
	grantClaims["scope"] = "orders:settle"
	grantClaims["resource"] = testResourceOrdersBatch
	grantClaims["authorization_details"] = []string{"purpose:monthly-settlement"}
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	opts := testSessionIdentityOptions(now)
	opts.Policy.SetMode = identitypolicy.SetModeExact
	opts.Policy.Expected.IntentRef = testIntentOrdersSettle
	opts.Policy.Expected.CapabilityRef = testCapabilitySettle
	opts.Policy.Expected.OntologyID = testOntologyOrders
	opts.Policy.Expected.Scopes = []string{"orders:settle"}
	opts.Policy.Expected.Resources = []string{testResourceOrdersBatch}
	opts.Policy.Expected.AuthorizationDetails = []string{"purpose:monthly-settlement"}

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
	var validationErrs identitypolicy.ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("VerifySessionIdentityJWT() error = %T, want identitypolicy.ValidationErrors", err)
	}
	if !validationErrs.Has(identitypolicy.LayerL6, identitypolicy.FieldCapabilityRef, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() errors do not include L6 capability_ref mismatch")
	}
}

func TestVerifySessionIdentityJWTRejectsExtraSemanticAuthorizationScope(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["intent_ref"] = testIntentOrdersSettle
	grantClaims["capability_ref"] = testCapabilitySettle
	grantClaims["ontology_id"] = testOntologyOrders
	grantClaims["scope"] = "orders:settle orders:admin"
	grantClaims["resource"] = testResourceOrdersBatch
	grantClaims["authorization_details"] = []string{"purpose:monthly-settlement"}
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	opts := testSessionIdentityOptions(now)
	opts.Policy.SetMode = identitypolicy.SetModeExact
	opts.Policy.Expected.IntentRef = testIntentOrdersSettle
	opts.Policy.Expected.CapabilityRef = testCapabilitySettle
	opts.Policy.Expected.OntologyID = testOntologyOrders
	opts.Policy.Expected.Scopes = []string{"orders:settle"}
	opts.Policy.Expected.Resources = []string{testResourceOrdersBatch}
	opts.Policy.Expected.AuthorizationDetails = []string{"purpose:monthly-settlement"}

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
	var validationErrs identitypolicy.ValidationErrors
	if !errors.As(err, &validationErrs) {
		t.Fatalf("VerifySessionIdentityJWT() error = %T, want identitypolicy.ValidationErrors", err)
	}
	if !validationErrs.Has(identitypolicy.LayerL6, identitypolicy.FieldScopes, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() errors do not include L6 scopes mismatch")
	}
}

func TestVerifySessionIdentityJWTRejectsPeerSignedGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      testServicePayments,
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, ErrMissingKeyID) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, ErrMissingKeyID)
	}
}

func TestVerifySessionIdentityJWTRejectsLocalPolicyMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      "wrong-service",
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             IdentityGrantHash(grantToken),
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestVerifySessionIdentityJWTRejectsWrongGrantHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
		"service":      testServicePayments,
		"deployment":   "prod",
		"task_id":      "task-1",
		"scope":        "orders:read",
	})
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             "sha256:other-grant",
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
	}
}

func TestVerifySessionIdentityJWTRejectsWrongGrantIssuerOrAudience(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name string
		iss  string
		aud  string
	}{
		{name: "wrong issuer", iss: "peer", aud: "client-a"},
		{name: "wrong audience", iss: "manager", aud: "other-client"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
				"iss":          tt.iss,
				"sub":          "agent-a",
				"aud":          tt.aud,
				"jti":          "grant-1",
				"iat":          now.Unix(),
				"exp":          now.Add(time.Minute).Unix(),
				"agtp_type":    TokenTypeIdentityGrant,
				"agtp_version": ProfileVersion,
				"cnf":          map[string]any{"kid": "agent-key-1"},
				"service":      testServicePayments,
				"deployment":   "prod",
				"task_id":      "task-1",
				"scope":        "orders:read",
			})
			bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
				"iss":                    "agent-a",
				"aud":                    "client-a",
				"jti":                    "binding-1",
				"iat":                    now.Unix(),
				"exp":                    now.Add(time.Minute).Unix(),
				"agtp_type":              TokenTypeSessionBinding,
				"agtp_version":           ProfileVersion,
				"grant_hash":             IdentityGrantHash(grantToken),
				"leaf_public_key_sha256": "sha256:leaf",
				"tls_exporter_sha256":    "sha256:exporter",
				"request_context_sha256": "sha256:context",
				"nonce":                  "nonce-1",
			})

			if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now)); err == nil {
				t.Fatal("VerifySessionIdentityJWT() error = nil, want issuer or audience failure")
			}
		})
	}
}

func TestVerifySessionIdentityJWTRejectsMissingPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	_, err := VerifySessionIdentityJWT("grant", "binding", SessionIdentityJWTOptions{Now: now})
	if !errors.Is(err, ErrMissingIdentityPolicy) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, ErrMissingIdentityPolicy)
	}
}

func TestVerifySessionIdentityJWTRejectsExpiredGrant(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantClaims := testDefaultGrantClaims(now)
	grantClaims["exp"] = now.Add(-time.Minute).Unix()
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), grantClaims)
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestVerifySessionIdentityJWTRejectsExpiredSessionBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingClaims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
	bindingClaims["exp"] = now.Add(-time.Minute).Unix()
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), bindingClaims)

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, jwt.ErrTokenExpired)
	}
}

func TestVerifySessionIdentityJWTRejectsUnauthorizedSessionBindingSigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "other-agent-key", []byte("other-agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.SessionBinding.KeyFunc = testKeyFunc(map[string][]byte{"other-agent-key": []byte("other-agent-secret")})

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, identitypolicy.ErrUnauthorizedBindingKey)
	}
}

func TestVerifySessionIdentityJWTEnvelopeAcceptsManagerGrantAndLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	envelopeToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultEnvelopeClaims(now, grantToken, IdentityGrantHash(grantToken)))

	result, err := VerifySessionIdentityJWTEnvelope(envelopeToken, testSessionIdentityOptions(now))
	if err != nil {
		t.Fatalf("VerifySessionIdentityJWTEnvelope() error = %v", err)
	}
	if result.Grant.GrantHash != IdentityGrantHash(grantToken) {
		t.Fatalf("result grant hash = %q, want inner grant hash", result.Grant.GrantHash)
	}
	if result.Assertion.Values.Service != testServicePayments {
		t.Fatalf("result service = %q, want payments from inner Manager grant", result.Assertion.Values.Service)
	}
}

func TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	tests := []struct {
		name      string
		envelope  func() string
		want      error
		wantError bool
	}{
		{
			name: "inner grant substitution",
			envelope: func() string {
				substitutedGrantClaims := testDefaultGrantClaims(now)
				substitutedGrantClaims["jti"] = "grant-2"
				substitutedGrant := signTestJWT(t, "manager-key", []byte("manager-secret"), substitutedGrantClaims)
				return signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultEnvelopeClaims(now, substitutedGrant, IdentityGrantHash(grantToken)))
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "outer grant_hash mismatch",
			envelope: func() string {
				return signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultEnvelopeClaims(now, grantToken, "sha256:other-grant"))
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "skipped inner signature verification",
			envelope: func() string {
				forgedGrant := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultGrantClaims(now))
				return signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultEnvelopeClaims(now, forgedGrant, IdentityGrantHash(forgedGrant)))
			},
			want: ErrMissingKeyID,
		},
		{
			name: "skipped outer signature verification",
			envelope: func() string {
				envelope := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultEnvelopeClaims(now, grantToken, IdentityGrantHash(grantToken)))
				return corruptTestJWTSignature(t, envelope)
			},
			wantError: true,
		},
		{
			name: "Agent-signed semantic claims ignored",
			envelope: func() string {
				analyticsGrantClaims := testDefaultGrantClaims(now)
				analyticsGrantClaims["service"] = testServiceAnalytics
				analyticsGrant := signTestJWT(t, "manager-key", []byte("manager-secret"), analyticsGrantClaims)
				envelopeClaims := testDefaultEnvelopeClaims(now, analyticsGrant, IdentityGrantHash(analyticsGrant))
				envelopeClaims["service"] = testServicePayments
				envelopeClaims["scope"] = "orders:read"
				return signTestJWT(t, "agent-key-1", []byte("agent-secret"), envelopeClaims)
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "missing inner grant",
			envelope: func() string {
				envelopeClaims := testDefaultEnvelopeClaims(now, grantToken, IdentityGrantHash(grantToken))
				delete(envelopeClaims, "identity_grant_jwt")
				return signTestJWT(t, "agent-key-1", []byte("agent-secret"), envelopeClaims)
			},
			want: ErrMissingIdentityGrant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifySessionIdentityJWTEnvelope(tt.envelope(), testSessionIdentityOptions(now))
			if tt.wantError {
				if err == nil {
					t.Fatal("VerifySessionIdentityJWTEnvelope() error = nil, want failure")
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifySessionIdentityJWTEnvelope() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifySessionIdentityJWTRejectsReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = newAGTPReplayCache()

	if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() first error = %v", err)
	}
	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("VerifySessionIdentityJWT() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

func TestVerifySessionIdentityJWTRedTeamRejectsWalletMisuse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name          string
		grantClaims   func() jwt.MapClaims
		bindingClaims func(grantToken string) jwt.MapClaims
		want          error
	}{
		{
			name: "wallet metadata cannot override Manager grant",
			grantClaims: func() jwt.MapClaims {
				claims := testDefaultGrantClaims(now)
				claims["service"] = testServiceAnalytics
				return claims
			},
			bindingClaims: func(grantToken string) jwt.MapClaims {
				claims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
				claims["service"] = testServicePayments
				claims["wallet_display_name"] = "Payments Agent"
				claims["wallet_policy_hint"] = "service:payments"
				return claims
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "wallet-signed binding for another TLS exporter",
			grantClaims: func() jwt.MapClaims {
				return testDefaultGrantClaims(now)
			},
			bindingClaims: func(grantToken string) jwt.MapClaims {
				claims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
				claims["tls_exporter_sha256"] = "sha256:other-exporter"
				return claims
			},
			want: identitypolicy.ErrMismatch,
		},
		{
			name: "wallet-signed binding for another request context",
			grantClaims: func() jwt.MapClaims {
				return testDefaultGrantClaims(now)
			},
			bindingClaims: func(grantToken string) jwt.MapClaims {
				claims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
				claims["request_context_sha256"] = "sha256:other-context"
				return claims
			},
			want: identitypolicy.ErrMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), tt.grantClaims())
			bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), tt.bindingClaims(grantToken))

			_, err := VerifySessionIdentityJWT(grantToken, bindingToken, testSessionIdentityOptions(now))
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("wallet-signed binding replay", func(t *testing.T) {
		grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
		bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
		opts := testSessionIdentityOptions(now)

		if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
			t.Fatalf("VerifySessionIdentityJWT() first error = %v", err)
		}
		_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
		if !errors.Is(err, identitypolicy.ErrReplayDetected) {
			t.Fatalf("VerifySessionIdentityJWT() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
		}
	})
}

func TestVerifySessionIdentityJWTLiveRedTeamHTTP2ConnectionReuse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingTaskA := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "task-a", "sha256:exporter-shared"))
	bindingTaskB := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "task-b", "sha256:exporter-shared"))
	replay := newAGTPReplayCache()
	var connections atomic.Int64

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, fmt.Sprintf("expected HTTP/2, got %s", r.Proto), http.StatusHTTPVersionNotSupported)
			return
		}
		task := strings.TrimPrefix(r.URL.Path, "/task/")
		opts := liveRedTeamSessionIdentityOptions(now, replay, "sha256:exporter-shared", "sha256:context-"+task, "nonce-"+task)
		_, err := VerifySessionIdentityJWT(r.Header.Get("X-Identity-Grant-JWT"), r.Header.Get("X-Session-Binding-JWT"), opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	liveRedTeamDoRequest(t, client, server.URL+"/task/task-a", grantToken, bindingTaskA, http.StatusNoContent)
	liveRedTeamDoRequest(t, client, server.URL+"/task/task-b", grantToken, bindingTaskA, http.StatusForbidden)
	liveRedTeamDoRequest(t, client, server.URL+"/task/task-b", grantToken, bindingTaskB, http.StatusNoContent)

	if got := connections.Load(); got != 1 {
		t.Fatalf("HTTP/2 harness opened %d TCP connections, want 1 reused connection", got)
	}
}

func TestVerifySessionIdentityJWTLiveRedTeamGRPCConnectionReuse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingTaskA := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "task-a", "sha256:exporter-shared"))
	bindingTaskB := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "task-b", "sha256:exporter-shared"))
	replay := newAGTPReplayCache()

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	healthpb.RegisterHealthServer(server, &liveRedTeamGRPCHealthServer{
		now:         now,
		replay:      replay,
		tlsExporter: "sha256:exporter-shared",
	})
	go func() {
		_ = server.Serve(lis)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})

	var dials atomic.Int64
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			dials.Add(1)
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer conn.Close()
	client := healthpb.NewHealthClient(conn)

	liveRedTeamGRPCCheck(t, client, "task-a", grantToken, bindingTaskA, codes.OK)
	liveRedTeamGRPCCheck(t, client, "task-b", grantToken, bindingTaskA, codes.PermissionDenied)
	liveRedTeamGRPCCheck(t, client, "task-b", grantToken, bindingTaskB, codes.OK)

	if got := dials.Load(); got != 1 {
		t.Fatalf("gRPC harness opened %d client connections, want 1 reused ClientConn", got)
	}
}

func TestVerifySessionIdentityJWTLiveRedTeamRejectsNetworkRelayAcrossEndpoints(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingEndpointA := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "endpoint-a", "sha256:exporter-endpoint-a"))
	bindingEndpointB := signTestJWT(t, "agent-key-1", []byte("agent-secret"), liveRedTeamBindingClaims(now, grantToken, "endpoint-b", "sha256:exporter-endpoint-b"))

	endpointA := liveRedTeamServer(t, now, "endpoint-a", "sha256:exporter-endpoint-a")
	defer endpointA.Close()
	endpointB := liveRedTeamServer(t, now, "endpoint-b", "sha256:exporter-endpoint-b")
	defer endpointB.Close()

	liveRedTeamDoRequest(t, endpointA.Client(), endpointA.URL, grantToken, bindingEndpointA, http.StatusNoContent)
	liveRedTeamDoRequest(t, endpointB.Client(), endpointB.URL, grantToken, bindingEndpointA, http.StatusForbidden)
	liveRedTeamDoRequest(t, endpointB.Client(), endpointB.URL, grantToken, bindingEndpointB, http.StatusNoContent)
}

func TestVerifySessionIdentityJWTLiveRedTeamRejectsTLSResumptionReplayAndPreBinding(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))

	addr := liveRedTeamTLSServer(t, 4)
	context := []byte("agtp-lrtt14-resumption-context")
	contextHash := liveRedTeamSHA256Hex(context)
	clientConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}

	initial := liveRedTeamTLSConnectionMaterial(t, addr, clientConfig, context)
	if initial.didResume {
		t.Fatal("first TLS connection unexpectedly resumed")
	}
	initialNonce := "nonce-lrtt14-initial"
	initialBinding := signTestJWT(t, "agent-key-1", []byte("agent-secret"),
		liveRedTeamBindingClaimsWithSession(now, grantToken, "lrtt14-initial", initial.exporterHash, contextHash, initialNonce))
	initialOpts := liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), initial.exporterHash, contextHash, initialNonce)
	if _, err := VerifySessionIdentityJWT(grantToken, initialBinding, initialOpts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() initial session error = %v", err)
	}

	var resumed liveRedTeamTLSMaterial
	for attempt := 0; attempt < 3; attempt++ {
		resumed = liveRedTeamTLSConnectionMaterial(t, addr, clientConfig, context)
		if resumed.didResume {
			break
		}
	}
	if !resumed.didResume {
		t.Skip("local Go TLS stack did not resume the session; cannot exercise LRTT14 resumption path")
	}
	if resumed.exporterHash == initial.exporterHash {
		t.Fatalf("resumed TLS exporter hash = initial hash %q, want a fresh connection binding", resumed.exporterHash)
	}

	resumedOptsForOldBinding := liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), resumed.exporterHash, contextHash, initialNonce)
	_, err := VerifySessionIdentityJWT(grantToken, initialBinding, resumedOptsForOldBinding)
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() resumed old binding error = %v, want %v", err, identitypolicy.ErrMismatch)
	}

	resumedNonce := "nonce-lrtt14-resumed"
	resumedBinding := signTestJWT(t, "agent-key-1", []byte("agent-secret"),
		liveRedTeamBindingClaimsWithSession(now, grantToken, "lrtt14-resumed", resumed.exporterHash, contextHash, resumedNonce))
	resumedOpts := liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), resumed.exporterHash, contextHash, resumedNonce)
	if _, err := VerifySessionIdentityJWT(grantToken, resumedBinding, resumedOpts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() resumed fresh binding error = %v", err)
	}

	preBindingClaims := liveRedTeamBindingClaimsWithSession(now, grantToken, "lrtt14-pre-binding", resumed.exporterHash, contextHash, "nonce-lrtt14-pre-binding")
	delete(preBindingClaims, "tls_exporter_sha256")
	preBindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), preBindingClaims)
	_, err = VerifySessionIdentityJWT(grantToken, preBindingToken,
		liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), resumed.exporterHash, contextHash, "nonce-lrtt14-pre-binding"))
	if !errors.Is(err, ErrMissingBindingField) {
		t.Fatalf("VerifySessionIdentityJWT() pre-binding error = %v, want %v", err, ErrMissingBindingField)
	}
}

func TestVerifySessionIdentityJWTLiveRedTeamRejectsQUICEarlyDataAuthentication(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	clientConfig, serverConfig := liveRedTeamQUICTLSConfigs(t)

	initialClient := liveRedTeamQUICClient(t, clientConfig)
	initialClient.conn.SetTransportParameters(nil)
	initialServer := liveRedTeamQUICServer(t, serverConfig)
	initialServer.conn.SetTransportParameters(nil)
	initialServer.ticketOpts.EarlyData = true
	if err := liveRedTeamRunQUICConnection(context.Background(), initialClient, initialServer); err != nil {
		t.Fatalf("initial QUIC handshake error = %v", err)
	}
	if initialClient.conn.ConnectionState().DidResume {
		t.Fatal("first QUIC connection unexpectedly resumed")
	}

	resumedClient := liveRedTeamQUICClient(t, clientConfig)
	resumedClient.conn.SetTransportParameters(nil)
	resumedServer := liveRedTeamQUICServer(t, serverConfig)
	resumedServer.conn.SetTransportParameters(nil)
	if err := liveRedTeamRunQUICConnection(context.Background(), resumedClient, resumedServer); err != nil {
		t.Fatalf("resumed QUIC handshake error = %v", err)
	}
	if !resumedClient.conn.ConnectionState().DidResume {
		t.Fatal("second QUIC connection did not resume")
	}
	if resumedClient.writeSecret[tls.QUICEncryptionLevelEarly].secret == nil {
		t.Fatal("resumed QUIC client did not receive early-data write secret")
	}
	if resumedServer.readSecret[tls.QUICEncryptionLevelEarly].secret == nil {
		t.Fatal("resumed QUIC server did not receive early-data read secret")
	}

	contextBytes := []byte("agtp-lrtt18-quic-early-context")
	contextHash := liveRedTeamSHA256Hex(contextBytes)
	earlyClaims := liveRedTeamBindingClaimsWithSession(now, grantToken, "lrtt18-early", "", contextHash, "nonce-lrtt18-early")
	delete(earlyClaims, "tls_exporter_sha256")
	earlyToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), earlyClaims)
	_, err := VerifySessionIdentityJWT(grantToken, earlyToken,
		liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), "not-available-before-finished-handshake", contextHash, "nonce-lrtt18-early"))
	if !errors.Is(err, ErrMissingBindingField) {
		t.Fatalf("VerifySessionIdentityJWT() QUIC early-data binding error = %v, want %v", err, ErrMissingBindingField)
	}

	state := resumedClient.conn.ConnectionState()
	exported, err := state.ExportKeyingMaterial(attestation.ExporterLabelAttestation, contextBytes, 32)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial() error = %v", err)
	}
	exporterHash := liveRedTeamSHA256Hex(exported)
	finishedToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"),
		liveRedTeamBindingClaimsWithSession(now, grantToken, "lrtt18-finished", exporterHash, contextHash, "nonce-lrtt18-finished"))
	if _, err := VerifySessionIdentityJWT(grantToken, finishedToken,
		liveRedTeamSessionIdentityOptions(now, newAGTPReplayCache(), exporterHash, contextHash, "nonce-lrtt18-finished")); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() QUIC finished-handshake binding error = %v", err)
	}
}

func TestVerifySessionIdentityJWTRedTeamRejectsMalformedCorpus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	validGrant := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	validBinding := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(validGrant)))

	duplicateClaimGrant := signRawTestJWT(t,
		`{"alg":"HS256","typ":"JWT","kid":"manager-key"}`,
		`{"iss":"manager","sub":"agent-a","aud":"client-a","jti":"grant-dup","iat":1700000000,"exp":1700000060,"agtp_type":"agtp.identity-grant","agtp_type":"agtp.session-binding","agtp_version":"1","cnf":{"kid":"agent-key-1"},"service":"payments"}`,
		[]byte("manager-secret"),
	)
	duplicateHeaderGrant := signRawTestJWT(t,
		`{"alg":"HS256","typ":"JWT","kid":"manager-key","kid":"other-manager-key"}`,
		`{"iss":"manager","sub":"agent-a","aud":"client-a","jti":"grant-dup-header","iat":1700000000,"exp":1700000060,"agtp_type":"agtp.identity-grant","agtp_version":"1","cnf":{"kid":"agent-key-1"},"service":"payments"}`,
		[]byte("manager-secret"),
	)
	controlClaimGrantClaims := testDefaultGrantClaims(now)
	controlClaimGrantClaims["service"] = "payments\nadmin"
	controlClaimGrant := signTestJWT(t, "manager-key", []byte("manager-secret"), controlClaimGrantClaims)
	controlClaimBinding := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(controlClaimGrant)))

	tests := []struct {
		name    string
		grant   string
		binding string
		want    error
	}{
		{name: "malformed grant compact serialization", grant: "not-a-jwt", binding: validBinding},
		{name: "malformed binding compact serialization", grant: validGrant, binding: "not-a-jwt"},
		{name: "duplicate payload member", grant: duplicateClaimGrant, binding: validBinding, want: ErrDuplicateJWTMember},
		{name: "duplicate protected header member", grant: duplicateHeaderGrant, binding: validBinding, want: ErrDuplicateJWTMember},
		{name: "control character in semantic claim", grant: controlClaimGrant, binding: controlClaimBinding, want: identitypolicy.ErrUnsafeValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifySessionIdentityJWT(tt.grant, tt.binding, testSessionIdentityOptions(now))
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, tt.want)
			}
			if tt.want == nil && err == nil {
				t.Fatal("VerifySessionIdentityJWT() error = nil, want malformed token rejection")
			}
		})
	}
}

func TestVerifySessionIdentityJWTInvariantMatrix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	newGrant := func() string {
		return signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	}
	newBinding := func(grantToken string) jwt.MapClaims {
		claims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
		claims["attestation_binder_sha256"] = "sha256:attestation"
		return claims
	}
	newOptions := func() SessionIdentityJWTOptions {
		opts := testSessionIdentityOptions(now)
		opts.ExpectedBinding.AttestationBinderSHA256 = "sha256:attestation"
		return opts
	}

	t.Run("baseline accepts", func(t *testing.T) {
		grantToken := newGrant()
		bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), newBinding(grantToken))
		if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, newOptions()); err != nil {
			t.Fatalf("VerifySessionIdentityJWT() error = %v", err)
		}
	})

	tests := []struct {
		name    string
		mutate  func(grantToken string, bindingClaims jwt.MapClaims, opts *SessionIdentityJWTOptions) string
		wantErr error
	}{
		{
			name: "grant hash mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				otherClaims := testDefaultGrantClaims(now)
				otherClaims["jti"] = "grant-other"
				otherGrant := signTestJWT(t, "manager-key", []byte("manager-secret"), otherClaims)
				bindingClaims["grant_hash"] = IdentityGrantHash(otherGrant)
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "request context mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				bindingClaims["request_context_sha256"] = "sha256:other-context"
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "tls exporter mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				bindingClaims["tls_exporter_sha256"] = "sha256:other-exporter"
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "attestation binder mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				bindingClaims["attestation_binder_sha256"] = "sha256:other-attestation"
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "audience mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				bindingClaims["aud"] = "other-client"
				return grantToken
			},
		},
		{
			name: "role-separated context mismatch",
			mutate: func(grantToken string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				bindingClaims["request_context_sha256"] = "sha256:initiator-context"
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "task policy mismatch",
			mutate: func(_ string, bindingClaims jwt.MapClaims, _ *SessionIdentityJWTOptions) string {
				claims := testDefaultGrantClaims(now)
				claims["task_id"] = "task-2"
				grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), claims)
				bindingClaims["grant_hash"] = IdentityGrantHash(grantToken)
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
		{
			name: "local policy mismatch",
			mutate: func(grantToken string, _ jwt.MapClaims, opts *SessionIdentityJWTOptions) string {
				opts.Policy.Expected.Service = testServiceAnalytics
				return grantToken
			},
			wantErr: identitypolicy.ErrMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grantToken := newGrant()
			bindingClaims := newBinding(grantToken)
			opts := newOptions()
			grantToken = tt.mutate(grantToken, bindingClaims, &opts)
			bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), bindingClaims)

			_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && err == nil {
				t.Fatal("VerifySessionIdentityJWT() error = nil, want invariant rejection")
			}
		})
	}

	t.Run("replay mismatch", func(t *testing.T) {
		grantToken := newGrant()
		bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), newBinding(grantToken))
		opts := newOptions()
		if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
			t.Fatalf("VerifySessionIdentityJWT() first error = %v", err)
		}
		_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
		if !errors.Is(err, identitypolicy.ErrReplayDetected) {
			t.Fatalf("VerifySessionIdentityJWT() replay error = %v, want %v", err, identitypolicy.ErrReplayDetected)
		}
	})
}

func TestVerifySessionIdentityJWTRejectsMissingReplayCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = nil

	_, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts)
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("VerifySessionIdentityJWT() error = %v, want %v", err, ErrMissingReplayCache)
	}
}

func TestVerifySessionIdentityJWTEnvelopeRejectsMissingReplayCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	envelopeToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"),
		testDefaultEnvelopeClaims(now, grantToken, IdentityGrantHash(grantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = nil

	_, err := VerifySessionIdentityJWTEnvelope(envelopeToken, opts)
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("VerifySessionIdentityJWTEnvelope() error = %v, want %v", err, ErrMissingReplayCache)
	}
}

func TestVerifySessionIdentityJWTDoesNotConsumeReplayOnPolicyMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	replay := newAGTPReplayCache()
	wrongGrantClaims := testDefaultGrantClaims(now)
	wrongGrantClaims["service"] = testServiceAnalytics
	wrongGrantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), wrongGrantClaims)
	wrongBindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(wrongGrantToken)))
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = replay

	err := func() error {
		_, err := VerifySessionIdentityJWT(wrongGrantToken, wrongBindingToken, opts)
		return err
	}()
	if !errors.Is(err, identitypolicy.ErrMismatch) {
		t.Fatalf("VerifySessionIdentityJWT() mismatch error = %v, want %v", err, identitypolicy.ErrMismatch)
	}

	grantToken := signTestJWT(t, "manager-key", []byte("manager-secret"), testDefaultGrantClaims(now))
	bindingToken := signTestJWT(t, "agent-key-1", []byte("agent-secret"), testDefaultBindingClaims(now, IdentityGrantHash(grantToken)))
	if _, err := VerifySessionIdentityJWT(grantToken, bindingToken, opts); err != nil {
		t.Fatalf("VerifySessionIdentityJWT() after mismatch error = %v", err)
	}
}

func TestVerifySessionBindingJWTRejectsWrongSigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := identitypolicy.VerifiedGrant{
		Issuer:          "manager",
		Audience:        "client-a",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-key-1",
		Values:          identitypolicy.Values{Agent: "agent-a"},
		IssuedAt:        now,
		ExpiresAt:       now.Add(time.Minute),
	}
	bindingToken := signTestJWT(t, "other-agent-key", []byte("other-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             grant.GrantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})
	statement, err := VerifySessionBindingJWT(bindingToken, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"other-agent-key": []byte("other-secret")}),
		Now:              now,
	})
	if err != nil {
		t.Fatalf("VerifySessionBindingJWT() error = %v", err)
	}

	_, err = identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
		t.Fatalf("NewAssertionFromSessionBinding() error = %v, want %v", err, identitypolicy.ErrUnauthorizedBindingKey)
	}
}

func TestVerifySessionBindingJWTRejectsWrongTokenType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                       "agent-a",
		"aud":                       "client-a",
		"jti":                       "binding-1",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Minute).Unix(),
		"agtp_type":                 TokenTypeIdentityGrant,
		"agtp_version":              ProfileVersion,
		"grant_hash":                "sha256:grant",
		"leaf_public_key_sha256":    "sha256:leaf",
		"tls_exporter_sha256":       "sha256:exporter",
		"request_context_sha256":    "sha256:context",
		"attestation_binder_sha256": "sha256:binder",
		"nonce":                     "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrInvalidTokenType) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrInvalidTokenType)
	}
}

func TestVerifySessionBindingJWTRejectsMissingGrantHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingGrantHash) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrMissingGrantHash)
	}
}

func TestVerifySessionBindingJWTRejectsMissingBindingField(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "agent-key-1", []byte("agent-secret"), jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		"agtp_type":              TokenTypeSessionBinding,
		"agtp_version":           ProfileVersion,
		"grant_hash":             "sha256:grant",
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"nonce":                  "nonce-1",
	})

	_, err := VerifySessionBindingJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "agent-a",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"HS256"},
		KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrMissingBindingField) {
		t.Fatalf("VerifySessionBindingJWT() error = %v, want %v", err, ErrMissingBindingField)
	}
}

func TestVerifyJWTRejectsUnsafeSigningMethodAllowList(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tokenString := signTestJWT(t, "manager-key", []byte("manager-secret"), jwt.MapClaims{
		"iss":          "manager",
		"sub":          "agent-a",
		"aud":          "client-a",
		"jti":          "grant-1",
		"iat":          now.Unix(),
		"exp":          now.Add(time.Minute).Unix(),
		"agtp_type":    TokenTypeIdentityGrant,
		"agtp_version": ProfileVersion,
		"cnf":          map[string]any{"kid": "agent-key-1"},
	})

	_, err := VerifyIdentityGrantJWT(tokenString, JWTVerifyOptions{
		ExpectedIssuer:   "manager",
		ExpectedAudience: "client-a",
		ValidMethods:     []string{"none"},
		KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		Now:              now,
	})
	if !errors.Is(err, ErrUnsafeSigningMethod) {
		t.Fatalf("VerifyIdentityGrantJWT() error = %v, want %v", err, ErrUnsafeSigningMethod)
	}
}

func signTestJWT(t testing.TB, keyID string, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func signRawTestJWT(t testing.TB, headerJSON, payloadJSON string, secret []byte) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature
}

func liveRedTeamBindingClaims(now time.Time, grantToken, contextID, tlsExporter string) jwt.MapClaims {
	return liveRedTeamBindingClaimsWithSession(now, grantToken, contextID, tlsExporter, "sha256:context-"+contextID, "nonce-"+contextID)
}

func liveRedTeamBindingClaimsWithSession(now time.Time, grantToken, contextID, tlsExporter, requestContext, nonce string) jwt.MapClaims {
	claims := testDefaultBindingClaims(now, IdentityGrantHash(grantToken))
	claims["jti"] = "binding-" + contextID
	claims["tls_exporter_sha256"] = tlsExporter
	claims["request_context_sha256"] = requestContext
	claims["nonce"] = nonce
	return claims
}

func liveRedTeamSessionIdentityOptions(now time.Time, replay identitypolicy.ReplayCache, tlsExporter, requestContext, nonce string) SessionIdentityJWTOptions {
	opts := testSessionIdentityOptions(now)
	opts.ReplayCache = replay
	opts.ExpectedBinding.TLSExporterSHA256 = tlsExporter
	opts.ExpectedBinding.RequestContextSHA256 = requestContext
	opts.ExpectedBinding.Nonce = nonce
	return opts
}

func liveRedTeamServer(t *testing.T, now time.Time, contextID, tlsExporter string) *httptest.Server {
	t.Helper()
	replay := newAGTPReplayCache()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opts := liveRedTeamSessionIdentityOptions(now, replay, tlsExporter, "sha256:context-"+contextID, "nonce-"+contextID)
		_, err := VerifySessionIdentityJWT(r.Header.Get("X-Identity-Grant-JWT"), r.Header.Get("X-Session-Binding-JWT"), opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	return server
}

func liveRedTeamDoRequest(t *testing.T, client *http.Client, url, grantToken, bindingToken string, wantStatus int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("X-Identity-Grant-JWT", grantToken)
	req.Header.Set("X-Session-Binding-JWT", bindingToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do(%s) error = %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("Do(%s) status = %d, want %d", url, resp.StatusCode, wantStatus)
	}
}

type liveRedTeamGRPCHealthServer struct {
	healthpb.UnimplementedHealthServer
	now         time.Time
	replay      identitypolicy.ReplayCache
	tlsExporter string
}

func (s *liveRedTeamGRPCHealthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	task := req.GetService()
	opts := liveRedTeamSessionIdentityOptions(s.now, s.replay, s.tlsExporter, "sha256:context-"+task, "nonce-"+task)
	_, err := VerifySessionIdentityJWT(firstMetadataValue(md, "identity-grant-jwt"), firstMetadataValue(md, "session-binding-jwt"), opts)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func liveRedTeamGRPCCheck(t *testing.T, client healthpb.HealthClient, service, grantToken, bindingToken string, want codes.Code) {
	t.Helper()
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		"identity-grant-jwt", grantToken,
		"session-binding-jwt", bindingToken,
	)
	_, err := client.Check(ctx, &healthpb.HealthCheckRequest{Service: service})
	if got := status.Code(err); got != want {
		t.Fatalf("gRPC Check(%s) code = %v, want %v; err = %v", service, got, want, err)
	}
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

type liveRedTeamTLSMaterial struct {
	exporterHash string
	didResume    bool
}

type liveRedTeamQUICSecret struct {
	suite  uint16
	secret []byte
}

type liveRedTeamQUICConn struct {
	conn              *tls.QUICConn
	readSecret        map[tls.QUICEncryptionLevel]liveRedTeamQUICSecret
	writeSecret       map[tls.QUICEncryptionLevel]liveRedTeamQUICSecret
	ticketOpts        tls.QUICSessionTicketOptions
	onResumeSession   func(*tls.SessionState)
	earlyDataRejected bool
	complete          bool
	started           bool
}

func liveRedTeamQUICClient(t *testing.T, config *tls.QUICConfig) *liveRedTeamQUICConn {
	t.Helper()
	conn := &liveRedTeamQUICConn{conn: tls.QUICClient(config)}
	t.Cleanup(func() {
		_ = conn.conn.Close()
	})
	return conn
}

func liveRedTeamQUICServer(t *testing.T, config *tls.QUICConfig) *liveRedTeamQUICConn {
	t.Helper()
	conn := &liveRedTeamQUICConn{conn: tls.QUICServer(config)}
	t.Cleanup(func() {
		_ = conn.conn.Close()
	})
	return conn
}

func liveRedTeamRunQUICConnection(ctx context.Context, client, server *liveRedTeamQUICConn) error {
	for _, conn := range []*liveRedTeamQUICConn{client, server} {
		if !conn.started {
			if err := conn.conn.Start(ctx); err != nil {
				return err
			}
			conn.started = true
		}
	}

	source, target := client, server
	idleCount := 0
	for {
		event := source.conn.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			idleCount++
			if idleCount == 2 {
				if !client.complete || !server.complete {
					return errors.New("QUIC handshake incomplete")
				}
				return nil
			}
			source, target = target, source
		case tls.QUICSetReadSecret:
			source.setReadSecret(event.Level, event.Suite, event.Data)
		case tls.QUICSetWriteSecret:
			source.setWriteSecret(event.Level, event.Suite, event.Data)
		case tls.QUICWriteData:
			if err := target.conn.HandleData(event.Level, event.Data); err != nil {
				return err
			}
		case tls.QUICTransportParameters:
		case tls.QUICTransportParametersRequired:
			return errors.New("QUIC transport parameters required")
		case tls.QUICHandshakeDone:
			source.complete = true
			if source == server {
				if err := server.conn.SendSessionTicket(server.ticketOpts); err != nil {
					return err
				}
			}
		case tls.QUICStoreSession:
			if source != client {
				return errors.New("unexpected QUICStoreSession event on server")
			}
			if err := source.conn.StoreSession(event.SessionState); err != nil {
				return err
			}
		case tls.QUICResumeSession:
			if source.onResumeSession != nil {
				source.onResumeSession(event.SessionState)
			}
		case tls.QUICRejectedEarlyData:
			source.earlyDataRejected = true
		case tls.QUICErrorEvent:
			if event.Err == nil {
				return errors.New("QUIC error event without error")
			}
			return event.Err
		}
		if event.Kind != tls.QUICNoEvent {
			idleCount = 0
		}
	}
}

func (conn *liveRedTeamQUICConn) setReadSecret(level tls.QUICEncryptionLevel, suite uint16, secret []byte) {
	if conn.readSecret == nil {
		conn.readSecret = map[tls.QUICEncryptionLevel]liveRedTeamQUICSecret{}
	}
	conn.readSecret[level] = liveRedTeamQUICSecret{suite: suite, secret: secret}
}

func (conn *liveRedTeamQUICConn) setWriteSecret(level tls.QUICEncryptionLevel, suite uint16, secret []byte) {
	if conn.writeSecret == nil {
		conn.writeSecret = map[tls.QUICEncryptionLevel]liveRedTeamQUICSecret{}
	}
	conn.writeSecret[level] = liveRedTeamQUICSecret{suite: suite, secret: secret}
}

func liveRedTeamQUICTLSConfigs(t *testing.T) (*tls.QUICConfig, *tls.QUICConfig) {
	t.Helper()
	cert := liveRedTeamSelfSignedTLSCertificate(t)
	clientConfig := &tls.QUICConfig{
		TLSConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(1),
			NextProtos:         []string{"h3"},
		},
	}
	serverConfig := &tls.QUICConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		},
	}
	return clientConfig, serverConfig
}

func liveRedTeamTLSServer(t *testing.T, maxConnections int) string {
	t.Helper()

	cert := liveRedTeamSelfSignedTLSCertificate(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
	})

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	go func() {
		for i := 0; i < maxConnections; i++ {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			conn := tls.Server(raw, config)
			if err := conn.Handshake(); err == nil {
				_, _ = conn.Write([]byte{0})
			}
			_ = conn.Close()
		}
	}()

	return ln.Addr().String()
}

func liveRedTeamTLSConnectionMaterial(t *testing.T, addr string, config *tls.Config, context []byte) liveRedTeamTLSMaterial {
	t.Helper()

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("tls.Dial() error = %v", err)
	}
	defer conn.Close()

	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	state := conn.ConnectionState()
	exported, err := state.ExportKeyingMaterial(attestation.ExporterLabelAttestation, context, 32)
	if err != nil {
		t.Fatalf("ExportKeyingMaterial() error = %v", err)
	}
	return liveRedTeamTLSMaterial{
		exporterHash: liveRedTeamSHA256Hex(exported),
		didResume:    state.DidResume,
	}
}

func liveRedTeamSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func liveRedTeamSelfSignedTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func testKeyFunc(keys map[string][]byte) KeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, ErrMissingKeyID
		}
		return key, nil
	}
}

func testDefaultGrantClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":               "manager",
		"sub":               "agent-a",
		"aud":               "client-a",
		"jti":               "grant-1",
		"iat":               now.Unix(),
		"exp":               now.Add(time.Minute).Unix(),
		ClaimTokenType:      TokenTypeIdentityGrant,
		ClaimProfileVersion: ProfileVersion,
		"cnf":               map[string]any{"kid": "agent-key-1"},
		"service":           testServicePayments,
		"deployment":        "prod",
		"task_id":           "task-1",
		"scope":             "orders:read",
	}
}

func testDefaultBindingClaims(now time.Time, grantHash string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                    "agent-a",
		"aud":                    "client-a",
		"jti":                    "binding-1",
		"iat":                    now.Unix(),
		"exp":                    now.Add(time.Minute).Unix(),
		ClaimTokenType:           TokenTypeSessionBinding,
		ClaimProfileVersion:      ProfileVersion,
		"grant_hash":             grantHash,
		"leaf_public_key_sha256": "sha256:leaf",
		"tls_exporter_sha256":    "sha256:exporter",
		"request_context_sha256": "sha256:context",
		"nonce":                  "nonce-1",
	}
}

func testDefaultEnvelopeClaims(now time.Time, grantToken, grantHash string) jwt.MapClaims {
	claims := testDefaultBindingClaims(now, grantHash)
	claims["jti"] = "envelope-1"
	claims[ClaimTokenType] = TokenTypeSessionEnvelope
	claims["identity_grant_jwt"] = grantToken
	return claims
}

func corruptTestJWTSignature(t *testing.T, tokenString string) string {
	t.Helper()

	index := strings.LastIndex(tokenString, ".")
	if index < 0 || index == len(tokenString)-1 {
		t.Fatalf("JWT does not contain a signature segment: %q", tokenString)
	}
	corrupted := []byte(tokenString)
	switch corrupted[len(corrupted)-1] {
	case 'A':
		corrupted[len(corrupted)-1] = 'B'
	default:
		corrupted[len(corrupted)-1] = 'A'
	}
	return string(corrupted)
}

type agtpReplayCache struct {
	seen map[string]time.Time
}

func newAGTPReplayCache() *agtpReplayCache {
	return &agtpReplayCache{seen: make(map[string]time.Time)}
}

func (c *agtpReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}

func testSessionIdentityOptions(now time.Time) SessionIdentityJWTOptions {
	return SessionIdentityJWTOptions{
		Grant: JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          testKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		},
		SessionBinding: JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          testKeyFunc(map[string][]byte{"agent-key-1": []byte("agent-secret")}),
		},
		Policy: identitypolicy.Policy{
			Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
			Expected: identitypolicy.Values{
				Service:    testServicePayments,
				Deployment: "prod",
				Agent:      "agent-a",
				TaskID:     "task-1",
				Scopes:     []string{"orders:read"},
			},
		},
		ExpectedBinding: identitypolicy.Binding{
			LeafPublicKeySHA256:  "sha256:leaf",
			TLSExporterSHA256:    "sha256:exporter",
			RequestContextSHA256: "sha256:context",
			Nonce:                "nonce-1",
		},
		ReplayCache: newAGTPReplayCache(),
		Now:         now,
	}
}
