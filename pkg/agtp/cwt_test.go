// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func TestVerifySessionIdentityCWTAcceptsManagerGrantAndLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)

	grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
	bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

	result, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
	if err != nil {
		t.Fatalf("VerifySessionIdentityCWT() error = %v", err)
	}
	if result.Grant.GrantHash != IdentityGrantCWTHash(grantToken) {
		t.Fatalf("result grant hash = %q, want CWT profile hash", result.Grant.GrantHash)
	}
	if result.Assertion.Values.Service != testServicePayments {
		t.Fatalf("result service = %q, want payments", result.Assertion.Values.Service)
	}
}

func TestIdentityGrantCWTHashUsesSSOTDomainSeparator(t *testing.T) {
	token := []byte("cwt-token")
	h := sha256.New()
	_, _ = h.Write([]byte("sbaip.identity-grant.cwt.v1\x00"))
	_, _ = h.Write(token)
	want := "sha256:" + hex.EncodeToString(h.Sum(nil))

	if got := IdentityGrantCWTHash(token); got != want {
		t.Fatalf("IdentityGrantCWTHash() = %q, want %q", got, want)
	}
}

func TestVerifySessionIdentityCWTRejectsMissingReplayCache(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)
	grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
	bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))
	opts := testSessionIdentityCWTOptions(now, keys)
	opts.ReplayCache = nil

	_, err := VerifySessionIdentityCWT(grantToken, bindingToken, opts)
	if !errors.Is(err, ErrMissingReplayCache) {
		t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, ErrMissingReplayCache)
	}
}

func TestVerifySessionIdentityCWTRejectsNaturalLanguageSemanticReference(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)
	grantClaims := testDefaultCWTGrantClaims(now)
	grantClaims["intent_ref"] = "セリフ配布"
	grantToken := signTestCWT(t, "manager-key", keys.manager, grantClaims)
	bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

	_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
	if !errors.Is(err, identitypolicy.ErrUnsafeValue) {
		t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, identitypolicy.ErrUnsafeValue)
	}
}

func TestVerifySessionIdentityCWTRedTeamRejectsCOSEProfileAttacks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)

	t.Run("forged grant signed by Agent key", func(t *testing.T) {
		grantToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTGrantClaims(now))
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
		if !errors.Is(err, ErrUnknownKeyID) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, ErrUnknownKeyID)
		}
	})

	t.Run("forged grant signature", func(t *testing.T) {
		grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
		grantToken[len(grantToken)-1] ^= 0xff
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

		if _, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys)); err == nil {
			t.Fatal("VerifySessionIdentityCWT() error = nil, want COSE signature verification failure")
		}
	})

	t.Run("wrong binding signer", func(t *testing.T) {
		grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
		bindingToken := signTestCWT(t, "other-agent-key", keys.otherAgent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))
		opts := testSessionIdentityCWTOptions(now, keys)
		opts.SessionBinding.KeyFunc = testCWTKeyFunc(map[string]*ecdsa.PrivateKey{
			"agent-key-1":     keys.agent,
			"other-agent-key": keys.otherAgent,
		})

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, opts)
		if !errors.Is(err, identitypolicy.ErrUnauthorizedBindingKey) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, identitypolicy.ErrUnauthorizedBindingKey)
		}
	})

	t.Run("grant substitution", func(t *testing.T) {
		grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
		otherGrantClaims := testDefaultCWTGrantClaims(now)
		otherGrantClaims[cose.CWTClaimCWTID] = []byte("grant-2")
		otherGrantToken := signTestCWT(t, "manager-key", keys.manager, otherGrantClaims)
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(otherGrantToken)))

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
		}
	})

	t.Run("expired session binding", func(t *testing.T) {
		grantToken := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
		bindingClaims := testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken))
		bindingClaims[cose.CWTClaimExpirationTime] = now.Add(-time.Minute).Unix()
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, bindingClaims)

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
		if !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, ErrExpiredToken)
		}
	})

	t.Run("local policy mismatch", func(t *testing.T) {
		grantClaims := testDefaultCWTGrantClaims(now)
		grantClaims["service"] = testServiceAnalytics
		grantToken := signTestCWT(t, "manager-key", keys.manager, grantClaims)
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
		if !errors.Is(err, identitypolicy.ErrMismatch) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, identitypolicy.ErrMismatch)
		}
	})

	t.Run("unprotected COSE kid", func(t *testing.T) {
		grantToken := signTestCWTWithKidPlacement(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now), false)
		bindingToken := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(grantToken)))

		_, err := VerifySessionIdentityCWT(grantToken, bindingToken, testSessionIdentityCWTOptions(now, keys))
		if !errors.Is(err, ErrUnprotectedKeyID) {
			t.Fatalf("VerifySessionIdentityCWT() error = %v, want %v", err, ErrUnprotectedKeyID)
		}
	})
}

func TestVerifySessionIdentityCWTRedTeamRejectsMalformedCorpus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)
	validGrant := signTestCWT(t, "manager-key", keys.manager, testDefaultCWTGrantClaims(now))
	validBinding := signTestCWT(t, "agent-key-1", keys.agent, testDefaultCWTBindingClaims(now, IdentityGrantCWTHash(validGrant)))

	tests := []struct {
		name    string
		grant   []byte
		binding []byte
	}{
		{
			name:    "empty grant bytes",
			grant:   nil,
			binding: validBinding,
		},
		{
			name:    "truncated grant COSE",
			grant:   validGrant[:len(validGrant)/2],
			binding: validBinding,
		},
		{
			name:    "malformed binding CBOR",
			grant:   validGrant,
			binding: []byte{0xa1, 0x01},
		},
		{
			name:    "non-COSE binding bytes",
			grant:   validGrant,
			binding: []byte("not a cose sign1 message"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := VerifySessionIdentityCWT(tt.grant, tt.binding, testSessionIdentityCWTOptions(now, keys)); err == nil {
				t.Fatal("VerifySessionIdentityCWT() error = nil, want malformed CWT/COSE rejection")
			}
		})
	}
}

type testCWTKeySet struct {
	manager    *ecdsa.PrivateKey
	agent      *ecdsa.PrivateKey
	otherAgent *ecdsa.PrivateKey
}

func newTestCWTKeySet(t *testing.T) testCWTKeySet {
	t.Helper()
	return testCWTKeySet{
		manager:    generateTestCWTKey(t),
		agent:      generateTestCWTKey(t),
		otherAgent: generateTestCWTKey(t),
	}
}

func generateTestCWTKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signTestCWT(t *testing.T, keyID string, key *ecdsa.PrivateKey, claims map[any]any) []byte {
	t.Helper()
	return signTestCWTWithKidPlacement(t, keyID, key, claims, true)
}

func signTestCWTWithKidPlacement(t *testing.T, keyID string, key *ecdsa.PrivateKey, claims map[any]any, protectedKid bool) []byte {
	t.Helper()
	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatalf("cbor.Marshal() error = %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	if protectedKid {
		msg.Headers.Protected[cose.HeaderLabelKeyID] = []byte(keyID)
	} else {
		msg.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte(keyID)
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	token, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR() error = %v", err)
	}
	return token
}

func testCWTKeyFunc(keys map[string]*ecdsa.PrivateKey) CWTKeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, ErrUnknownKeyID
		}
		return &key.PublicKey, nil
	}
}

func testDefaultCWTGrantClaims(now time.Time) map[any]any {
	return map[any]any{
		cose.CWTClaimIssuer:         "manager",
		cose.CWTClaimSubject:        "agent-a",
		cose.CWTClaimAudience:       "client-a",
		cose.CWTClaimCWTID:          []byte("grant-1"),
		cose.CWTClaimIssuedAt:       now.Unix(),
		cose.CWTClaimExpirationTime: now.Add(time.Minute).Unix(),
		cose.CWTClaimConfirmation:   map[any]any{"kid": "agent-key-1"},
		ClaimTokenType:              TokenTypeIdentityGrant,
		ClaimProfileVersion:         ProfileVersion,
		"service":                   testServicePayments,
		"deployment":                "prod",
		"task_id":                   "task-1",
		"scope":                     "orders:read",
	}
}

func testDefaultCWTBindingClaims(now time.Time, grantHash string) map[any]any {
	return map[any]any{
		cose.CWTClaimIssuer:         "agent-a",
		cose.CWTClaimAudience:       "client-a",
		cose.CWTClaimCWTID:          []byte("binding-1"),
		cose.CWTClaimIssuedAt:       now.Unix(),
		cose.CWTClaimExpirationTime: now.Add(time.Minute).Unix(),
		ClaimTokenType:              TokenTypeSessionBinding,
		ClaimProfileVersion:         ProfileVersion,
		"grant_hash":                grantHash,
		"leaf_public_key_sha256":    "sha256:leaf",
		"tls_exporter_sha256":       "sha256:exporter",
		"request_context_sha256":    "sha256:context",
		"nonce":                     "nonce-1",
	}
}

func testSessionIdentityCWTOptions(now time.Time, keys testCWTKeySet) SessionIdentityCWTOptions {
	return SessionIdentityCWTOptions{
		Grant: CWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidAlgorithms:  []cose.Algorithm{cose.AlgorithmES256},
			KeyFunc:          testCWTKeyFunc(map[string]*ecdsa.PrivateKey{"manager-key": keys.manager}),
		},
		SessionBinding: CWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidAlgorithms:  []cose.Algorithm{cose.AlgorithmES256},
			KeyFunc:          testCWTKeyFunc(map[string]*ecdsa.PrivateKey{"agent-key-1": keys.agent}),
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
