// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type invalidAzureBridgeSigner struct {
	public ed25519.PublicKey
}

func (s invalidAzureBridgeSigner) Public() crypto.PublicKey {
	return s.public
}

func (s invalidAzureBridgeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

const (
	testMAAIssuer      = "https://asb-prod.eus.attest.azure.net"
	testMAAKeyID       = "maa-rs256-2026-01"
	testMAAPolicyHash  = "maa-policy-sha256:test"
	testAzureSNPMetric = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type azureSNPBridgeFixture struct {
	bridge      AzureSNPAttestationBridge
	maaPrivate  *rsa.PrivateKey
	attesterPub ed25519.PublicKey
	now         time.Time
	binder      string
	claims      jwt.MapClaims
}

func TestAzureSNPAttestationBridgeIssuesVerifiableResult(t *testing.T) {
	t.Parallel()
	fixture := newAzureSNPBridgeFixture(t)
	token := fixture.signToken(t, fixture.claims)

	result, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	policy := SignedAttestationPolicy{
		TrustedKeys:         map[string]ed25519.PublicKey{fixture.bridge.VerifierKeyID: fixture.attesterPub},
		PolicyID:            fixture.bridge.PolicyID,
		AllowedMeasurements: []string{testAzureSNPMetric},
		MaxAge:              time.Minute,
		ClockSkew:           time.Second,
	}
	if err := policy.Verify(context.Background(), result, fixture.binder, fixture.now); err != nil {
		t.Fatalf("SignedAttestationPolicy.Verify() error = %v", err)
	}
	if result.ExpiresAt.After(fixture.now.Add(fixture.bridge.ResultTTL)) {
		t.Fatalf("result expiry = %v, exceeds bridge TTL", result.ExpiresAt)
	}
}

func TestAzureSNPAttestationBridgeAcceptsGuestNonce(t *testing.T) {
	t.Parallel()
	for _, matchingDirectNonce := range []bool{false, true} {
		name := "nested only"
		if matchingDirectNonce {
			name = "matching direct and nested"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newAzureSNPBridgeFixture(t)
			challenge := AzureSNPChallenge(fixture.binder)
			fixture.claims["x-ms-runtime"] = map[string]any{
				"client-payload": map[string]any{
					"nonce": base64.StdEncoding.EncodeToString([]byte(challenge)),
				},
			}
			if !matchingDirectNonce {
				delete(fixture.claims, "nonce")
			}
			token := fixture.signToken(t, fixture.claims)
			result, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
			if err != nil {
				t.Fatalf("Issue() error = %v", err)
			}
			policy := SignedAttestationPolicy{
				TrustedKeys:         map[string]ed25519.PublicKey{fixture.bridge.VerifierKeyID: fixture.attesterPub},
				PolicyID:            fixture.bridge.PolicyID,
				AllowedMeasurements: []string{testAzureSNPMetric},
				MaxAge:              time.Minute,
				ClockSkew:           time.Second,
			}
			if err := policy.Verify(context.Background(), result, fixture.binder, fixture.now); err != nil {
				t.Fatalf("SignedAttestationPolicy.Verify() error = %v", err)
			}
		})
	}
}

func TestAzureSNPAttestationBridgeRejectsInvalidGuestNonce(t *testing.T) {
	t.Parallel()
	encoded := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	payload := func(value any) map[string]any {
		return map[string]any{"client-payload": map[string]any{"nonce": value}}
	}
	tests := []struct {
		name       string
		runtime    any
		direct     any
		keepDirect bool
		want       error
	}{
		{name: "missing nonce", runtime: map[string]any{}, want: ErrAzureSNPClaims},
		{name: "missing client payload nonce", runtime: map[string]any{"client-payload": map[string]any{}}, want: ErrAzureSNPClaims},
		{name: "null runtime", runtime: nil, want: ErrAzureSNPClaims},
		{name: "runtime wrong type", runtime: "nonce", want: ErrAzureSNPClaims},
		{name: "null payload", runtime: map[string]any{"client-payload": nil}, want: ErrAzureSNPClaims},
		{name: "payload wrong type", runtime: map[string]any{"client-payload": "nonce"}, want: ErrAzureSNPClaims},
		{name: "null nonce", runtime: payload(nil), want: ErrAzureSNPClaims},
		{name: "nonce wrong type", runtime: payload(1), want: ErrAzureSNPClaims},
		{name: "empty nonce", runtime: payload(""), want: ErrAzureSNPClaims},
		{name: "blank nonce", runtime: payload(encoded(" ")), want: ErrAzureSNPClaims},
		{name: "whitespace nonce", runtime: payload(encoded("a b")), want: ErrAzureSNPClaims},
		{name: "control byte nonce", runtime: payload(encoded("a\x00b")), want: ErrAzureSNPClaims},
		{name: "non ASCII nonce", runtime: payload(encoded("é")), want: ErrAzureSNPClaims},
		{name: "invalid base64", runtime: payload("!"), want: ErrAzureSNPClaims},
		{name: "missing base64 padding", runtime: payload("YQ"), want: ErrAzureSNPClaims},
		{name: "nonzero base64 padding bits", runtime: payload("YR=="), want: ErrAzureSNPClaims},
		{name: "base64 newline", runtime: payload("YQ==\n"), want: ErrAzureSNPClaims},
		{name: "base64url alphabet", runtime: payload("____"), want: ErrAzureSNPClaims},
		{name: "oversized nonce", runtime: payload(encoded(strings.Repeat("a", 4097))), want: ErrAzureSNPClaims},
		{name: "conflicting direct nonce", runtime: payload(encoded("guest-nonce")), direct: "different", want: ErrAzureSNPClaims},
		{name: "invalid direct nonce", runtime: payload(encoded("guest-nonce")), direct: 1, want: ErrAzureSNPClaims},
		{name: "blank direct nonce", runtime: payload(encoded("guest-nonce")), direct: "", want: ErrAzureSNPClaims},
		{name: "valid direct with null runtime", runtime: nil, keepDirect: true, want: ErrAzureSNPClaims},
		{name: "valid direct with null payload", runtime: map[string]any{"client-payload": nil}, keepDirect: true, want: ErrAzureSNPClaims},
		{name: "valid direct with malformed nested nonce", runtime: payload("!"), keepDirect: true, want: ErrAzureSNPClaims},
		{name: "valid direct with empty nested nonce", runtime: payload(""), keepDirect: true, want: ErrAzureSNPClaims},
		{name: "valid direct with conflicting nested nonce", runtime: payload(encoded("different")), keepDirect: true, want: ErrAzureSNPClaims},
		{name: "wrong binder", runtime: payload(encoded(AzureSNPChallenge(testHash("other-binder")))), want: ErrAzureSNPBinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAzureSNPBridgeFixture(t)
			if !tt.keepDirect {
				delete(fixture.claims, "nonce")
			}
			fixture.claims["x-ms-runtime"] = tt.runtime
			if tt.direct != nil {
				fixture.claims["nonce"] = tt.direct
			}
			token := fixture.signToken(t, fixture.claims)
			result, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Issue() error = %v, want %v", err, tt.want)
			}
			if len(result.Signature) != 0 {
				t.Fatal("Issue() signed a result for a rejected nonce")
			}
		})
	}
}

func TestAzureSNPAttestationBridgeAuthenticatesGuestNonce(t *testing.T) {
	t.Parallel()
	fixture := newAzureSNPBridgeFixture(t)
	delete(fixture.claims, "nonce")
	fixture.claims["x-ms-runtime"] = map[string]any{
		"client-payload": map[string]any{
			"nonce": base64.StdEncoding.EncodeToString([]byte(AzureSNPChallenge(fixture.binder))),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, fixture.claims)
	token.Header["kid"] = testMAAKeyID
	unsigned, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	guestPayload := fixture.claims["x-ms-runtime"].(map[string]any)["client-payload"].(map[string]any)
	guestPayload["nonce"] = base64.StdEncoding.EncodeToString([]byte(AzureSNPChallenge(testHash("other-binder"))))
	signed := fixture.signToken(t, fixture.claims)
	guestPayload["nonce"] = base64.StdEncoding.EncodeToString([]byte(AzureSNPChallenge(fixture.binder)))
	modifiedClaims, err := json.Marshal(fixture.claims)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(signed, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(modifiedClaims)
	for name, input := range map[string]string{
		"unsigned": unsigned,
		"tampered": strings.Join(parts, "."),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := fixture.bridge.Issue(context.Background(), input, fixture.binder, fixture.now)
			if !errors.Is(err, ErrAzureMAAToken) {
				t.Fatalf("Issue() error = %v, want %v", err, ErrAzureMAAToken)
			}
			if len(result.Signature) != 0 {
				t.Fatal("Issue() signed a result for an unauthenticated token")
			}
		})
	}
}

func TestAzureSNPAttestationBridgeRejectsPolicyAndBindingFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*azureSNPBridgeFixture)
		want   error
	}{
		{"wrong binder challenge", func(f *azureSNPBridgeFixture) { f.claims["nonce"] = AzureSNPChallenge(testHash("other-binder")) }, ErrAzureSNPBinding},
		{"debug enabled", func(f *azureSNPBridgeFixture) { f.tee()["x-ms-sevsnpvm-is-debuggable"] = true }, ErrAzureSNPPolicy},
		{"migration enabled", func(f *azureSNPBridgeFixture) { f.tee()["x-ms-sevsnpvm-migration-allowed"] = true }, ErrAzureSNPPolicy},
		{"measurement mismatch", func(f *azureSNPBridgeFixture) { f.tee()["x-ms-sevsnpvm-launchmeasurement"] = "different" }, ErrAzureSNPPolicy},
		{"policy hash mismatch", func(f *azureSNPBridgeFixture) { f.claims["x-ms-policy-hash"] = "different" }, ErrAzureSNPPolicy},
		{"guest svn too old", func(f *azureSNPBridgeFixture) { f.tee()["x-ms-sevsnpvm-guestsvn"] = float64(1) }, ErrAzureSNPPolicy},
		{"wrong issuer", func(f *azureSNPBridgeFixture) { f.claims["iss"] = "https://attacker.example" }, ErrAzureMAAToken},
		{"expired token", func(f *azureSNPBridgeFixture) { f.claims["exp"] = f.now.Add(-time.Minute).Unix() }, ErrAzureMAAToken},
		{"stale token", func(f *azureSNPBridgeFixture) { f.claims["iat"] = f.now.Add(-10 * time.Minute).Unix() }, ErrAzureMAAToken},
		{"disabled MAA key", func(f *azureSNPBridgeFixture) {
			verifier := f.bridge.TokenVerifier.(AzureMAATokenVerifier)
			verifier.DisabledKeyIDs = []string{testMAAKeyID}
			f.bridge.TokenVerifier = verifier
		}, ErrAzureMAAToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAzureSNPBridgeFixture(t)
			tt.mutate(fixture)
			token := fixture.signToken(t, fixture.claims)
			_, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Issue() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestExactUint64PreservesJSONIntegerSemantics(t *testing.T) {
	t.Parallel()
	if _, ok := exactUint64(float64(1 << 53)); ok {
		t.Fatal("exactUint64() accepted a float64 outside the safe JSON integer range")
	}
	const maxUint64 = "18446744073709551615"
	got, ok := exactUint64(json.Number(maxUint64))
	if !ok || got != ^uint64(0) {
		t.Fatalf("exactUint64(%s) = (%d, %t)", maxUint64, got, ok)
	}
	if _, ok := exactUint64(json.Number("18446744073709551616")); ok {
		t.Fatal("exactUint64() accepted a JSON integer larger than uint64")
	}
}

func TestAzureMAATokenVerifierRejectsUntrustedKey(t *testing.T) {
	t.Parallel()
	fixture := newAzureSNPBridgeFixture(t)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, fixture.claims)
	token.Header["kid"] = "attacker"
	signed, err := token.SignedString(attacker)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.bridge.Issue(context.Background(), signed, fixture.binder, fixture.now)
	if !errors.Is(err, ErrAzureMAAToken) {
		t.Fatalf("Issue() error = %v, want %v", err, ErrAzureMAAToken)
	}
}

func TestAzureSNPAttestationBridgeRejectsInvalidSignerOutput(t *testing.T) {
	t.Parallel()
	fixture := newAzureSNPBridgeFixture(t)
	fixture.bridge.Signer = invalidAzureBridgeSigner{public: fixture.attesterPub}
	token := fixture.signToken(t, fixture.claims)
	_, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
	if !errors.Is(err, ErrAzureSNPBridge) {
		t.Fatalf("Issue() error = %v, want %v", err, ErrAzureSNPBridge)
	}
}

func newAzureSNPBridgeFixture(t *testing.T) *azureSNPBridgeFixture {
	t.Helper()
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	maaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attesterPub, attesterPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binder := testHash("azure-snp-exact-session-action")
	tee := map[string]any{
		"x-ms-attestation-type":           AzureSNPAttestationType,
		"x-ms-sevsnpvm-launchmeasurement": testAzureSNPMetric,
		"x-ms-sevsnpvm-guestsvn":          float64(3),
		"x-ms-sevsnpvm-is-debuggable":     false,
		"x-ms-sevsnpvm-migration-allowed": false,
	}
	claims := jwt.MapClaims{
		"iss":                testMAAIssuer,
		"jti":                "maa-attestation-0001",
		"iat":                now.Add(-10 * time.Second).Unix(),
		"nbf":                now.Add(-10 * time.Second).Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"nonce":              AzureSNPChallenge(binder),
		"x-ms-ver":           "1.0",
		"x-ms-policy-hash":   testMAAPolicyHash,
		"x-ms-isolation-tee": tee,
	}
	return &azureSNPBridgeFixture{
		bridge: AzureSNPAttestationBridge{
			TokenVerifier: AzureMAATokenVerifier{
				Issuer:      testMAAIssuer,
				TrustedKeys: map[string]*rsa.PublicKey{testMAAKeyID: &maaPrivate.PublicKey},
				MaxAge:      2 * time.Minute,
				ClockSkew:   time.Second,
			},
			VerifierKeyID:       "asb-azure-bridge-ed25519-2026-01",
			Signer:              attesterPrivate,
			PolicyID:            "protected-change-azure-sevsnp/v1",
			AllowedPolicyHashes: []string{testMAAPolicyHash},
			AllowedMeasurements: []string{testAzureSNPMetric},
			MinimumGuestSVN:     2,
			ResultTTL:           30 * time.Second,
		},
		maaPrivate:  maaPrivate,
		attesterPub: attesterPub,
		now:         now,
		binder:      binder,
		claims:      claims,
	}
}

func (f *azureSNPBridgeFixture) tee() map[string]any {
	return f.claims["x-ms-isolation-tee"].(map[string]any)
}

func (f *azureSNPBridgeFixture) signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testMAAKeyID
	signed, err := token.SignedString(f.maaPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
