// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
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
