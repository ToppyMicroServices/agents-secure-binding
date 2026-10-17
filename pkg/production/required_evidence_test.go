// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	asb "github.com/ToppyMicroServices/agents-secure-binding/v2"
	"github.com/golang-jwt/jwt/v5"
)

// These tests exercise local cryptographic verification with test trust roots;
// they do not claim that the fixtures came from live Azure or hardware.
func TestAzureSNPBridgeRejectsNonemptyInvalidAndSampleEvidence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		token func(*testing.T, *azureSNPBridgeFixture) string
		want  error
	}{
		{
			name: "opaque collection output",
			token: func(*testing.T, *azureSNPBridgeFixture) string {
				return "nonempty raw evidence is not an authenticated MAA token"
			},
			want: ErrAzureMAAToken,
		},
		{
			name: "embedded sample collection output",
			token: func(*testing.T, *azureSNPBridgeFixture) string {
				return string(asb.EmbeddedAttestation)
			},
			want: ErrAzureMAAToken,
		},
		{
			name: "unsigned token with otherwise valid claims",
			token: func(t *testing.T, f *azureSNPBridgeFixture) string {
				token := jwt.NewWithClaims(jwt.SigningMethodNone, f.claims)
				token.Header["kid"] = testMAAKeyID
				signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatal(err)
				}
				return signed
			},
			want: ErrAzureMAAToken,
		},
		{
			name: "tampered signature",
			token: func(t *testing.T, f *azureSNPBridgeFixture) string {
				parts := strings.Split(f.signToken(t, f.claims), ".")
				signature, err := base64.RawURLEncoding.DecodeString(parts[2])
				if err != nil {
					t.Fatal(err)
				}
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				return strings.Join(parts, ".")
			},
			want: ErrAzureMAAToken,
		},
		{
			name: "untrusted signer using trusted key ID",
			token: func(t *testing.T, f *azureSNPBridgeFixture) string {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				f.maaPrivate = key
				return f.signToken(t, f.claims)
			},
			want: ErrAzureMAAToken,
		},
		{
			name: "authenticated NoCC claim is not SNP evidence",
			token: func(t *testing.T, f *azureSNPBridgeFixture) string {
				f.tee()["x-ms-attestation-type"] = "NoCC"
				return f.signToken(t, f.claims)
			},
			want: ErrAzureSNPPolicy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newAzureSNPBridgeFixture(t)
			token := tt.token(t, fixture)
			if len(token) == 0 {
				t.Fatal("test requires nonempty evidence")
			}
			result, err := fixture.bridge.Issue(context.Background(), token, fixture.binder, fixture.now)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Issue() error = %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(result, AttestationResult{}) {
				t.Fatalf("rejected evidence produced an attestation result: %+v", result)
			}
		})
	}
}

func TestRequiredProfileRejectsInvalidAndSampleAttestationResults(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *profileFixture)
		want   error
	}{
		{
			name: "nonempty malformed signature",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.request.Attestation.Signature = []byte("invalid")
			},
			want: ErrAttestationSignature,
		},
		{
			name: "tampered signature",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.request.Attestation.Signature[0] ^= 1
			},
			want: ErrAttestationSignature,
		},
		{
			name: "signed result changed after signing",
			mutate: func(_ *testing.T, f *profileFixture) {
				f.request.Attestation.ResultID = "tampered-result-id"
			},
			want: ErrAttestationSignature,
		},
		{
			name: "untrusted signer using trusted key ID",
			mutate: func(t *testing.T, f *profileFixture) {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signAttestation(t, &f.request.Attestation, key)
			},
			want: ErrAttestationSignature,
		},
		{
			name: "authenticated sample measurement",
			mutate: func(t *testing.T, f *profileFixture) {
				f.request.Attestation.Measurement = "sample"
				signAttestation(t, &f.request.Attestation, f.attesterPrivate)
			},
			want: ErrAttestationPolicy,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fixture := newProfileFixture(t)
			tt.mutate(t, fixture)
			if len(fixture.request.Attestation.Signature) == 0 {
				t.Fatal("test requires a nonempty attestation signature")
			}
			accepted, err := fixture.profile.Verify(context.Background(), fixture.request)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(accepted, AcceptedIdentity{}) {
				t.Fatalf("rejected attestation returned an accepted identity: %+v", accepted)
			}
			if fixture.replay.count() != 0 {
				t.Fatalf("replay commits = %d, want 0", fixture.replay.count())
			}
		})
	}
}
