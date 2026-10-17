// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package platformmodule

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tdxmodule "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/tdx"
	asb "github.com/ToppyMicroServices/agents-secure-binding/v2"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/fxamacker/cbor/v2"
)

func TestPlatformVerifierRejectsNonemptySampleEvidence(t *testing.T) {
	expected := testEvidenceBinding()
	key := testEATSigningKey(t)
	snpFixture := testDirectSNPEvidence(t, expected)
	// Match the 96-byte layout produced by FetchAttestation(UNSPECIFIED),
	// including the correct session values. Matching these values is not proof.
	noCC := append(append([]byte(nil), expected.ReportData[:]...), expected.Nonce[:]...)
	// This is a representative CC sample JSON fixture, not a live agent result.
	ccSample, err := json.Marshal(map[string]string{
		"svn":         "1",
		"report_data": base64.StdEncoding.EncodeToString(expected.ReportData[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	samples := []struct {
		name    string
		claim   string
		raw     []byte
		wantSNP error
	}{
		{name: "NoCC service sample", claim: "NoCC", raw: noCC, wantSNP: ErrInvalidSNPEvidence},
		{name: "CC sample JSON", claim: "sample", raw: ccSample, wantSNP: ErrInvalidSNPEvidence},
		// The legacy embedded bytes parse as an SNP ABI report, but contain
		// no trusted endorsements. They must reach and fail authentication.
		{name: "embedded vTPM sample", claim: "vTPM", raw: asb.EmbeddedAttestation, wantSNP: ErrSNPVerification},
	}
	for _, sample := range samples {
		if len(sample.raw) == 0 {
			t.Fatalf("%s must exercise nonempty evidence", sample.name)
		}
	}

	for _, platform := range []Platform{PlatformSNP, PlatformTDX} {
		t.Run(string(platform), func(t *testing.T) {
			// Use a well-formed policy rather than a placeholder file. Every
			// expected failure below must precede measurement appraisal.
			options := corimgen.Options{Platform: string(platform)}
			if platform == PlatformSNP {
				options.Measurement = hex.EncodeToString(snpFixture.measurement)
			}
			policy, err := corimgen.GenerateCoRIM(options)
			if err != nil {
				t.Fatal(err)
			}
			policyPath := filepath.Join(t.TempDir(), "policy.corim")
			if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCoRIM(policyPath, nil, time.Now()); err != nil {
				t.Fatalf("invalid test policy: %v", err)
			}
			config := testVerifierConfig(platform, policyPath, &key.PublicKey)
			if platform == PlatformSNP {
				config.SNPVerificationOptions = snpFixture.verificationOptions
				config.SNPValidationOptions = snpFixture.validationOptions
			}
			if platform == PlatformTDX {
				config.TDXRuntimeOptions = &tdxmodule.RuntimeOptions{Getter: rejectingTDXGetter{}}
			}
			verifier, err := NewEvidenceVerifier(config)
			if err != nil {
				t.Fatal(err)
			}
			if platform == PlatformSNP {
				claims := testSignedEnvelopeClaims(snpFixture.providerEvidence, expected.Nonce[:], "SNP")
				token, err := eat.EncodeToCBOR(claims, key, testEATIssuer)
				if err != nil {
					t.Fatal(err)
				}
				if err := verifier.VerifyEvidence(token, expected); err != nil {
					t.Fatalf("valid signed SNP control failed: %v", err)
				}
			}

			t.Run("malformed EAT", func(t *testing.T) {
				if err := verifier.VerifyEvidence([]byte("nonempty malformed EAT"), expected); !errors.Is(err, eat.ErrSignedCBORRequired) {
					t.Fatalf("VerifyEvidence() error = %v, want signed EAT rejection", err)
				}
			})
			for _, sample := range samples {
				t.Run(sample.name, func(t *testing.T) {
					claims := testSignedEnvelopeClaims(sample.raw, expected.Nonce[:], sample.claim)
					unsigned, err := cbor.Marshal(claims)
					if err != nil {
						t.Fatal(err)
					}
					if err := verifier.VerifyEvidence(unsigned, expected); !errors.Is(err, eat.ErrSignedCBORRequired) {
						t.Fatalf("unsigned sample error = %v, want signed EAT rejection", err)
					}

					token, err := eat.EncodeToCBOR(claims, key, testEATIssuer)
					if err != nil {
						t.Fatal(err)
					}
					if err := verifier.VerifyEvidence(token, expected); !errors.Is(err, ErrUnsupportedPlatform) {
						t.Fatalf("signed sample error = %v, want unsupported platform rejection", err)
					}

					// Even a trusted envelope signer cannot turn sample bytes into
					// hardware evidence by changing the platform label.
					claims.PlatformType = strings.ToUpper(string(platform))
					relabeled, err := eat.EncodeToCBOR(claims, key, testEATIssuer)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := eat.DecodeVerifiedCBOR(relabeled, &key.PublicKey)
					if err != nil {
						t.Fatalf("test envelope must have a valid signature: %v", err)
					}
					if !bytes.Equal(decoded.RawReport, sample.raw) || !bytes.Equal(decoded.Nonce, expected.Nonce[:]) {
						t.Fatal("test envelope did not preserve sample and expected nonce")
					}
					want := sample.wantSNP
					if platform == PlatformTDX {
						want = ErrTDXVerification
					}
					if err := verifier.VerifyEvidence(relabeled, expected); !errors.Is(err, want) {
						t.Fatalf("relabeled sample error = %v, want raw evidence rejection %v", err, want)
					}
				})
			}
		})
	}
}
