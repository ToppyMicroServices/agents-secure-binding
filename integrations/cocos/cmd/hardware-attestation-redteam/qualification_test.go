// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/veraison/go-cose"
	"google.golang.org/protobuf/proto"
)

func TestQualificationEATPreservesProviderWireFormats(t *testing.T) {
	key, binding, snp := qualificationFixture(t)
	for _, tc := range []struct {
		platform attestation.PlatformType
		claim    string
		raw      []byte
	}{
		{attestation.SNP, "SNP", snp},
		{attestation.TDX, "TDX", tdxtestdata.RawQuote},
	} {
		t.Run(tc.claim, func(t *testing.T) {
			token, err := qualificationEAT(tc.raw, binding.Nonce[:], tc.platform, key, "qualification-test")
			if err != nil {
				t.Fatal(err)
			}
			claims, err := eat.DecodeVerifiedCBOR(token, &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(claims.RawReport, tc.raw) || !bytes.Equal(claims.Nonce, binding.Nonce[:]) || claims.PlatformType != tc.claim {
				t.Fatal("qualification envelope changed provider evidence or binding")
			}
		})
	}
}

func TestQualificationRejectionsUseValidEnvelopesAroundInvalidReports(t *testing.T) {
	key, binding, snp := qualificationFixture(t)
	for _, tc := range []struct {
		platform string
		typeID   attestation.PlatformType
		raw      []byte
	}{
		{platformSNP, attestation.SNP, snp},
		{platformTDX, attestation.TDX, tdxtestdata.RawQuote},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			original := append([]byte(nil), tc.raw...)
			token, err := qualificationEAT(tc.raw, binding.Nonce[:], tc.typeID, key, "qualification-test")
			if err != nil {
				t.Fatal(err)
			}
			cases, err := qualificationRejections(tc.platform, tc.raw, token, binding, key, "qualification-test")
			if err != nil {
				t.Fatal(err)
			}
			if len(cases) != 10 {
				t.Fatalf("rejection count = %d, want 10", len(cases))
			}
			for _, test := range cases {
				t.Run(test.name, func(t *testing.T) {
					if len(test.evidence) == 0 {
						t.Fatal("negative evidence must be nonempty")
					}
					claims, err := eat.DecodeVerifiedCBOR(test.evidence, &key.PublicKey)
					switch test.name {
					case "malformed_eat":
						if !errors.Is(err, eat.ErrSignedCBORRequired) {
							t.Fatalf("malformed envelope error = %v", err)
						}
					case "tampered_eat_signature":
						if !errors.Is(err, cose.ErrVerification) {
							t.Fatalf("signature mutation error = %v", err)
						}
					default:
						if err != nil || !bytes.Equal(claims.Nonce, binding.Nonce[:]) || len(claims.RawReport) == 0 {
							t.Fatalf("raw negative must use a trusted, bound envelope: %v", err)
						}
						if test.name == "tampered_report_signature" {
							assertOnlyReportSignatureChanged(t, tc.platform, original, claims.RawReport)
						}
						if strings.HasPrefix(test.name, "relabeled_") && claims.PlatformType != strings.ToUpper(tc.platform) {
							t.Fatal("relabeled sample must claim the configured hardware platform")
						}
					}
				})
			}
			if !bytes.Equal(original, tc.raw) {
				t.Fatal("negative cases modified the original evidence")
			}
		})
	}
}

func TestQualificationRequiresEveryExpectedDecision(t *testing.T) {
	key, bindingA, snp := qualificationFixture(t)
	bindingB := bindingA
	bindingB.Nonce[0] ^= 0xff
	tokenA, err := qualificationEAT(snp, bindingA.Nonce[:], attestation.SNP, key, "qualification-test")
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := qualificationEAT(snp, bindingB.Nonce[:], attestation.SNP, key, "qualification-test")
	if err != nil {
		t.Fatal(err)
	}
	cases, err := qualificationRejections(platformSNP, snp, tokenA, bindingA, key, "qualification-test")
	if err != nil {
		t.Fatal(err)
	}
	// This fake appraiser tests harness control flow only. It is not a live or
	// synthetic hardware verification result.
	decisions := []error{nil, nil, errChallengeMismatch}
	for _, tc := range cases {
		decisions = append(decisions, tc.want)
	}
	run := func(decisions []error) ([]verificationCheck, int, error) {
		calls := 0
		verifier := evidenceVerifierFunc(func(_ []byte, _ eaattestation.EvidenceBinding) error {
			result := decisions[calls]
			calls++
			return result
		})
		results, err := verifyQualificationCases(verifier, platformSNP, snp, tokenA, tokenB, bindingA, bindingB, key, "qualification-test")
		return results, calls, err
	}
	results, calls, err := run(decisions)
	if err != nil || calls != 13 || len(results) != 13 {
		t.Fatalf("complete qualification = %d results, %d calls, %v", len(results), calls, err)
	}
	for index := range decisions {
		changed := append([]error(nil), decisions...)
		if index < 2 {
			changed[index] = errors.New("appraiser unavailable")
		} else {
			changed[index] = nil
		}
		results, calls, err := run(changed)
		if err == nil || results != nil || calls != index+1 {
			t.Fatalf("decision %d mismatch returned success or continued: calls=%d, err=%v", index, calls, err)
		}
	}
	changed := append([]error(nil), decisions...)
	changed[3] = errors.New("unrelated outage")
	if results, _, err := run(changed); err == nil || results != nil {
		t.Fatal("unrelated outage counted as the expected evidence rejection")
	}
	for _, result := range results {
		if result.Name == "" || result.Expected != result.Observed || len(result.EvidenceSHA256) != 64 {
			t.Fatalf("incomplete named result: %+v", result)
		}
	}
	dir := t.TempDir()
	if err := writeSummary(dir, &runSummary{Checks: results}); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact map[string]json.RawMessage
	if err := json.Unmarshal(payload, &artifact); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw_report", "token", "nonce", "signature", "error"} {
		if _, ok := artifact[forbidden]; ok {
			t.Fatalf("artifact includes %s", forbidden)
		}
	}
}

type evidenceVerifierFunc func([]byte, eaattestation.EvidenceBinding) error

func (f evidenceVerifierFunc) VerifyEvidence(evidence []byte, binding eaattestation.EvidenceBinding) error {
	return f(evidence, binding)
}

func qualificationFixture(t *testing.T) (*ecdsa.PrivateKey, eaattestation.EvidenceBinding, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var binding eaattestation.EvidenceBinding
	binding.ReportData[0] = 42
	binding.Nonce[0] = 17
	// A small protobuf fixture catches accidental reinterpretation as an ABI
	// report. It does not carry a valid hardware signature or endorsements.
	raw, err := proto.Marshal(&sevsnppb.Attestation{Report: &sevsnppb.Report{
		ReportData: binding.ReportData[:], Signature: []byte("test-signature"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return key, binding, raw
}

func assertOnlyReportSignatureChanged(t *testing.T, platform string, original, changed []byte) {
	t.Helper()
	if bytes.Equal(original, changed) {
		t.Fatal("report signature was not changed")
	}
	if platform == platformSNP {
		var before, after sevsnppb.Attestation
		if err := proto.Unmarshal(original, &before); err != nil {
			t.Fatal(err)
		}
		if err := proto.Unmarshal(changed, &after); err != nil {
			t.Fatal(err)
		}
		after.Report.Signature[0] ^= 0xff
		if !proto.Equal(&before, &after) {
			t.Fatal("SNP mutation changed fields other than signature")
		}
		return
	}
	before, err := tdxabi.QuoteToProto(original)
	if err != nil {
		t.Fatal(err)
	}
	after, err := tdxabi.QuoteToProto(changed)
	if err != nil {
		t.Fatal(err)
	}
	after.(*tdxpb.QuoteV4).SignedData.Signature[0] ^= 0xff
	if !proto.Equal(before.(*tdxpb.QuoteV4), after.(*tdxpb.QuoteV4)) {
		t.Fatal("TDX mutation changed fields other than signature")
	}
}
