// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/sha3"
	"testing"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	asbattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
)

func testEvidenceBinding() eaattestation.EvidenceBinding {
	var binding eaattestation.EvidenceBinding
	for i := range binding.ReportData {
		binding.ReportData[i] = byte(i + 1)
	}
	for i := range binding.Nonce {
		binding.Nonce[i] = byte(0xa0 + i)
	}
	return binding
}

func TestVerifyEvidenceBindingRejectsTDXReportDataMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report := make([]byte, 0x248)
	copy(report[0x208:0x248], expected.ReportData[:])

	if err := verifyEvidenceBinding(asbattestation.TDX, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	report[0x208] ^= 0xff
	if err := verifyEvidenceBinding(asbattestation.TDX, report, expected); err == nil {
		t.Fatal("expected mismatched TDX report data to fail")
	}
}

func TestVerifyEvidenceBindingRejectsSNPReportDataMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report, err := proto.Marshal(&sevsnp.Attestation{
		Report: &sevsnp.Report{
			ReportData: append([]byte(nil), expected.ReportData[:]...),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := verifyEvidenceBinding(asbattestation.SNP, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wrong eaattestation.EvidenceBinding
	copy(wrong.ReportData[:], expected.ReportData[:])
	wrong.ReportData[0] ^= 0xff
	if err := verifyEvidenceBinding(asbattestation.SNP, report, wrong); err == nil {
		t.Fatal("expected mismatched SNP report data to fail")
	}
}

func TestVerifyEvidenceBindingRejectsVTPMNonceMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report := testVTPMReport(t, expected.Nonce[:])

	if err := verifyEvidenceBinding(asbattestation.VTPM, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wrong := expected
	wrong.Nonce[0] ^= 0xff
	if err := verifyEvidenceBinding(asbattestation.VTPM, report, wrong); err == nil {
		t.Fatal("expected mismatched vTPM nonce to fail")
	}
}

func TestVerifyEvidenceBindingRejectsSNPvTPMQuoteNonceMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report := testSNPvTPMReport(t, expected)

	if err := verifyEvidenceBinding(asbattestation.SNPvTPM, report, expected); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wrong := expected
	wrong.Nonce[0] ^= 0xff
	if err := verifyEvidenceBinding(asbattestation.SNPvTPM, report, wrong); err == nil {
		t.Fatal("expected mismatched SNP-vTPM quote nonce to fail")
	}
}

func TestVerifyEvidenceBindingRejectsSNPvTPMReportDataMismatch(t *testing.T) {
	expected := testEvidenceBinding()
	report := testSNPvTPMReport(t, expected)

	wrong := expected
	wrong.ReportData[0] ^= 0xff
	if err := verifyEvidenceBinding(asbattestation.SNPvTPM, report, wrong); err == nil {
		t.Fatal("expected mismatched SNP-vTPM report data to fail")
	}
}

func testVTPMReport(t *testing.T, nonce []byte) []byte {
	t.Helper()
	quote := testTPMQuote(t, nonce)
	report, err := proto.Marshal(&attest.Attestation{
		Quotes: []*tpmpb.Quote{{Quote: quote}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func testSNPvTPMReport(t *testing.T, expected eaattestation.EvidenceBinding) []byte {
	t.Helper()
	akPub := []byte("test-ak-public-key")
	teeReportData := sha3.Sum512(append(append([]byte(nil), expected.ReportData[:]...), akPub...))
	quote := testTPMQuote(t, expected.Nonce[:])
	report, err := proto.Marshal(&attest.Attestation{
		AkPub:  akPub,
		Quotes: []*tpmpb.Quote{{Quote: quote}},
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{
					ReportData: teeReportData[:],
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func testTPMQuote(t *testing.T, nonce []byte) []byte {
	t.Helper()
	quote, err := tpm2.AttestationData{
		Magic:           0xff544347,
		Type:            tpm2.TagAttestQuote,
		QualifiedSigner: tpm2.Name{},
		ExtraData:       tpmutil.U16Bytes(nonce),
		ClockInfo:       tpm2.ClockInfo{},
		AttestedQuoteInfo: &tpm2.QuoteInfo{
			PCRSelection: tpm2.PCRSelection{Hash: tpm2.AlgSHA256},
			PCRDigest:    tpmutil.U16Bytes{},
		},
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return quote
}
