// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/subtle"
	"fmt"
	"os"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	asbattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/azure"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/tdx"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/vtpm"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/veraison/corim/corim"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

type policyEvidenceVerifier struct {
	policyPath string
}

func NewEvidenceVerifier(policyPath string) eaattestation.EvidenceVerifier {
	return &policyEvidenceVerifier{policyPath: policyPath}
}

func (v *policyEvidenceVerifier) VerifyEvidence(evidence []byte, expected eaattestation.EvidenceBinding) error {
	if v.policyPath == "" {
		return fmt.Errorf("atls: attestation policy path is not set")
	}
	claims, err := eat.DecodeCBOR(evidence, nil)
	if err != nil {
		return fmt.Errorf("atls: failed to decode EAT evidence: %w", err)
	}
	if !constantTimeEqual(claims.Nonce, expected.Nonce[:]) {
		return fmt.Errorf("atls: evidence nonce does not match TLS exporter binding")
	}
	platformType := platformTypeFromClaims(claims.PlatformType)
	if err := verifyEvidenceBinding(platformType, claims.RawReport, expected); err != nil {
		return err
	}
	manifest, err := loadCoRIM(v.policyPath)
	if err != nil {
		return err
	}
	verifier, err := platformVerifier(platformType)
	if err != nil {
		return err
	}
	return verifier.VerifyWithCoRIM(claims.RawReport, manifest)
}

func verifyEvidenceBinding(platformType asbattestation.PlatformType, report []byte, expected eaattestation.EvidenceBinding) error {
	switch platformType {
	case asbattestation.TDX:
		return verifyTDXReportData(report, expected.ReportData[:])
	case asbattestation.SNP, asbattestation.Azure:
		return verifySNPReportData(report, expected.ReportData[:])
	case asbattestation.SNPvTPM:
		if err := verifyVTPMNonce(report, expected.Nonce[:]); err != nil {
			return err
		}
		return verifySNPvTPMReportData(report, expected.ReportData[:])
	case asbattestation.VTPM:
		return verifyVTPMNonce(report, expected.Nonce[:])
	default:
		return fmt.Errorf("atls: unsupported platform type for binding verification: %d", platformType)
	}
}

func verifyTDXReportData(report []byte, expectedReportData []byte) error {
	const (
		tdxReportDataStart = 0x208
		tdxReportDataEnd   = 0x248
	)
	if len(report) < tdxReportDataEnd {
		return fmt.Errorf("atls: TDX report too small to extract report data")
	}
	if !constantTimeEqual(report[tdxReportDataStart:tdxReportDataEnd], expectedReportData) {
		return fmt.Errorf("atls: TDX report data does not match TLS exporter binding")
	}
	return nil
}

func verifySNPReportData(report []byte, expectedReportData []byte) error {
	if snpReport, ok := snpReportFromAttestation(report); ok {
		return compareSNPReportData(snpReport, expectedReportData)
	}
	var snpAtt sevsnp.Attestation
	if err := proto.Unmarshal(report, &snpAtt); err != nil {
		return fmt.Errorf("atls: failed to parse SNP attestation report: %w", err)
	}
	return compareSNPReportData(&snpAtt, expectedReportData)
}

func verifySNPvTPMReportData(report []byte, expectedReportData []byte) error {
	var att attest.Attestation
	if err := proto.Unmarshal(report, &att); err != nil {
		return fmt.Errorf("atls: failed to parse SNP-vTPM attestation report: %w", err)
	}
	snpReport := att.GetSevSnpAttestation()
	if snpReport == nil {
		return fmt.Errorf("atls: SNP-vTPM attestation is missing embedded SNP report")
	}
	expectedTEEReportData := sha3.Sum512(append(append([]byte(nil), expectedReportData...), att.GetAkPub()...))
	return compareSNPReportData(snpReport, expectedTEEReportData[:])
}

func snpReportFromAttestation(report []byte) (*sevsnp.Attestation, bool) {
	var att attest.Attestation
	if err := proto.Unmarshal(report, &att); err != nil {
		return nil, false
	}
	snpReport := att.GetSevSnpAttestation()
	return snpReport, snpReport != nil
}

func compareSNPReportData(snpReport *sevsnp.Attestation, expectedReportData []byte) error {
	if snpReport == nil || snpReport.GetReport() == nil {
		return fmt.Errorf("atls: SNP attestation is missing report data")
	}
	if !constantTimeEqual(snpReport.GetReport().GetReportData(), expectedReportData) {
		return fmt.Errorf("atls: SNP report data does not match TLS exporter binding")
	}
	return nil
}

func verifyVTPMNonce(report []byte, expectedNonce []byte) error {
	var att attest.Attestation
	if err := proto.Unmarshal(report, &att); err != nil {
		return fmt.Errorf("atls: failed to parse vTPM attestation report: %w", err)
	}
	for _, quote := range att.GetQuotes() {
		attested, err := tpm2.DecodeAttestationData(quote.GetQuote())
		if err != nil {
			continue
		}
		if constantTimeEqual(attested.ExtraData, expectedNonce) {
			return nil
		}
	}
	return fmt.Errorf("atls: vTPM quote nonce does not match TLS exporter binding")
}

func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func loadCoRIM(path string) (*corim.UnsignedCorim, error) {
	corimBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("atls: failed to read CoRIM file: %w", err)
	}

	var sc corim.SignedCorim
	if err := sc.FromCOSE(corimBytes); err == nil {
		return &sc.UnsignedCorim, nil
	}

	var uc corim.UnsignedCorim
	if err := uc.FromCBOR(corimBytes); err != nil {
		return nil, fmt.Errorf("atls: failed to parse CoRIM: %w", err)
	}
	return &uc, nil
}

func platformTypeFromClaims(name string) asbattestation.PlatformType {
	switch name {
	case "SNP":
		return asbattestation.SNP
	case "TDX":
		return asbattestation.TDX
	case "vTPM":
		return asbattestation.VTPM
	case "SNP-vTPM":
		return asbattestation.SNPvTPM
	case "Azure":
		return asbattestation.Azure
	default:
		return asbattestation.NoCC
	}
}

func platformVerifier(platformType asbattestation.PlatformType) (asbattestation.Verifier, error) {
	switch platformType {
	case asbattestation.SNP, asbattestation.SNPvTPM, asbattestation.VTPM:
		return vtpm.NewVerifier(nil), nil
	case asbattestation.Azure:
		return azure.NewVerifier(nil), nil
	case asbattestation.TDX:
		return tdx.NewVerifier(), nil
	default:
		return nil, fmt.Errorf("atls: unsupported platform type: %d", platformType)
	}
}
