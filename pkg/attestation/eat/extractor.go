// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

// OEMID constants (Private Enterprise Numbers).
const (
	OEMID_AMD       = 3704 // https://www.iana.org/assignments/enterprise-numbers/?q=Advanced+Micro+Devices
	OEMID_INTEL     = 343  // https://www.iana.org/assignments/enterprise-numbers/?q=Intel+Corporation
	OEMID_MICROSOFT = 311  // https://www.iana.org/assignments/enterprise-numbers/?q=Microsoft+Corporation
)

// extractSNPClaims extracts AMD SEV-SNP specific claims from binary report.
func extractSNPClaims(claims *EATClaims, report []byte) error {
	var snpReport *sevsnp.Report
	if len(report) >= abi.ReportSize && abi.ValidateReportFormat(report[:abi.ReportSize]) == nil {
		// ABI evidence may include a certificate table after the report.
		attestation, err := abi.ReportCertsToProto(report)
		if err != nil {
			return fmt.Errorf("failed to parse SNP report: %w", err)
		}
		snpReport = attestation.GetReport()
	} else {
		// The direct SNP provider returns a marshaled sevsnp.Attestation.
		var attestation sevsnp.Attestation
		if err := proto.Unmarshal(report, &attestation); err != nil {
			return fmt.Errorf("failed to parse SNP report: %w", err)
		}
		snpReport = attestation.GetReport()
		if snpReport == nil {
			return fmt.Errorf("failed to parse SNP report: protobuf report is missing")
		}
		raw, err := abi.ReportToAbiBytes(snpReport)
		if err != nil {
			return fmt.Errorf("failed to parse SNP report: %w", err)
		}
		if err := abi.ValidateReportFormat(raw); err != nil {
			return fmt.Errorf("failed to parse SNP report: %w", err)
		}
	}

	// Extract SNP-specific fields
	claims.SNPExtensions = &SNPExtensions{
		Measurement:   snpReport.Measurement,
		Policy:        snpReport.Policy,
		FamilyID:      snpReport.FamilyId,
		ImageID:       snpReport.ImageId,
		VMPL:          int(snpReport.Vmpl),
		SignatureAlgo: int(snpReport.SignatureAlgo),
		PlatformInfo:  snpReport.PlatformInfo,
		ChipID:        snpReport.ChipId,
	}

	// Set TCB version info
	claims.SNPExtensions.CurrentTCB = snpReport.CurrentTcb
	claims.SNPExtensions.ReportedTCB = snpReport.ReportedTcb
	claims.SNPExtensions.CommittedTCB = snpReport.CommittedTcb
	claims.SNPExtensions.LaunchTCB = snpReport.LaunchTcb
	claims.SNPExtensions.TCB = fmt.Sprintf("current:%d,reported:%d", snpReport.CurrentTcb, snpReport.ReportedTcb)

	// Set core EAT claims from SNP report
	claims.Measurements = snpReport.Measurement
	claims.UEID = snpReport.ChipId // Use ChipID as UEID
	claims.OEMID = OEMID_AMD       // AMD's PEN (Private Enterprise Number)
	claims.SNPExtensions.Signature = snpReport.Signature

	// Set hardware model (hash of product name)
	claims.HWModel = []byte(fmt.Sprintf("SEV-SNP-%d", snpReport.Version))

	return nil
}

// extractSNPvTPMClaims unwraps the combined vTPM evidence before extracting
// the embedded SNP report. RawReport remains the original combined evidence.
func extractSNPvTPMClaims(claims *EATClaims, report []byte) error {
	var combined attest.Attestation
	if err := proto.Unmarshal(report, &combined); err != nil {
		return fmt.Errorf("failed to parse SNP-vTPM report: %w", err)
	}
	if len(combined.GetAkPub()) == 0 {
		return fmt.Errorf("SNP-vTPM report is missing the vTPM attestation key")
	}
	hasQuote := false
	for _, quote := range combined.GetQuotes() {
		if len(quote.GetQuote()) > 0 {
			hasQuote = true
			break
		}
	}
	if !hasQuote {
		return fmt.Errorf("SNP-vTPM report is missing a vTPM quote")
	}
	snp := combined.GetSevSnpAttestation()
	if snp == nil {
		return fmt.Errorf("SNP-vTPM report is missing the SEV-SNP attestation")
	}
	snpReport, err := proto.Marshal(snp)
	if err != nil {
		return fmt.Errorf("failed to encode embedded SNP report: %w", err)
	}
	if err := extractSNPClaims(claims, snpReport); err != nil {
		return fmt.Errorf("invalid embedded SNP report: %w", err)
	}
	return nil
}

// extractTDXClaims extracts Intel TDX specific claims from binary report.
func extractTDXClaims(claims *EATClaims, report []byte) error {
	// Parse TDX quote using go-tdx-guest ABI
	decodedQuote, err := tdxabi.QuoteToProto(report)
	if err != nil {
		return fmt.Errorf("failed to parse TDX quote: %w", err)
	}

	quoteV4, ok := decodedQuote.(*tdxpb.QuoteV4)
	if !ok {
		return fmt.Errorf("unsupported TDX quote format")
	}

	tdReport := quoteV4.GetTdQuoteBody()
	signedData := quoteV4.GetSignedData()

	rtmrs := tdReport.GetRtmrs()
	var rtmr0, rtmr1, rtmr2, rtmr3 []byte
	if len(rtmrs) > 0 {
		rtmr0 = rtmrs[0]
	}
	if len(rtmrs) > 1 {
		rtmr1 = rtmrs[1]
	}
	if len(rtmrs) > 2 {
		rtmr2 = rtmrs[2]
	}
	if len(rtmrs) > 3 {
		rtmr3 = rtmrs[3]
	}

	claims.TDXExtensions = &TDXExtensions{
		MRTD:          tdReport.GetMrTd(),
		RTMR0:         rtmr0,
		RTMR1:         rtmr1,
		RTMR2:         rtmr2,
		RTMR3:         rtmr3,
		XFAM:          binary.LittleEndian.Uint64(tdReport.GetXfam()),
		TDAttributes:  binary.LittleEndian.Uint64(tdReport.GetTdAttributes()),
		MRConfigID:    tdReport.GetMrConfigId(),
		MROwner:       tdReport.GetMrOwner(),
		MROwnerConfig: tdReport.GetMrOwnerConfig(),
		MRSEAM:        tdReport.GetMrSeam(),
		Signature:     signedData.GetSignature(),
	}

	// Set core EAT claims
	claims.Measurements = tdReport.GetMrTd()
	// Use first 32 bytes of MRTD as UEID, similar to other extractors
	if len(claims.Measurements) >= 32 {
		claims.UEID = claims.Measurements[:32]
	}
	claims.OEMID = OEMID_INTEL // Intel's PEN

	// Set hardware model
	claims.HWModel = []byte("Intel-TDX")

	return nil
}

// extractVTPMClaims extracts vTPM specific claims from binary report.
func extractVTPMClaims(claims *EATClaims, report []byte) error {
	if len(report) < 32 {
		return fmt.Errorf("vTPM report too short: got %d bytes, want at least 32", len(report))
	}
	// vTPM report is typically a marshaled structure containing PCRs and quote
	// For now, store the entire report as the quote
	claims.VTPMExtensions = &VTPMExtensions{
		Quote: report,
		PCRs:  make(map[string]string),
	}

	// Set core EAT claims
	claims.Measurements = report[:32] // Use first 32 bytes as measurement
	claims.UEID = report[:16]         // Use first 16 bytes as UEID

	return nil
}

// extractAzureClaims extracts Azure-specific claims from attestation token.
func extractAzureClaims(claims *EATClaims, report []byte) error {
	if len(report) < 32 {
		return fmt.Errorf("Azure report too short: got %d bytes, want at least 32", len(report))
	}
	// Azure provides JWT tokens, so the report is already in a structured format
	// For now, just store it as raw report
	claims.Measurements = report[:32] // Use first 32 bytes as measurement
	claims.UEID = report[:16]         // Use first 16 bytes as UEID
	claims.OEMID = OEMID_MICROSOFT    // Microsoft's PEN

	return nil
}
