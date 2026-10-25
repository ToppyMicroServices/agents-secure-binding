// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevtesting "github.com/google/go-sev-guest/testing"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestExtractSNPClaims(t *testing.T) {
	validReport := make([]byte, abi.ReportSize)
	validReport[0] = 2
	validReport[10] = 0x2 // Policy bit 17 set (byte 2 of Policy, bit 1)

	tests := []struct {
		name        string
		report      []byte
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "valid report size (minimal)",
			report:  validReport,
			wantErr: false,
		},
		{
			name:        "report too small",
			report:      make([]byte, abi.ReportSize-1),
			wantErr:     true,
			expectedErr: "failed to parse SNP report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &EATClaims{}
			err := extractSNPClaims(claims, tt.report)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims.SNPExtensions)
				assert.Equal(t, OEMID_AMD, claims.OEMID)
				assert.Equal(t, []byte(fmt.Sprintf("SEV-SNP-%d", 2)), claims.HWModel)
			}
		})
	}
}

func TestExtractSNPClaimsAcceptsDirectProviderProtobuf(t *testing.T) {
	var reportData [abi.ReportDataSize]byte
	raw := sevtesting.TestRawReport(reportData)
	snpAttestation, err := abi.ReportCertsToProto(raw[:abi.ReportSize])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		withCert bool
	}{
		{name: "report only"},
		{name: "report with certificate chain", withCert: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := proto.Clone(snpAttestation).(*sevsnp.Attestation)
			if tc.withCert {
				evidence.CertificateChain.VcekCert = make([]byte, abi.ReportSize)
			}
			encoded, err := proto.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			if tc.withCert && len(encoded) < abi.ReportSize {
				t.Fatal("test did not cover a protobuf longer than an ABI report")
			}
			claims, err := NewEATClaims(encoded, []byte("12345678"), attestation.SNP)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, encoded, claims.RawReport)
			assert.Equal(t, evidence.GetReport().GetMeasurement(), claims.Measurements)
			assert.NotNil(t, claims.SNPExtensions)
		})
	}
}

func TestExtractSNPClaimsRejectsIncompleteProtobuf(t *testing.T) {
	encoded, err := proto.Marshal(&sevsnp.Attestation{Report: &sevsnp.Report{Version: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEATClaims(encoded, []byte("12345678"), attestation.SNP); err == nil {
		t.Fatal("accepted structurally incomplete SNP protobuf")
	}
}

func TestExtractSNPvTPMClaimsRequiresCombinedEvidence(t *testing.T) {
	var reportData [abi.ReportDataSize]byte
	raw := sevtesting.TestRawReport(reportData)
	snp, err := abi.ReportCertsToProto(raw[:abi.ReportSize])
	if err != nil {
		t.Fatal(err)
	}
	combined := &attest.Attestation{
		AkPub:  []byte("attestation-key"),
		Quotes: []*tpm.Quote{{Quote: []byte("quote")}},
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: snp,
		},
	}
	for _, tc := range []struct {
		name    string
		change  func(*attest.Attestation)
		wantErr string
	}{
		{name: "valid combined evidence"},
		{name: "missing attestation key", change: func(a *attest.Attestation) { a.AkPub = nil }, wantErr: "attestation key"},
		{name: "missing quote", change: func(a *attest.Attestation) { a.Quotes = nil }, wantErr: "vTPM quote"},
		{name: "missing SNP", change: func(a *attest.Attestation) { a.TeeAttestation = nil }, wantErr: "SEV-SNP attestation"},
		{name: "invalid SNP", change: func(a *attest.Attestation) {
			a.TeeAttestation = &attest.Attestation_SevSnpAttestation{
				SevSnpAttestation: &sevsnp.Attestation{Report: &sevsnp.Report{Version: 2}},
			}
		}, wantErr: "invalid embedded SNP report"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := proto.Clone(combined).(*attest.Attestation)
			if tc.change != nil {
				tc.change(evidence)
			}
			encoded, err := proto.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := NewEATClaims(encoded, []byte("12345678"), attestation.SNPvTPM)
			if tc.wantErr != "" {
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, encoded, claims.RawReport)
			assert.Equal(t, "SNP-vTPM", claims.PlatformType)
			assert.Equal(t, snp.GetReport().GetMeasurement(), claims.Measurements)
			assert.NotNil(t, claims.SNPExtensions)
		})
	}

	direct, err := proto.Marshal(snp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEATClaims(direct, []byte("12345678"), attestation.SNPvTPM); err == nil {
		t.Fatal("accepted direct SNP evidence as SNP-vTPM")
	}
}

func TestExtractTDXClaims(t *testing.T) {
	report := []byte("invalid-tdx-quote")
	claims := &EATClaims{}
	err := extractTDXClaims(claims, report)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse TDX quote")
}

func TestTDXExtensionsJSON(t *testing.T) {
	ext := &TDXExtensions{
		MRTD:         []byte("mrtd_val"),
		RTMR0:        []byte("rtmr0_val"),
		RTMR1:        []byte("rtmr1_val"),
		RTMR2:        []byte("rtmr2_val"),
		RTMR3:        []byte("rtmr3_val"),
		XFAM:         123,
		TDAttributes: 456,
		TDXModule: &TDXModuleInfo{
			Major: 1,
		},
	}

	claims := &EATClaims{
		TDXExtensions: ext,
	}

	// Marshal to JSON
	data, err := json.Marshal(claims)
	assert.NoError(t, err)

	// Verify JSON keys match Intel EAT profile
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"tdx_mrtd":"bXJ0ZF92YWw="`)
	assert.Contains(t, jsonStr, `"tdx_rtmr0":"cnRtcjBfdmFs"`) // base64 of "rtmr0_val"
	assert.Contains(t, jsonStr, `"tdx_rtmr1":"cnRtcjFfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_rtmr2":"cnRtcjJfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_rtmr3":"cnRtcjNfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_xfam":123`)
	assert.Contains(t, jsonStr, `"tdx_td_attributes":456`)
	assert.Contains(t, jsonStr, `"tdx_module":{"major":1,"minor":0,"build_num":0,"build_date":0}`)
}

func TestExtractVTPMClaims(t *testing.T) {
	report := make([]byte, 32)
	copy(report, []byte("vtpm-report-with-enough-length-123"))

	claims := &EATClaims{}
	err := extractVTPMClaims(claims, report)
	assert.NoError(t, err)
	assert.NotNil(t, claims.VTPMExtensions)
	assert.Equal(t, report, claims.VTPMExtensions.Quote)
	assert.Equal(t, report[:32], claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
}

func TestNewEATClaimsRejectsShortVTPMAndAzureReports(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform attestation.PlatformType
	}{
		{name: "vTPM", platform: attestation.VTPM},
		{name: "Azure", platform: attestation.Azure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for size := 1; size <= 32; size++ {
				claims, err := NewEATClaims(make([]byte, size), []byte("12345678"), tc.platform)
				if size < 32 {
					if err == nil || claims != nil {
						t.Fatalf("accepted %d-byte report: claims=%+v, err=%v", size, claims, err)
					}
					continue
				}
				if err != nil || claims == nil || len(claims.Measurements) != 32 {
					t.Fatalf("rejected 32-byte report: claims=%+v, err=%v", claims, err)
				}
			}
		})
	}
}

func TestExtractAzureClaims(t *testing.T) {
	report := make([]byte, 32) // Needs at least 32 bytes for valid slicing
	for i := range report {
		report[i] = byte(i)
	}
	claims := &EATClaims{}
	err := extractAzureClaims(claims, report)
	assert.NoError(t, err)
	assert.Equal(t, report, claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
	assert.Equal(t, OEMID_MICROSOFT, claims.OEMID)
}

// Platform type helper.
func TestGetPlatformTypeName(t *testing.T) {
	tests := []struct {
		pt   attestation.PlatformType
		want string
	}{
		{attestation.SNP, "SNP"},
		{attestation.SNPvTPM, "SNP-vTPM"},
		{attestation.TDX, "TDX"},
		{attestation.VTPM, "vTPM"},
		{attestation.Azure, "Azure"},
		{attestation.NoCC, "NoCC"},
		{attestation.PlatformType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, getPlatformTypeName(tt.pt))
		})
	}
}
