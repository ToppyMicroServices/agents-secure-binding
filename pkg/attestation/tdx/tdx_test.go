// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/google/go-tdx-guest/proto/tdx"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name string
		want attestation.Provider
	}{
		{
			name: "should create new provider successfully",
			want: provider{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewProvider()
			assert.IsType(t, tt.want, got)
		})
	}
}

func tdxDeviceErrContains() string {
	if runtime.GOOS == "linux" {
		return "/sys/kernel/config/tsm/report"
	}
	return "unsupported"
}

func TestProvider_Attestation(t *testing.T) {
	tests := []struct {
		name        string
		teeNonce    []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should handle empty nonces",
			teeNonce:    []byte{},
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "invalid tee nonce length: expected 64 bytes, got 0 bytes",
		},
		{
			name:        "should handle valid nonces",
			teeNonce:    []byte("test-noncetest-noncetest-noncetest-noncetest-noncetest-noncetest"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: tdxDeviceErrContains(),
		},
		{
			name:        "should handle nil nonces",
			teeNonce:    nil,
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "tee nonce is required for TDX attestation",
		},
		{
			name:        "should handle large nonce",
			teeNonce:    make([]byte, 64),
			vTpmNonce:   make([]byte, 32),
			wantErr:     true,
			errContains: tdxDeviceErrContains(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.Attestation(tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestProvider_TeeAttestation(t *testing.T) {
	tests := []struct {
		name        string
		teeNonce    []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should handle empty nonce",
			teeNonce:    []byte{},
			wantErr:     true,
			errContains: "invalid tee nonce length: expected 64 bytes, got 0 bytes",
		},
		{
			name:        "should handle valid nonce",
			teeNonce:    []byte("test-noncetest-noncetest-noncetest-noncetest-noncetest-noncetest"),
			wantErr:     true,
			errContains: tdxDeviceErrContains(),
		},
		{
			name:        "should handle nil nonce",
			teeNonce:    nil,
			wantErr:     true,
			errContains: "tee nonce is required for TDX attestation",
		},
		{
			name:        "should handle 64-byte nonce",
			teeNonce:    make([]byte, 64),
			wantErr:     true,
			errContains: tdxDeviceErrContains(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.TeeAttestation(tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestProvider_VTpmAttestation(t *testing.T) {
	tests := []struct {
		name        string
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for empty nonce",
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
		{
			name:        "should return error for valid nonce",
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
		{
			name:        "should return error for nil nonce",
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.VTpmAttestation(tt.vTpmNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Nil(t, got)
		})
	}
}

func TestProvider_AzureAttestationToken(t *testing.T) {
	tests := []struct {
		name        string
		tokenNonce  []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for empty nonce",
			tokenNonce:  []byte{},
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
		{
			name:        "should return error for valid nonce",
			tokenNonce:  []byte("token-nonce"),
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
		{
			name:        "should return error for nil nonce",
			tokenNonce:  nil,
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.AzureAttestationToken(tt.tokenNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Nil(t, got)
		})
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "should create new verifier successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVerifier()
			v, ok := got.(verifier)
			assert.True(t, ok)
			assert.NotNil(t, v.Policy)
			assert.NotNil(t, v.Policy.RootOfTrust)
			assert.NotNil(t, v.Policy.Policy)
			assert.NotNil(t, v.Policy.Policy.HeaderPolicy)
			assert.NotNil(t, v.Policy.Policy.TdQuoteBodyPolicy)
		})
	}
}

func TestNewVerifierWithPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *checkconfig.Config
	}{
		{
			name:   "should create verifier with nil policy",
			policy: nil,
		},
		{
			name: "should create verifier with valid policy",
			policy: &checkconfig.Config{
				RootOfTrust: &checkconfig.RootOfTrust{},
				Policy:      &checkconfig.Policy{},
			},
		},
		{
			name:   "should create verifier with empty policy",
			policy: &checkconfig.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVerifierWithPolicy(tt.policy)
			v, ok := got.(verifier)
			assert.True(t, ok)

			if tt.policy == nil {
				assert.NotNil(t, v.Policy)
				assert.NotNil(t, v.Policy.RootOfTrust)
				assert.NotNil(t, v.Policy.Policy)
			} else {
				assert.Equal(t, tt.policy, v.Policy)
			}
		})
	}
}

func TestVerifier_VerifTeeAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		teeNonce    []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "should return error when policy is nil",
			verifier: verifier{
				Policy: nil,
			},
			report:      []byte("test-report"),
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "tdx policy is not provided",
		},
		{
			name: "should handle invalid report format",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte("invalid-report"),
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should handle empty report",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte{},
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should handle nil report",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      nil,
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifTeeAttestation(tt.report, tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyAttestationWithPolicyBindsReportData(t *testing.T) {
	quoteAny, err := abi.QuoteToProto(tdxtestdata.RawQuote)
	require.NoError(t, err)
	quote, ok := quoteAny.(*tdx.QuoteV4)
	require.True(t, ok)
	expected := append([]byte(nil), quote.GetTdQuoteBody().GetReportData()...)
	policy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy: &checkconfig.Policy{
			HeaderPolicy:      &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{},
		},
	}

	require.NoError(t, VerifyAttestationWithPolicy(tdxtestdata.RawQuote, expected, policy))
	expected[0] ^= 0xff
	err = VerifyAttestationWithPolicy(tdxtestdata.RawQuote, expected, policy)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REPORT_DATA")
}

func TestVerifier_VerifVTpmAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for any input",
			verifier:    verifier{},
			report:      []byte("test-report"),
			vTpmNonce:   []byte("test-nonce"),
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
		{
			name:        "should return error for empty inputs",
			verifier:    verifier{},
			report:      []byte{},
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
		{
			name:        "should return error for nil inputs",
			verifier:    verifier{},
			report:      nil,
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifVTpmAttestation(tt.report, tt.vTpmNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestVerifier_VerifyAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		teeNonce    []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "should delegate to VerifTeeAttestation with nil policy",
			verifier: verifier{
				Policy: nil,
			},
			report:      []byte("test-report"),
			teeNonce:    []byte("test-nonce"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "tdx policy is not provided",
		},
		{
			name: "should delegate to VerifTeeAttestation with valid policy",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte("invalid-report"),
			teeNonce:    []byte("test-nonce"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifyAttestation(tt.report, tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifier_JSONToPolicy(t *testing.T) {
	tempDir := t.TempDir()

	testPolicy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy: &checkconfig.Policy{
			HeaderPolicy:      &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{},
		},
	}

	validPolicyJSON, err := protojson.Marshal(testPolicy)
	require.NoError(t, err)

	validPolicyFile := filepath.Join(tempDir, "valid_policy.json")
	err = os.WriteFile(validPolicyFile, validPolicyJSON, 0o644)
	require.NoError(t, err)

	invalidPolicyFile := filepath.Join(tempDir, "invalid_policy.json")
	err = os.WriteFile(invalidPolicyFile, []byte("invalid json"), 0o644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		verifier    verifier
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name: "should load valid policy file",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:    validPolicyFile,
			wantErr: false,
		},
		{
			name: "should return error for non-existent file",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        filepath.Join(tempDir, "non_existent.json"),
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name: "should return error for invalid JSON",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        invalidPolicyFile,
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should return error for empty path",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        "",
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.JSONToPolicy(tt.path)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadTDXAttestationPolicy(t *testing.T) {
	tempDir := t.TempDir()

	testPolicy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy: &checkconfig.Policy{
			HeaderPolicy:      &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{},
		},
	}

	validPolicyJSON, err := protojson.Marshal(testPolicy)
	require.NoError(t, err)

	validPolicyFile := filepath.Join(tempDir, "valid_policy.json")
	err = os.WriteFile(validPolicyFile, validPolicyJSON, 0o644)
	require.NoError(t, err)

	invalidPolicyFile := filepath.Join(tempDir, "invalid_policy.json")
	err = os.WriteFile(invalidPolicyFile, []byte("invalid json"), 0o644)
	require.NoError(t, err)

	emptyFile := filepath.Join(tempDir, "empty.json")
	err = os.WriteFile(emptyFile, []byte{}, 0o644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		policyPath  string
		policy      *checkconfig.Config
		wantErr     bool
		errContains string
	}{
		{
			name:       "should read valid policy file",
			policyPath: validPolicyFile,
			policy:     &checkconfig.Config{},
			wantErr:    false,
		},
		{
			name:        "should return error for non-existent file",
			policyPath:  filepath.Join(tempDir, "non_existent.json"),
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:        "should return error for invalid JSON",
			policyPath:  invalidPolicyFile,
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "should return error for empty file",
			policyPath:  emptyFile,
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "should return error for empty path",
			policyPath:  "",
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ReadTDXAttestationPolicy(tt.policyPath, tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.policy)
			}
		})
	}
}

func tdxCoRIMTestQuote(t *testing.T) ([]byte, *tdx.TDQuoteBody) {
	t.Helper()
	report := append([]byte(nil), tdxtestdata.RawQuote...)
	parsed, err := abi.QuoteToProto(report)
	require.NoError(t, err)
	quoteV4, ok := parsed.(*tdx.QuoteV4)
	require.True(t, ok)
	require.NotNil(t, quoteV4.GetTdQuoteBody())
	return report, quoteV4.GetTdQuoteBody()
}

func tdxCoRIMMeasurement(t *testing.T, key uint64, digest []byte) comid.Measurement {
	t.Helper()
	measurement, err := comid.NewUintMeasurement(key)
	require.NoError(t, err)
	require.NotNil(t, measurement.AddDigest(swid.Sha384, append([]byte(nil), digest...)))
	return *measurement
}

func allTDXCoRIMMeasurements(t *testing.T, body *tdx.TDQuoteBody) []comid.Measurement {
	t.Helper()
	measurements := []comid.Measurement{
		tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd()),
		tdxCoRIMMeasurement(t, corimgen.TDXMRSEAMMKey, body.GetMrSeam()),
	}
	require.Len(t, body.GetRtmrs(), 4)
	for index, rtmr := range body.GetRtmrs() {
		measurements = append(measurements, tdxCoRIMMeasurement(t, corimgen.TDXRTMR0MKey+uint64(index), rtmr))
	}
	return measurements
}

func tdxCoRIMManifest(measurements ...comid.Measurement) *corim.UnsignedCorim {
	tag := comid.NewComid().
		SetTagIdentity("tdx-test-tag", 0).
		AddReferenceValue(comid.ReferenceValue{
			Environment: comid.Environment{
				Class:    comid.NewClassOID(comid.TestOID),
				Instance: comid.MustNewUEIDInstance(comid.TestUEID),
			},
			Measurements: measurements,
		})
	manifest := corim.NewUnsignedCorim()
	manifest.AddComid(*tag)
	return manifest
}

func TestVerifier_VerifyWithCoRIM(t *testing.T) {
	v := verifier{}

	err := v.VerifyWithCoRIM([]byte("small"), &corim.UnsignedCorim{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse TDX quote")

	report, body := tdxCoRIMTestQuote(t)
	err = v.VerifyWithCoRIM(report, &corim.UnsignedCorim{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing the required MRTD")

	err = v.VerifyWithCoRIM(report, &corim.UnsignedCorim{
		Tags: []corim.Tag{corim.Tag("not-a-comid")},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing the required MRTD")

	err = v.VerifyWithCoRIM(report, &corim.UnsignedCorim{
		Tags: []corim.Tag{append(corim.ComidTag, []byte("invalid")...)},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CoMID from tag")

	require.NoError(t, v.VerifyWithCoRIM(report, tdxCoRIMManifest(
		tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd()),
	)))
	require.NoError(t, v.VerifyWithCoRIM(report, tdxCoRIMManifest(allTDXCoRIMMeasurements(t, body)...)))
}

func TestVerifier_VerifyWithGeneratedTDXCoRIM(t *testing.T) {
	report, body := tdxCoRIMTestQuote(t)
	rtmrs := make([]string, 0, len(body.GetRtmrs()))
	for _, rtmr := range body.GetRtmrs() {
		rtmrs = append(rtmrs, hex.EncodeToString(rtmr))
	}
	payload, err := corimgen.GenerateCoRIM(corimgen.Options{
		Platform:    "tdx",
		Measurement: hex.EncodeToString(body.GetMrTd()),
		MrSeam:      hex.EncodeToString(body.GetMrSeam()),
		RTMRs:       strings.Join(rtmrs, ","),
	})
	require.NoError(t, err)

	var manifest corim.UnsignedCorim
	require.NoError(t, manifest.FromCBOR(payload))
	require.NoError(t, (verifier{}).VerifyWithCoRIM(report, &manifest))
}

func TestVerifier_VerifyWithCoRIMRejectsFieldMismatch(t *testing.T) {
	v := verifier{}
	report, body := tdxCoRIMTestQuote(t)
	tests := []struct {
		name             string
		measurementIndex int
		field            string
	}{
		{name: "mrtd", measurementIndex: 0, field: "MRTD"},
		{name: "mrseam", measurementIndex: 1, field: "MRSEAM"},
		{name: "rtmr0", measurementIndex: 2, field: "RTMR0"},
		{name: "rtmr1", measurementIndex: 3, field: "RTMR1"},
		{name: "rtmr2", measurementIndex: 4, field: "RTMR2"},
		{name: "rtmr3", measurementIndex: 5, field: "RTMR3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			measurements := allTDXCoRIMMeasurements(t, body)
			digest := (*measurements[test.measurementIndex].Val.Digests)[0].HashValue
			digest[0] ^= 0xff
			err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(measurements...))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.field+" measurement does not match")
		})
	}
}

func TestVerifier_VerifyWithCoRIMDoesNotTreatOtherFieldsAsMRTD(t *testing.T) {
	v := verifier{}
	report, body := tdxCoRIMTestQuote(t)
	for _, test := range []struct {
		name  string
		key   uint64
		field string
	}{
		{name: "mrseam", key: corimgen.TDXMRSEAMMKey, field: "MRSEAM"},
		{name: "rtmr0", key: corimgen.TDXRTMR0MKey, field: "RTMR0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := tdxCoRIMManifest(tdxCoRIMMeasurement(t, test.key, body.GetMrTd()))
			err := v.VerifyWithCoRIM(report, manifest)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.field+" measurement does not match")
		})
	}
}

func TestVerifier_VerifyWithCoRIMRejectsInvalidKeys(t *testing.T) {
	v := verifier{}
	report, body := tdxCoRIMTestQuote(t)
	mrtd := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())

	t.Run("unknown", func(t *testing.T) {
		unknown := tdxCoRIMMeasurement(t, corimgen.TDXRTMR0MKey+4, body.GetMrTd())
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(mrtd, unknown))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown TDX CoRIM measurement key")
	})

	t.Run("duplicate", func(t *testing.T) {
		duplicate := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(mrtd, duplicate))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate TDX CoRIM measurement key")
	})

	t.Run("unkeyed", func(t *testing.T) {
		unkeyed := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())
		unkeyed.Key = nil
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(unkeyed))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "measurement key is required")
	})

	t.Run("non-integer", func(t *testing.T) {
		nonInteger := *comid.MustNewUUIDMeasurement(comid.TestUUID).AddDigest(swid.Sha384, body.GetMrTd())
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(mrtd, nonInteger))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be an unsigned integer")
	})
}

func TestVerifier_VerifyWithCoRIMRejectsMultipleReferenceProfiles(t *testing.T) {
	report, body := tdxCoRIMTestQuote(t)
	measurement := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())
	reference := comid.ReferenceValue{
		Environment:  comid.Environment{Class: comid.NewClassOID(comid.TestOID)},
		Measurements: comid.Measurements{measurement},
	}
	tag := comid.NewComid().
		SetTagIdentity("tdx-multiple-reference-values", 0).
		AddReferenceValue(reference).
		AddReferenceValue(reference)
	manifest := corim.NewUnsignedCorim()
	manifest.AddComid(*tag)

	err := (verifier{}).VerifyWithCoRIM(report, manifest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one reference-value profile")
}

func TestVerifier_VerifyWithCoRIMRejectsUnsupportedValuesAndDigests(t *testing.T) {
	v := verifier{}
	report, body := tdxCoRIMTestQuote(t)

	t.Run("svn", func(t *testing.T) {
		measurement := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())
		measurement.SetSVN(1)
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(measurement))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported measurement values")
	})

	t.Run("multiple digests", func(t *testing.T) {
		measurement := tdxCoRIMMeasurement(t, corimgen.TDXMRTDMKey, body.GetMrTd())
		second := append([]byte(nil), body.GetMrTd()...)
		second[0] ^= 0xff
		require.NotNil(t, measurement.AddDigest(swid.Sha384, second))
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(measurement))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one digest")
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		measurement := comid.MustNewUintMeasurement(corimgen.TDXMRTDMKey)
		require.NotNil(t, measurement.AddDigest(swid.Sha3_384, body.GetMrTd()))
		err := v.VerifyWithCoRIM(report, tdxCoRIMManifest(*measurement))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must use SHA-384")
	})
}

func TestVerifier_VerifyEAT(t *testing.T) {
	v := verifier{}

	// Invalid EAT token
	err := v.VerifyEAT([]byte("invalid"), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode EAT token")
}

func TestVerifier_VerifVTpmAttestation_Error(t *testing.T) {
	v := verifier{}
	err := v.VerifVTpmAttestation(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VTPM attestation verification is not supported")
}
