// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
	"google.golang.org/protobuf/proto"
)

func TestDecodeCachedSEVCertificateChainPreservesASKARKOrder(t *testing.T) {
	vcek := []byte("vcek-der")
	ask := []byte("ask-der")
	ark := []byte("ark-der")
	encode := func(value []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: value})
	}

	chain, err := decodeCachedSEVCertificateChain(
		encode(vcek),
		append(encode(ask), encode(ark)...),
	)
	require.NoError(t, err)
	assert.Equal(t, vcek, chain.GetVcekCert())
	assert.Equal(t, ask, chain.GetAskCert())
	assert.Equal(t, ark, chain.GetArkCert())

	_, err = decodeCachedSEVCertificateChain([]byte("not PEM"), append(encode(ask), encode(ark)...))
	assert.Error(t, err)
	_, err = decodeCachedSEVCertificateChain(encode(vcek), encode(ask))
	assert.Error(t, err)
}

type mockTPM struct {
	*bytes.Buffer
	closeErr error
}

func (m *mockTPM) Close() error {
	return m.closeErr
}

type errorRWC struct {
	DummyRWC
}

func (e *errorRWC) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func (e *errorRWC) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("read error")
}

type mockWriter struct {
	data []byte
	err  error
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	m.data = append(m.data, p...)
	return len(p), nil
}

func TestOpenTpm(t *testing.T) {
	tests := []struct {
		name        string
		externalTPM io.ReadWriteCloser
		expectError bool
	}{
		{
			name:        "External TPM available",
			externalTPM: &mockTPM{Buffer: &bytes.Buffer{}},
			expectError: false,
		},
		{
			name:        "No external TPM",
			externalTPM: nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalExternalTPM := ExternalTPM
			defer func() { ExternalTPM = originalExternalTPM }()

			ExternalTPM = tt.externalTPM

			tpm, err := OpenTpm()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				if tt.externalTPM != nil {
					assert.NoError(t, err)
					assert.NotNil(t, tpm)
				}
			}
		})
	}
}

func TestTpmEventLog(t *testing.T) {
	tempFile, err := os.CreateTemp("", "event_log")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	testData := []byte("test event log data")
	_, err = tempFile.Write(testData)
	require.NoError(t, err)
	tempFile.Close()

	tpm := &tpm{ReadWriteCloser: &mockTPM{Buffer: &bytes.Buffer{}}}

	_, err = tpm.EventLog()
	assert.Error(t, err)
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name           string
		teeAttestation bool
		vmpl           uint
	}{
		{
			name:           "TEE attestation enabled",
			teeAttestation: true,
			vmpl:           1,
		},
		{
			name:           "TEE attestation disabled",
			teeAttestation: false,
			vmpl:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(tt.teeAttestation, tt.vmpl)
			assert.NotNil(t, provider)
		})
	}
}

func TestProviderAzureAttestationToken(t *testing.T) {
	provider := NewProvider(false, 0)

	token, err := provider.AzureAttestationToken([]byte("test-nonce"))
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "Azure attestation token is not supported")
}

func TestNewVerifier(t *testing.T) {
	writer := &mockWriter{}
	verifier := NewVerifier(writer)

	assert.NotNil(t, verifier)
}

func TestMarshalQuote(t *testing.T) {
	tests := []struct {
		name        string
		attestation *attest.Attestation
		expectError bool
	}{
		{
			name: "Valid attestation",
			attestation: &attest.Attestation{
				AkPub: []byte("test-key"),
			},
			expectError: false,
		},
		{
			name:        "Nil attestation",
			attestation: nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := marshalQuote(tt.attestation)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, data)
			} else {
				assert.NoError(t, err)
				if tt.attestation != nil {
					assert.NotEmpty(t, data)
				}
			}
		})
	}
}

func TestAttest(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &mockTPM{Buffer: &bytes.Buffer{}}

	_, err := Attest([]byte("tee-nonce"), []byte("vtpm-nonce"), false, 0)
	assert.Error(t, err)
}

func TestExtendPCR(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &errorRWC{}

	err := ExtendPCR(PCR16, []byte("test-value"))
	assert.Error(t, err)
}

func TestGetPCRValue(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &DummyRWC{}

	val, err := GetPCRSHA1Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)

	val, err = GetPCRSHA256Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)

	val, err = GetPCRSHA384Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)
}

func TestVerifier_VerifyWithCoRIM(t *testing.T) {
	v := NewVerifier(&mockWriter{})

	// 1. Invalid report
	err := v.VerifyWithCoRIM([]byte("invalid"), &corim.UnsignedCorim{})
	assert.Error(t, err)

	// 2. Missing SEV-SNP attestation
	att := &attest.Attestation{}
	reportBytes, _ := proto.Marshal(att)
	err = v.VerifyWithCoRIM(reportBytes, &corim.UnsignedCorim{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SEV-SNP attestation found")

	// 3. No measurement in report
	att = &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{},
			},
		},
	}
	reportBytes, _ = proto.Marshal(att)
	err = v.VerifyWithCoRIM(reportBytes, &corim.UnsignedCorim{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no measurement in SEV-SNP report")

	// 4. Successful match
	measurement := make([]byte, 48)
	att = &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{
					Measurement: measurement,
				},
			},
		},
	}
	reportBytes, _ = proto.Marshal(att)

	// Create a mock CoMID with the same measurement
	c := comid.NewComid().
		SetTagIdentity("vtpm-test-tag", 0).
		AddReferenceValue(comid.ReferenceValue{
			Environment: comid.Environment{
				Class:    comid.NewClassOID(comid.TestOID),
				Instance: comid.MustNewUEIDInstance(comid.TestUEID),
			},
			Measurements: *comid.NewMeasurements().
				AddMeasurement(comid.MustNewUintMeasurement(corimgen.SNPMeasurementMKey).AddDigest(swid.Sha384, measurement)),
		})

	unsignedCorim := corim.NewUnsignedCorim()
	unsignedCorim.AddComid(*c)

	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.NoError(t, err)

	// 5. CoRIM with no tags
	unsignedCorim.Tags = nil
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching reference value found in CoRIM for SNP")

	// 6. Non-CoMID tag
	unsignedCorim.Tags = []corim.Tag{corim.Tag([]byte("non-comid-tag"))}
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching reference value found in CoRIM for SNP")

	// 7. Invalid CoMID tag
	unsignedCorim.Tags = []corim.Tag{corim.Tag(append(corim.ComidTag, []byte("invalid")...))}
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CoMID from tag")
}

func TestVerifierVerifyWithCoRIMEnforcesKeyedSNPConstraints(t *testing.T) {
	report := &sevsnp.Report{
		Measurement: bytes.Repeat([]byte{0x11}, Hash384),
		HostData:    bytes.Repeat([]byte{0x22}, Hash256),
		Policy:      0x30000,
		GuestSvn:    3,
		LaunchTcb:   0x0202,
	}
	primary := comid.MustNewUintMeasurement(corimgen.SNPMeasurementMKey).
		AddDigest(swid.Sha384, report.GetMeasurement()).
		SetSVN(uint64(report.GetGuestSvn()))
	manifest := testSNPManifest(t,
		primary,
		testRawMeasurement(t, corimgen.SNPHostDataMKey, report.GetHostData()),
		testRawUint64Measurement(t, corimgen.SNPPolicyMKey, report.GetPolicy()),
		testRawUint64Measurement(t, corimgen.SNPMinimumLaunchTCBMKey, 0x0101),
	)

	verifier := NewVerifier(nil)
	if err := verifier.VerifyWithCoRIM(testWrappedSNPReport(t, report), manifest); err != nil {
		t.Fatalf("VerifyWithCoRIM() error = %v", err)
	}

	mutations := map[string]func(*sevsnp.Report){
		"measurement": func(r *sevsnp.Report) { r.Measurement[0] ^= 0xff },
		"host data":   func(r *sevsnp.Report) { r.HostData[0] ^= 0xff },
		"policy":      func(r *sevsnp.Report) { r.Policy ^= 1 },
		"guest SVN":   func(r *sevsnp.Report) { r.GuestSvn-- },
		"launch TCB":  func(r *sevsnp.Report) { r.LaunchTcb = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := proto.Clone(report).(*sevsnp.Report)
			mutate(changed)
			if err := verifier.VerifyWithCoRIM(testWrappedSNPReport(t, changed), manifest); err == nil {
				t.Fatal("VerifyWithCoRIM() accepted a mismatched keyed constraint")
			}
		})
	}

	unkeyed := testSNPManifest(t,
		comid.MustNewUUIDMeasurement(comid.TestUUID).AddDigest(swid.Sha384, report.GetMeasurement()),
	)
	if err := verifier.VerifyWithCoRIM(testWrappedSNPReport(t, report), unkeyed); err == nil {
		t.Fatal("VerifyWithCoRIM() accepted an unkeyed digest")
	}

	authorized := *primary
	authorized.AuthorizedBy = &comid.CryptoKey{}
	if _, err := matchSNPReferenceValue(report, comid.Measurements{authorized}); err == nil {
		t.Fatal("matchSNPReferenceValue() accepted unsupported authorized-by metadata")
	}
}

func testSNPManifest(t *testing.T, measurements ...*comid.Measurement) *corim.UnsignedCorim {
	t.Helper()
	values := comid.Measurements{}
	for _, measurement := range measurements {
		values = append(values, *measurement)
	}
	tag := comid.NewComid().
		SetTagIdentity("snp-keyed-test", 0).
		AddReferenceValue(comid.ReferenceValue{
			Environment:  comid.Environment{Class: comid.NewClassOID(comid.TestOID)},
			Measurements: values,
		})
	manifest := corim.NewUnsignedCorim()
	manifest.AddComid(*tag)
	return manifest
}

func testRawMeasurement(t *testing.T, key uint64, value []byte) *comid.Measurement {
	t.Helper()
	measurement, err := comid.NewUintMeasurement(key)
	require.NoError(t, err)
	require.NotNil(t, measurement.SetRawValueBytes(value, nil))
	return measurement
}

func testRawUint64Measurement(t *testing.T, key, value uint64) *comid.Measurement {
	t.Helper()
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, value)
	return testRawMeasurement(t, key, raw)
}

func testWrappedSNPReport(t *testing.T, report *sevsnp.Report) []byte {
	t.Helper()
	payload, err := proto.Marshal(&attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{Report: report},
		},
	})
	require.NoError(t, err)
	return payload
}
