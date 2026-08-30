// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package corimgen

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
)

func TestGenerateCoRIM_SNP_Unsigned(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: strings.Repeat("ab", 48),
		Product:     "Milan",
		SVN:         1,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid CBOR CoRIM
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_TDX_Unsigned(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		// Will use defaults
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid CBOR CoRIM
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_WithDefaults(t *testing.T) {
	opts := Options{
		Platform: "snp",
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)

	// Decode and verify default measurement was used
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)

	// Verify CoRIM was created successfully
	assert.NotEmpty(t, unsignedCorim.GetID())
}

func TestGenerateCoRIM_InvalidMeasurement(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode measurement")
}

func TestGenerateCoRIM_RejectsWrongMeasurementLength(t *testing.T) {
	_, err := GenerateCoRIM(Options{
		Platform:    "snp",
		Measurement: "abc123",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "48 bytes")
}

func TestGenerateCoRIM_UsesSHA384ForSNPMeasurement(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, 48)
	corimBytes, err := GenerateCoRIM(Options{
		Platform:    "snp",
		Measurement: strings.Repeat("ab", 48),
	})
	require.NoError(t, err)

	var manifest corim.UnsignedCorim
	require.NoError(t, manifest.FromCBOR(corimBytes))
	require.Len(t, manifest.Tags, 1)
	require.True(t, bytes.HasPrefix(manifest.Tags[0], corim.ComidTag))

	var tag comid.Comid
	require.NoError(t, tag.FromCBOR(manifest.Tags[0][len(corim.ComidTag):]))
	require.NotNil(t, tag.Triples.ReferenceValues)
	require.Len(t, *tag.Triples.ReferenceValues, 1)
	measurements := (*tag.Triples.ReferenceValues)[0].Measurements
	require.Len(t, measurements, 1)
	key, err := measurements[0].Key.GetKeyUint()
	require.NoError(t, err)
	assert.Equal(t, SNPMeasurementMKey, key)
	require.NotNil(t, measurements[0].Val.Digests)
	require.Len(t, *measurements[0].Val.Digests, 1)
	assert.Equal(t, swid.Sha384, (*measurements[0].Val.Digests)[0].HashAlgID)
	assert.Equal(t, want, (*measurements[0].Val.Digests)[0].HashValue)
}

func TestApplyDefaults_SNP(t *testing.T) {
	opts := Options{
		Platform: "snp",
	}

	applyDefaults(&opts)

	assert.Equal(t, SNPDefaultMeasurement, opts.Measurement)
}

func TestApplyDefaults_TDX(t *testing.T) {
	opts := Options{
		Platform: "tdx",
	}

	applyDefaults(&opts)

	assert.Equal(t, TDXDefaultMrTd, opts.Measurement)
	assert.Equal(t, TDXDefaultMrSeam, opts.MrSeam)
	assert.NotEmpty(t, opts.RTMRs)
}

func TestGenerateCoRIM_TDX_WithRTMRs(t *testing.T) {
	rtmr1 := "ce0891f46a18db93e7691f1cf73ed76593f7dec1b58f0927ccb56a99242bf63bc9551561f9ee7833d40395fae59547ab"
	rtmr2 := "062ac322e26b10874a84977a09735408a856aec77ff62b4975b1e90e33c18f05220ea522cdbffc3b2cf4451cc209e418"

	opts := Options{
		Platform:    "tdx",
		Measurement: TDXDefaultMrTd,
		MrSeam:      TDXDefaultMrSeam,
		RTMRs:       rtmr1 + "," + rtmr2,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)

	// Verify it's valid
	var unsignedCorim corim.UnsignedCorim
	err = unsignedCorim.FromCBOR(corimBytes)
	require.NoError(t, err)
	measurements := referenceMeasurements(t, &unsignedCorim)
	assert.Equal(t, []uint64{TDXMRTDMKey, TDXMRSEAMMKey, TDXRTMR0MKey, TDXRTMR0MKey + 1}, measurementKeys(t, measurements))
}

func TestGenerateCoRIM_SNP_WithHostData(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: strings.Repeat("ab", 48),
		Policy:      0x30000,
		HostData:    strings.Repeat("cd", 32),
		LaunchTCB:   1,
		SVN:         1,
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	require.NotEmpty(t, corimBytes)
	var manifest corim.UnsignedCorim
	require.NoError(t, manifest.FromCBOR(corimBytes))
	measurements := referenceMeasurements(t, &manifest)
	assert.Equal(t, []uint64{SNPMeasurementMKey, SNPHostDataMKey, SNPPolicyMKey, SNPMinimumLaunchTCBMKey}, measurementKeys(t, measurements))
	hostData, err := measurements[1].Val.RawValue.GetBytes()
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{0xcd}, 32), hostData)
	policy, err := measurements[2].Val.RawValue.GetBytes()
	require.NoError(t, err)
	assert.Equal(t, uint64(0x30000), binary.LittleEndian.Uint64(policy))
}

func TestGenerateCoRIMRejectsUnenforceableInputs(t *testing.T) {
	_, err := GenerateCoRIM(Options{Platform: "snp", HostData: "deadbeef"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HOST_DATA must be 32 bytes")

	_, err = GenerateCoRIM(Options{Platform: "tdx", SVN: 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scalar SVN is unsupported")

	_, err = GenerateCoRIM(Options{
		Platform: "tdx",
		RTMRs: strings.Join([]string{
			strings.Repeat("00", 48), strings.Repeat("01", 48), strings.Repeat("02", 48),
			strings.Repeat("03", 48), strings.Repeat("04", 48),
		}, ","),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at most 4 RTMR")
}

func TestGenerateCoRIM_TDX_InvalidMrSeam(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		MrSeam:   "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode MRSEAM")
}

func TestGenerateCoRIM_TDX_InvalidRTMR(t *testing.T) {
	opts := Options{
		Platform: "tdx",
		RTMRs:    "invalid-hex",
	}

	_, err := GenerateCoRIM(opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode RTMR")
}

func TestGenerateCoRIM_WithSigning(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	payload, err := GenerateCoRIM(Options{
		Platform:   "snp",
		SigningKey: key,
	})
	require.NoError(t, err)

	var signed corim.SignedCorim
	require.NoError(t, signed.FromCOSE(payload))
	require.NoError(t, signed.Meta.Valid())
	require.NoError(t, signed.Verify(&key.PublicKey))
}

func referenceMeasurements(t *testing.T, manifest *corim.UnsignedCorim) comid.Measurements {
	t.Helper()
	require.NotNil(t, manifest)
	require.Len(t, manifest.Tags, 1)
	require.True(t, bytes.HasPrefix(manifest.Tags[0], corim.ComidTag))
	var tag comid.Comid
	require.NoError(t, tag.FromCBOR(manifest.Tags[0][len(corim.ComidTag):]))
	require.NotNil(t, tag.Triples.ReferenceValues)
	require.Len(t, *tag.Triples.ReferenceValues, 1)
	return (*tag.Triples.ReferenceValues)[0].Measurements
}

func measurementKeys(t *testing.T, measurements comid.Measurements) []uint64 {
	t.Helper()
	keys := make([]uint64, len(measurements))
	for i := range measurements {
		key, err := measurements[i].Key.GetKeyUint()
		require.NoError(t, err)
		keys[i] = key
	}
	return keys
}
