// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/gcp"
	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewAttestationPolicyCmd(t *testing.T) {
	c := &CLI{}
	cmd := c.NewAttestationPolicyCmd()

	assert.Equal(t, "policy", cmd.Use)
	assert.Equal(t, "Change attestation policy", cmd.Short)
	assert.NotNil(t, cmd.Run)
}

func TestCLI_NewDownloadGCPOvmfFile(t *testing.T) {
	t.Chdir(t.TempDir())
	oldNewStorageClient := gcp.NewStorageClient
	t.Cleanup(func() { gcp.NewStorageClient = oldNewStorageClient })

	// This fixture tests the download checksum boundary, not hardware appraisal.
	reportBytes := make([]byte, abi.ReportSize)
	binary.LittleEndian.PutUint32(reportBytes[:4], abi.ReportVersion2)
	binary.LittleEndian.PutUint64(reportBytes[8:16], abi.SnpPolicyToBytes(abi.SnpPolicy{}))
	report, err := abi.ReportToProto(reportBytes)
	require.NoError(t, err)
	att := &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{Report: report},
		},
	}
	attestationBytes, err := proto.Marshal(att)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile("attestation.bin", attestationBytes, 0o600))
	firmware := []byte("firmware checksum fixture")
	validDigest := sha512.Sum384(firmware)

	for _, test := range []struct {
		name   string
		path   string
		match  bool
		output string
	}{
		{"missing attestation", "missing.bin", false, "Error reading attestation report file"},
		{"checksum mismatch", "attestation.bin", false, "Error OVMF file does not match"},
		{"verified download", "attestation.bin", true, "OVMF file downloaded successfully"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gcp.NewStorageClient = func(context.Context) (gcp.StorageClient, error) {
				return &mockGCPStorageClient{
					getReaderFunc: func(_ context.Context, _, object string) (io.ReadCloser, error) {
						if filepath.Ext(object) == ".fd" {
							return io.NopCloser(bytes.NewReader(firmware)), nil
						}
						digest := make([]byte, sha512.Size384)
						if test.match {
							digest = validDigest[:]
						}
						goldenBytes, err := proto.Marshal(&endorsement.VMGoldenMeasurement{Digest: digest})
						if err != nil {
							return nil, err
						}
						launchBytes, err := proto.Marshal(&endorsement.VMLaunchEndorsement{SerializedUefiGolden: goldenBytes})
						if err != nil {
							return nil, err
						}
						return io.NopCloser(bytes.NewReader(launchBytes)), nil
					},
					closeFunc: func() error { return nil },
				}, nil
			}
			cmd := (&CLI{}).NewDownloadGCPOvmfFile()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)
			cmd.SetArgs([]string{test.path})
			err := cmd.Execute()
			require.Contains(t, output.String(), test.output)
			if test.match {
				require.NoError(t, err)
				actual, err := os.ReadFile("ovmf.fd")
				require.NoError(t, err)
				require.Equal(t, firmware, actual)
			} else {
				require.ErrorIs(t, err, ErrCommandFailed)
				_, err = os.Stat("ovmf.fd")
				require.ErrorIs(t, err, os.ErrNotExist, "failed verification must not publish a firmware file")
			}
		})
	}
}
