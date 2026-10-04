// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager"
	managermocks "github.com/ToppyMicroServices/agents-secure-binding/v2/manager/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGeneratedKeysArePrivateAndNeverOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	require.NoError(t, generateAndWriteKeys(privateKey, publicDER, ed25519KeyType))
	info, err := os.Stat(privateKeyFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	original, err := os.ReadFile(privateKeyFile)
	require.NoError(t, err)
	require.ErrorIs(t, generateAndWriteKeys(privateKey, publicDER, ed25519KeyType), os.ErrExist)
	after, err := os.ReadFile(privateKeyFile)
	require.NoError(t, err)
	require.Equal(t, original, after)

	require.NoError(t, os.Remove(privateKeyFile))
	require.ErrorIs(t, generateAndWriteKeys(privateKey, publicDER, ed25519KeyType), os.ErrExist)
	_, err = os.Stat(privateKeyFile)
	require.ErrorIs(t, err, os.ErrNotExist, "failed pair creation must remove only its new private key")
	_, err = os.Stat(publicKeyFile)
	require.NoError(t, err, "existing public key must remain intact")
}

type failingIMAReader struct{}

func (failingIMAReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestIMAVerificationRejectsMalformedAndIncompleteInput(t *testing.T) {
	for _, test := range []struct {
		name string
		data io.Reader
	}{
		{"missing digest", strings.NewReader("10\n")},
		{"invalid digest", strings.NewReader("10 not-hex ima-ng\n")},
		{"wrong digest length", strings.NewReader("10 12 ima-ng\n")},
		{"truncated stream", failingIMAReader{}},
		{"oversized line", strings.NewReader(strings.Repeat("x", 70*1024))},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Error(t, verifyIMAMeasurements(test.data, make([]byte, sha1.Size)))
		})
	}
	require.NoError(t, verifyIMAMeasurements(strings.NewReader("\n\n"), make([]byte, sha1.Size)))
	initial := make([]byte, sha1.Size)
	digest := bytes.Repeat([]byte{0xff}, sha1.Size)
	expected := sha1.Sum(append(initial, digest...))
	require.NoError(t, verifyIMAMeasurements(strings.NewReader("10 "+strings.Repeat("0", 40)+" ima-ng\n"), expected[:]))
}

func TestManagerCommandDoesNotInheritAgentFailure(t *testing.T) {
	client := new(managermocks.ManagerServiceClient)
	client.On("RemoveVm", mock.Anything, &manager.RemoveReq{CvmId: "test-vm"}).Return(&emptypb.Empty{}, nil)
	service := &CLI{connectErr: errors.New("agent unavailable"), managerClient: client}
	cmd := service.NewRemoveVMCmd()
	cmd.SetArgs([]string{"test-vm"})
	cmd.SetOut(io.Discard)
	require.NoError(t, cmd.Execute())
	client.AssertExpectations(t)
}
