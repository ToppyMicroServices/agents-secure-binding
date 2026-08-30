// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package attestation

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	attestation_v1 "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/proto/attestation/v1"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func unixSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "asb-grpc-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

// mockAttestationServer is a mock implementation of the AttestationServiceServer.
type mockAttestationServer struct {
	attestation_v1.UnimplementedAttestationServiceServer
	fetchAttestationCalled bool
	fetchRawEvidenceCalled bool
	fetchAzureTokenCalled  bool
	lastReportData         []byte
	lastNonce              []byte
	lastPlatformType       attestation_v1.PlatformType
	attestationErr         error
	rawEvidenceErr         error
	azureTokenErr          error
}

func (m *mockAttestationServer) FetchAttestation(ctx context.Context, req *attestation_v1.AttestationRequest) (*attestation_v1.AttestationResponse, error) {
	m.fetchAttestationCalled = true
	m.lastReportData = req.ReportData
	m.lastNonce = req.Nonce
	m.lastPlatformType = req.PlatformType

	if m.attestationErr != nil {
		return nil, m.attestationErr
	}

	return &attestation_v1.AttestationResponse{
		EatToken: []byte("mock-attestation-quote"),
	}, nil
}

func (m *mockAttestationServer) FetchRawEvidence(ctx context.Context, req *attestation_v1.AttestationRequest) (*attestation_v1.RawEvidenceResponse, error) {
	m.fetchRawEvidenceCalled = true
	m.lastReportData = req.ReportData
	m.lastNonce = req.Nonce
	m.lastPlatformType = req.PlatformType

	if m.rawEvidenceErr != nil {
		return nil, m.rawEvidenceErr
	}

	return &attestation_v1.RawEvidenceResponse{
		Evidence: []byte("mock-raw-evidence"),
	}, nil
}

func (m *mockAttestationServer) FetchAzureToken(ctx context.Context, req *attestation_v1.AzureTokenRequest) (*attestation_v1.AzureTokenResponse, error) {
	m.fetchAzureTokenCalled = true
	m.lastNonce = req.Nonce

	if m.azureTokenErr != nil {
		return nil, m.azureTokenErr
	}

	return &attestation_v1.AzureTokenResponse{
		Token: []byte("mock-azure-token"),
	}, nil
}

// TestNewClient tests creating a new attestation client.
func TestNewClient(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}

// TestGetAttestationSNP tests getting SNP attestation.
func TestGetAttestationSNP(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-snp.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte
	copy(reportData[:], []byte("test-report-data"))
	copy(nonce[:], []byte("test-nonce"))

	quote, err := client.GetAttestation(ctx, reportData, nonce, attestation.SNP)
	require.NoError(t, err)
	assert.Equal(t, []byte("mock-attestation-quote"), quote)
	assert.True(t, mockServer.fetchAttestationCalled)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_SNP, mockServer.lastPlatformType)
	assert.Equal(t, reportData[:], mockServer.lastReportData)
	assert.Equal(t, nonce[:], mockServer.lastNonce)
}

// TestGetAttestationTDX tests getting TDX attestation.
func TestGetAttestationTDX(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-tdx.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	quote, err := client.GetAttestation(ctx, reportData, nonce, attestation.TDX)
	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_TDX, mockServer.lastPlatformType)
}

// TestGetAttestationVTPM tests getting vTPM attestation.
func TestGetAttestationVTPM(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-vtpm.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	quote, err := client.GetAttestation(ctx, reportData, nonce, attestation.VTPM)
	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_VTPM, mockServer.lastPlatformType)
}

// TestGetAttestationSNPvTPM tests getting SNP+vTPM attestation.
func TestGetAttestationSNPvTPM(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-snpvtpm.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	quote, err := client.GetAttestation(ctx, reportData, nonce, attestation.SNPvTPM)
	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_SNP_VTPM, mockServer.lastPlatformType)
}

// TestGetAttestationUnspecified tests getting attestation with unspecified platform.
func TestGetAttestationUnspecified(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-unspec.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	// Use an invalid platform type (999)
	quote, err := client.GetAttestation(ctx, reportData, nonce, attestation.PlatformType(999))
	require.NoError(t, err)
	assert.NotNil(t, quote)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_UNSPECIFIED, mockServer.lastPlatformType)
}

// TestGetAzureToken tests getting Azure token.
func TestGetAzureToken(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-azure.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var nonce [32]byte
	copy(nonce[:], []byte("azure-nonce"))

	token, err := client.GetAzureToken(ctx, nonce)
	require.NoError(t, err)
	assert.Equal(t, []byte("mock-azure-token"), token)
	assert.True(t, mockServer.fetchAzureTokenCalled)
	assert.Equal(t, nonce[:], mockServer.lastNonce)
}

// TestGetAttestationWithCanceledContext tests GetAttestation with canceled context.
func TestGetAttestationWithCanceledContext(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-cancel.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var reportData [64]byte
	var nonce [32]byte

	_, err = client.GetAttestation(ctx, reportData, nonce, attestation.SNP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// TestClientClose tests closing the attestation client.
func TestClientClose(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

// TestClientOperationsAfterClose tests operations after closing.
func TestClientOperationsAfterClose(t *testing.T) {
	socketPath := unixSocketPath(t, "attestation-after-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	_, err = client.GetAttestation(ctx, reportData, nonce, attestation.SNP)
	assert.Error(t, err)
}

// TestGetRawEvidenceSNP tests getting raw evidence for SNP platform.
func TestGetRawEvidenceSNP(t *testing.T) {
	socketPath := unixSocketPath(t, "raw-evidence-snp.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte
	copy(reportData[:], []byte("test-report-data"))
	copy(nonce[:], []byte("test-nonce"))

	evidence, err := client.GetRawEvidence(ctx, reportData, nonce, attestation.SNP)
	require.NoError(t, err)
	assert.Equal(t, []byte("mock-raw-evidence"), evidence)
	assert.True(t, mockServer.fetchRawEvidenceCalled)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_SNP, mockServer.lastPlatformType)
}

// TestGetRawEvidenceTDX tests getting raw evidence for TDX platform.
func TestGetRawEvidenceTDX(t *testing.T) {
	socketPath := unixSocketPath(t, "raw-evidence-tdx.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	evidence, err := client.GetRawEvidence(ctx, reportData, nonce, attestation.TDX)
	require.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_TDX, mockServer.lastPlatformType)
}

// TestGetRawEvidenceVTPM tests getting raw evidence for VTPM platform.
func TestGetRawEvidenceVTPM(t *testing.T) {
	socketPath := unixSocketPath(t, "raw-evidence-vtpm.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	evidence, err := client.GetRawEvidence(ctx, reportData, nonce, attestation.VTPM)
	require.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_VTPM, mockServer.lastPlatformType)
}

// TestGetRawEvidenceSNPvTPM tests getting raw evidence for SNPvTPM platform.
func TestGetRawEvidenceSNPvTPM(t *testing.T) {
	socketPath := unixSocketPath(t, "raw-evidence-snpvtpm.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	evidence, err := client.GetRawEvidence(ctx, reportData, nonce, attestation.SNPvTPM)
	require.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_SNP_VTPM, mockServer.lastPlatformType)
}

// TestGetRawEvidenceUnspecified tests getting raw evidence with unspecified platform.
func TestGetRawEvidenceUnspecified(t *testing.T) {
	socketPath := unixSocketPath(t, "raw-evidence-unspec.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationServer{}
	attestation_v1.RegisterAttestationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	var reportData [64]byte
	var nonce [32]byte

	evidence, err := client.GetRawEvidence(ctx, reportData, nonce, attestation.PlatformType(999))
	require.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, attestation_v1.PlatformType_PLATFORM_TYPE_UNSPECIFIED, mockServer.lastPlatformType)
}
