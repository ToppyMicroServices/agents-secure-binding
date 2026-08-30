// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/stretchr/testify/require"
)

type recordingEvidenceSource struct {
	called  bool
	request eaattestation.EvidenceRequest
	result  eaattestation.EvidenceResult
	err     error
}

func (s *recordingEvidenceSource) GetEvidence(_ context.Context, request eaattestation.EvidenceRequest) (eaattestation.EvidenceResult, error) {
	s.called = true
	s.request = request
	return s.result, s.err
}

func TestProviderBuildLeafExtensionsUsesSessionBinding(t *testing.T) {
	certificate, leaf := providerTestCertificate(t)
	server, client := providerTLSPair(t, certificate)
	defer server.Close()
	defer client.Close()

	source := &recordingEvidenceSource{result: eaattestation.EvidenceResult{
		MediaType: "application/eat+cwt",
		Evidence:  []byte("opaque-evidence"),
	}}
	provider, err := NewProvider(source)
	require.NoError(t, err)

	request := &ea.AuthenticatorRequest{Context: []byte("request-context")}
	state := client.ConnectionState()
	extensions, err := provider.BuildLeafExtensions(&state, request, leaf)
	require.NoError(t, err)
	require.True(t, source.called)
	require.Len(t, extensions, 1)

	exportedValue, aikPubHash, binding, err := eaattestation.ComputeBinding(
		&state,
		eaattestation.ExporterLabelAttestation,
		request.Context,
		leaf,
	)
	require.NoError(t, err)
	require.Equal(t, sha512.Sum512(binding), source.request.ReportData)
	require.Equal(t, sha256.Sum256(exportedValue), source.request.Nonce)

	rawPayload, present, err := ea.ExtractCMWAttestationFromExtensions(extensions)
	require.NoError(t, err)
	require.True(t, present)
	payload, err := eaattestation.ParsePayload(rawPayload)
	require.NoError(t, err)
	require.Equal(t, "application/eat+cwt", payload.MediaType)
	require.Equal(t, []byte("opaque-evidence"), payload.Evidence)
	require.Equal(t, eaattestation.ExporterLabelAttestation, payload.Binder.ExporterLabel)
	require.True(t, bytes.Equal(aikPubHash, payload.Binder.AIKPubHash))
	require.True(t, bytes.Equal(binding, payload.Binder.Binding))
}

func TestNewProviderRejectsMissingEvidenceSource(t *testing.T) {
	provider, err := NewProvider(nil)
	require.EqualError(t, err, "atls: missing evidence source")
	require.Nil(t, provider)
}

func TestProviderBuildLeafExtensionsWrapsEvidenceSourceError(t *testing.T) {
	certificate, leaf := providerTestCertificate(t)
	server, client := providerTLSPair(t, certificate)
	defer server.Close()
	defer client.Close()

	sourceErr := errors.New("source unavailable")
	provider, err := NewProvider(&recordingEvidenceSource{err: sourceErr})
	require.NoError(t, err)
	state := client.ConnectionState()

	_, err = provider.BuildLeafExtensions(&state, &ea.AuthenticatorRequest{Context: []byte("context")}, leaf)
	require.ErrorIs(t, err, sourceErr)
	require.ErrorContains(t, err, "failed to fetch attestation evidence")
}

func providerTestCertificate(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "provider-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}, leaf
}

func providerTLSPair(t *testing.T, certificate tls.Certificate) (*tls.Conn, *tls.Conn) {
	t.Helper()

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	clientConfig := &tls.Config{
		InsecureSkipVerify: true, // The test verifies the ASB binding, not PKI.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	serverConn, clientConn := net.Pipe()
	server := tls.Server(serverConn, serverConfig)
	client := tls.Client(clientConn, clientConfig)
	errCh := make(chan error, 2)
	go func() { errCh <- server.Handshake() }()
	go func() { errCh <- client.Handshake() }()
	for range 2 {
		require.NoError(t, <-errCh)
	}
	return server, client
}
