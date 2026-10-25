// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/server"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/manager"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	grpcreflection "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/test/bufconn"
)

type authenticatedManagerStub struct {
	manager.UnimplementedManagerServiceServer
}

func (authenticatedManagerStub) CreateVm(context.Context, *manager.CreateReq) (*manager.CreateRes, error) {
	return &manager.CreateRes{CvmId: "authenticated"}, nil
}

// Exercise the actual runtime transport with lifecycle, health, and reflection
// registrations. The TLS handshake must reject callers before any RPC dispatch.
func TestMTLSProtectsAllManagerRegistrations(t *testing.T) {
	ca, caKey, caPEM, _ := transportTestCertificate(t, nil, nil, 1, nil)
	_, _, certPEM, keyPEM := transportTestCertificate(t, ca, caKey, 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	_, _, clientPEM, clientKeyPEM := transportTestCertificate(t, ca, caKey, 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	otherCA, otherCAKey, _, _ := transportTestCertificate(t, nil, nil, 4, nil)
	_, _, otherPEM, otherKeyPEM := transportTestCertificate(t, otherCA, otherCAKey, 5, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	clientCertificate, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	require.NoError(t, err)
	otherCertificate, err := tls.X509KeyPair(otherPEM, otherKeyPEM)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))

	runtime := &runtimeServer{requireMTLS: true, Base: server.Base{Config: server.Config{
		CertFile: string(certPEM), KeyFile: string(keyPEM), ClientCAFile: string(caPEM),
	}}}
	transport, err := runtime.tlsCredentials()
	require.NoError(t, err)
	listener := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(transport)
	manager.RegisterManagerServiceServer(srv, authenticatedManagerStub{})
	grpchealth.RegisterHealthServer(srv, health.NewServer())
	reflection.Register(srv)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { srv.Stop(); _ = listener.Close() })

	for _, tc := range []struct {
		name         string
		certificates []tls.Certificate
		authorized   bool
	}{
		{name: "anonymous"},
		{name: "untrusted client CA", certificates: []tls.Certificate{otherCertificate}},
		{name: "authorized operator", certificates: []tls.Certificate{clientCertificate}, authorized: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := grpc.NewClient("passthrough:///manager", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				RootCAs: roots, ServerName: "manager.test", Certificates: tc.certificates, MinVersion: tls.VersionTLS12,
			})), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
			require.NoError(t, err)
			defer conn.Close()
			check := func(err error) {
				t.Helper()
				if tc.authorized {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = manager.NewManagerServiceClient(conn).CreateVm(ctx, &manager.CreateReq{})
			check(err)
			_, err = grpchealth.NewHealthClient(conn).Check(ctx, &grpchealth.HealthCheckRequest{})
			check(err)
			stream, err := grpcreflection.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
			if err == nil {
				err = stream.Send(&grpcreflection.ServerReflectionRequest{MessageRequest: &grpcreflection.ServerReflectionRequest_ListServices{ListServices: ""}})
			}
			if err == nil {
				_, err = stream.Recv()
			}
			check(err)
		})
	}
}

func TestRequiredMTLSFailsClosedWithoutWeakeningGenericServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, cfg := range []server.Config{
		{Host: "127.0.0.1"},
		{Host: "127.0.0.1", CertFile: "server", KeyFile: "key"},
		{Host: "127.0.0.1", CertFile: "server", ClientCAFile: "client CA"},
	} {
		srv := NewMTLSServer(ctx, cancel, "manager", cfg, nil, slog.Default())
		require.ErrorIs(t, srv.Start(), ErrMTLSRequired)
	}
	_, _, certPEM, keyPEM := transportTestCertificate(t, nil, nil, 1, nil)
	cfg := server.Config{CertFile: string(certPEM), KeyFile: string(keyPEM)}
	generic := &runtimeServer{Base: server.Base{Config: cfg}}
	_, err := generic.tlsCredentials()
	require.NoError(t, err, "generic TLS-only servers retain their existing policy")

	protected := &runtimeServer{requireMTLS: true, Base: server.Base{Config: cfg}}
	_, err = protected.tlsCredentials()
	require.ErrorIs(t, err, ErrMTLSRequired)
	protected.Config.ClientCAFile = filepath.Join(t.TempDir(), "empty-ca.pem")
	require.NoError(t, os.WriteFile(protected.Config.ClientCAFile, nil, 0o600))
	_, err = protected.tlsCredentials()
	require.ErrorIs(t, err, ErrMTLSRequired, "empty CA file must not downgrade to server-only TLS")
}

func transportTestCertificate(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, serial int64, usage []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, DNSNames: []string{"manager.test"},
	}
	if parent == nil {
		certificate.IsCA, certificate.BasicConstraintsValid = true, true
		certificate.KeyUsage |= x509.KeyUsageCertSign
		parent, signer = certificate, key
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, parent, key.Public(), signer)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
