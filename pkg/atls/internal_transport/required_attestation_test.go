// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
)

type requiredEvidenceVerifier struct{}

func (requiredEvidenceVerifier) VerifyEvidence([]byte, eaattestation.EvidenceBinding) error {
	return errors.New("test verifier must not accept evidence")
}

func TestClientRejectsEmptyAuthenticatorWhenAttestationRequired(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(fmt.Sprintf("required=%t", required), func(t *testing.T) {
			cert := selfSignedCert(t)
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			serverPipe, clientPipe := net.Pipe()
			t.Cleanup(func() {
				_ = serverPipe.Close()
				_ = clientPipe.Close()
			})
			serverTLS := tls.Server(serverPipe, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
			clientTLS := tls.Client(clientPipe, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := serverPipe.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			serverResult := make(chan error, 1)
			go func() {
				serverResult <- sendEmptyAuthenticator(ctx, serverTLS)
			}()
			// Identity policy is intentionally disabled. Required evidence must
			// still reject the peer's valid Finished-only protocol response.
			config := &ClientConfig{VerifyOptions: &x509.VerifyOptions{Roots: roots}}
			if required {
				config.AttestationPolicy.EvidenceVerifier = requiredEvidenceVerifier{}
			}
			conn, err := ClientContext(ctx, clientTLS, config)
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatalf("peer failed before sending the authenticator: %v", serverErr)
			}
			if required {
				if !errors.Is(err, eaattestation.ErrMissingAttestation) || conn != nil {
					t.Fatalf("required client returned (%+v, %v), want nil connection and missing attestation", conn, err)
				}
				return
			}
			if err != nil || conn == nil || conn.ValidationResult == nil || !conn.ValidationResult.Empty {
				t.Fatalf("optional empty authenticator returned (%+v, %v)", conn, err)
			}
		})
	}
}

func sendEmptyAuthenticator(ctx context.Context, server *tls.Conn) error {
	if err := server.HandshakeContext(ctx); err != nil {
		return err
	}
	frameType, requestBytes, err := readFrame(server)
	if err != nil {
		return err
	}
	if frameType != frameTypeRequest {
		return fmt.Errorf("unexpected frame type: %d", frameType)
	}
	request, rest, err := ea.UnmarshalAuthenticatorRequest(requestBytes)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("unexpected trailing request bytes")
	}
	state := server.ConnectionState()
	auth, err := ea.CreateAuthenticator(&state, ea.RoleServer, &request, tls.Certificate{}, nil)
	if err != nil {
		return err
	}
	return writeFrame(server, frameTypeAuthenticator, auth)
}
