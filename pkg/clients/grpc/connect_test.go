// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	caCertFile, clientCertFile, clientKeyFile, err := createCertificatesFiles()
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(caCertFile)
		os.Remove(clientCertFile)
		os.Remove(clientKeyFile)
	})

	tests := []struct {
		name     string
		cfg      clients.StandardClientConfig
		agentCfg clients.AttestedClientConfig
		wantErr  bool
		err      error
	}{
		{
			name: "Success without TLS",
			cfg: clients.StandardClientConfig{
				URL: "localhost:7001",
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Fail without TLS to remote target",
			cfg: clients.StandardClientConfig{
				URL: "agent.example.com:7001",
			},
			wantErr: true,
			err:     ErrPlaintextRemoteGRPC,
		},
		{
			name: "Success with TLS",
			cfg: clients.StandardClientConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success with mTLS",
			cfg: clients.StandardClientConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    clientKeyFile,
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success agent client with mTLS",
			agentCfg: clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success agent client with aTLS",
			agentCfg: clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS:                   true,
				AttestationVerificationPolicy: grpcAttestationVerificationPolicy(),
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success agent client with aTLS and custom request context",
			agentCfg: clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS:                   true,
				AttestationVerificationPolicy: grpcAttestationVerificationPolicy(),
				AttestationRequestContextHex:  "01020304",
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Failed agent client with aTLS and no verifier",
			agentCfg: clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS: true,
			},
			wantErr: true,
			err:     clients.ErrMissingAttestationVerifier,
		},
		{
			name: "Failed agent client with invalid attestation request context",
			agentCfg: clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS:                   true,
				AttestationVerificationPolicy: grpcAttestationVerificationPolicy(),
				AttestationRequestContextHex:  "xyz",
			},
			wantErr: true,
			err:     clients.ErrInvalidAttestationRequestContext,
		},
		{
			name: "Fail with invalid ServerCAFile",
			cfg: clients.StandardClientConfig{
				URL:          "localhost:7001",
				ServerCAFile: "nonexistent.pem",
			},
			wantErr: true,
			err:     tls.ErrFailedToLoadRootCA,
		},
		{
			name: "Fail with invalid ClientCert",
			cfg: clients.StandardClientConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   "nonexistent.pem",
				ClientKey:    clientKeyFile,
			},
			wantErr: true,
			err:     tls.ErrFailedToLoadClientCertKey,
		},
		{
			name: "Fail with invalid ClientKey",
			cfg: clients.StandardClientConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    "nonexistent.pem",
			},
			wantErr: true,
			err:     tls.ErrFailedToLoadClientCertKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client Client
			if strings.Contains(tt.name, "agent client") {
				client, err = NewClient(tt.agentCfg)
			} else {
				client, err = NewClient(tt.cfg)
			}
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NoError(t, client.Close())
			}
		})
	}
}

func TestConnect_ATLSPointerCannotBypassVerifier(t *testing.T) {
	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{URL: "localhost:7001"},
		AttestedTLS:          true,
	}

	conn, security, err := connect(config)
	assert.ErrorIs(t, err, clients.ErrMissingAttestationVerifier)
	assert.Nil(t, conn)
	assert.Equal(t, tls.WithoutTLS, security)
}

func TestConnect_RejectsNilAttestedConfig(t *testing.T) {
	var config *clients.AttestedClientConfig
	conn, security, err := connect(config)
	assert.ErrorIs(t, err, clients.ErrNilAttestedClientConfig)
	assert.Nil(t, conn)
	assert.Equal(t, tls.WithoutTLS, security)
}

func TestBuildATLSClientConfigCopiesIdentityBindingInputs(t *testing.T) {
	grant := &identitypolicy.VerifiedGrant{
		Issuer:          "manager-key-1",
		Audience:        "client-a",
		GrantHash:       "sha256:grant",
		ConfirmationKey: "agent-confirmation-key",
		Values:          identitypolicy.Values{Service: "payments"},
		IssuedAt:        time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}
	binding := &identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: "sha256:grant",
		Audience:  "client-a",
		SignerKey: "agent-confirmation-key",
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:  "leaf",
			RequestContextSHA256: "ctx",
			Nonce:                "nonce",
			ExpiresAt:            time.Now().Add(time.Minute),
		},
	}
	replay := newGRPCReplayCache()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agcfg := clients.AttestedClientConfig{
		AttestationVerificationPolicy: grpcAttestationVerificationPolicy(),
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrant:   grant,
		IdentityBinding: binding,
		IdentityReplay:  replay,
		IdentityLogger:  logger,
	}

	atlsConfig, err := buildATLSClientConfig(agcfg, &stdtls.Config{})

	require.NoError(t, err)
	assert.Equal(t, agcfg.AttestationVerificationPolicy, atlsConfig.AttestationPolicy)
	assert.Equal(t, agcfg.IdentityPolicy, atlsConfig.IdentityPolicy)
	assert.Same(t, grant, atlsConfig.IdentityGrant)
	assert.Same(t, binding, atlsConfig.IdentityBinding)
	assert.Same(t, replay, atlsConfig.IdentityReplay)
	assert.Same(t, logger, atlsConfig.IdentityLogger)
}

func TestBuildATLSClientConfigWiresAGTPObservedIdentity(t *testing.T) {
	agcfg := clients.AttestedClientConfig{
		AttestationVerificationPolicy: grpcAttestationVerificationPolicy(),
		IdentityPolicy: identitypolicy.Policy{
			Require:  identitypolicy.Requirements{L3: true},
			Expected: identitypolicy.Values{Service: "payments"},
		},
		IdentityGrantJWT:   "grant",
		IdentityBindingJWT: "binding",
		IdentityGrantJWTOptions: clients.JWTVerifyOptions{
			ExpectedIssuer:   "manager",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          grpcTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		},
		IdentityBindingJWTOptions: clients.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          grpcTestKeyFunc(map[string][]byte{"agent-key": []byte("agent-secret")}),
		},
		IdentityReplay: newGRPCReplayCache(),
	}

	atlsConfig, err := buildATLSClientConfig(agcfg, &stdtls.Config{})

	require.NoError(t, err)
	require.NotNil(t, atlsConfig.ObservedIdentity)
}

func TestClientSecure(t *testing.T) {
	tests := []struct {
		name     string
		secure   tls.Security
		expected string
	}{
		{
			name:     "Without TLS",
			secure:   tls.WithoutTLS,
			expected: "without TLS",
		},
		{
			name:     "With TLS",
			secure:   tls.WithTLS,
			expected: "with TLS",
		},
		{
			name:     "With mTLS",
			secure:   tls.WithMTLS,
			expected: "with mTLS",
		},
		{
			name:     "With aTLS",
			secure:   tls.WithATLS,
			expected: "with aTLS",
		},
		{
			name:     "With maTLS",
			secure:   tls.WithMATLS,
			expected: "with maTLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{security: tt.secure}
			assert.Equal(t, tt.expected, c.Secure())
		})
	}
}

type grpcReplayCache struct{}

type grpcAcceptEvidenceVerifier struct{}

func (grpcAcceptEvidenceVerifier) VerifyEvidence([]byte, eaattestation.EvidenceBinding) error {
	return nil
}

func grpcAttestationVerificationPolicy() eaattestation.VerificationPolicy {
	return eaattestation.VerificationPolicy{EvidenceVerifier: grpcAcceptEvidenceVerifier{}}
}

func newGRPCReplayCache() *grpcReplayCache {
	return &grpcReplayCache{}
}

func (c *grpcReplayCache) MarkUsed(string, time.Time) error {
	return nil
}

func grpcTestKeyFunc(keys map[string][]byte) clients.KeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, clients.ErrMissingKeyID
		}
		return key, nil
	}
}

func createCertificatesFiles() (string, string, string, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	caCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	clientCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKeyFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))
	if err != nil {
		return "", "", "", err
	}

	return caCertFile, clientCertFile, clientKeyFile, nil
}

func createTempFile(data []byte) (string, error) {
	file, err := createTempFileHandle()
	if err != nil {
		return "", err
	}

	_, err = file.Write(data)
	if err != nil {
		return "", err
	}

	err = file.Close()
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func createTempFileHandle() (*os.File, error) {
	return os.CreateTemp("", "test")
}
