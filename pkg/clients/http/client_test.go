// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/rand"
	"crypto/rsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/tls"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Configuration(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:          "http://localhost:8080",
		Timeout:      30 * time.Second,
		ClientCert:   "cert.pem",
		ClientKey:    "key.pem",
		ServerCAFile: "ca.pem",
	}

	result := config.Config()

	assert.Equal(t, config, result)
	assert.Equal(t, "http://localhost:8080", result.URL)
	assert.Equal(t, 30*time.Second, result.Timeout)
	assert.Equal(t, "cert.pem", result.ClientCert)
	assert.Equal(t, "key.pem", result.ClientKey)
	assert.Equal(t, "ca.pem", result.ServerCAFile)
}

func TestAgentClientConfig_Configuration(t *testing.T) {
	agentConfig := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:          "https://agent.example.com",
			Timeout:      60 * time.Second,
			ClientCert:   "agent-cert.pem",
			ClientKey:    "agent-key.pem",
			ServerCAFile: "agent-ca.pem",
		},
		AttestationPolicy: "policy.json",
		AttestedTLS:       true,
		ProductName:       "Milan",
	}

	result := agentConfig.Config()

	assert.Equal(t, agentConfig.StandardClientConfig, result)
	assert.Equal(t, "https://agent.example.com", result.URL)
	assert.Equal(t, 60*time.Second, result.Timeout)
	assert.Equal(t, "agent-cert.pem", result.ClientCert)
	assert.Equal(t, "agent-key.pem", result.ClientKey)
	assert.Equal(t, "agent-ca.pem", result.ServerCAFile)
}

func TestProxyClientConfig_Configuration(t *testing.T) {
	proxyConfig := clients.StandardClientConfig{
		URL:          "http://proxy.example.com",
		Timeout:      45 * time.Second,
		ClientCert:   "proxy-cert.pem",
		ClientKey:    "proxy-key.pem",
		ServerCAFile: "proxy-ca.pem",
	}

	result := proxyConfig

	assert.Equal(t, proxyConfig, result)
	assert.Equal(t, "http://proxy.example.com", result.URL)
	assert.Equal(t, 45*time.Second, result.Timeout)
}

func TestNewClient_Success(t *testing.T) {
	tests := []struct {
		name   string
		config clients.ClientConfiguration
	}{
		{
			name: "Basic config",
			config: clients.StandardClientConfig{
				URL:     "http://localhost:8080",
				Timeout: 30 * time.Second,
			},
		},
		{
			name: "Agent config without attested TLS",
			config: &clients.AttestedClientConfig{
				StandardClientConfig: clients.StandardClientConfig{
					URL:     "https://agent.example.com",
					Timeout: 60 * time.Second,
				},
				AttestedTLS: false,
			},
		},
		{
			name: "Proxy config",
			config: clients.StandardClientConfig{
				URL:     "http://proxy.example.com",
				Timeout: 45 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.NotNil(t, client.Transport())
			assert.Equal(t, tt.config.Config().Timeout, client.Timeout())
		})
	}
}

func TestClient_Transport(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	transport := client.Transport()

	assert.NotNil(t, transport)
	assert.IsType(t, &http.Transport{}, transport)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
}

func TestClient_Secure(t *testing.T) {
	tests := []struct {
		name     string
		config   clients.ClientConfiguration
		expected string
	}{
		{
			name: "Without TLS",
			config: clients.StandardClientConfig{
				URL:     "http://localhost:8080",
				Timeout: 30 * time.Second,
			},
			expected: tls.WithoutTLS.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			assert.NoError(t, err)

			secure := client.Secure()
			assert.Equal(t, tt.expected, secure)
		})
	}
}

func TestClient_Timeout(t *testing.T) {
	expectedTimeout := 45 * time.Second
	config := clients.StandardClientConfig{
		URL:     "http://localhost:8080",
		Timeout: expectedTimeout,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	timeout := client.Timeout()
	assert.Equal(t, expectedTimeout, timeout)
}

func TestCreateTransport_DefaultSettings(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	transport, security, err := createTransport(config)

	assert.NoError(t, err)
	assert.NotNil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	assert.Nil(t, transport.TLSClientConfig)
}

func TestCreateTransport_ATLSRejectsMissingVerifier(t *testing.T) {
	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:     "https://agent.example.com",
			Timeout: 60 * time.Second,
		},
		AttestedTLS: true,
		ProductName: "Milan",
	}

	transport, security, err := createTransport(config)

	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
	assert.ErrorIs(t, err, clients.ErrMissingAttestationVerifier)
}

func TestCreateTransport_ATLSValueCannotBypassVerifier(t *testing.T) {
	config := clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{URL: "https://agent.example.com"},
		AttestedTLS:          true,
	}

	transport, security, err := createTransport(config)
	assert.ErrorIs(t, err, clients.ErrMissingAttestationVerifier)
	assert.Nil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
}

func TestCreateTransport_ATLSRejectsPlainHTTP(t *testing.T) {
	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:          "http://example.invalid",
			ServerCAFile: createHTTPTestCAFile(t),
		},
		AttestedTLS:                   true,
		AttestationVerificationPolicy: httpAttestationVerificationPolicy(),
	}
	transport, security, err := createTransport(config)
	assert.NoError(t, err)
	assert.Equal(t, tls.WithMATLS, security)

	request, err := http.NewRequest(http.MethodGet, config.URL, nil)
	assert.NoError(t, err)
	response, err := transport.RoundTrip(request)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, clients.ErrAttestedTLSRequiresHTTPS)
}

func TestCreateTransport_RejectsNilAttestedConfig(t *testing.T) {
	var config *clients.AttestedClientConfig
	transport, security, err := createTransport(config)
	assert.ErrorIs(t, err, clients.ErrNilAttestedClientConfig)
	assert.Nil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
}

func TestCreateTransport_ATLSCustomRequestContext(t *testing.T) {
	caFile := createHTTPTestCAFile(t)

	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:          "https://agent.example.com",
			Timeout:      60 * time.Second,
			ServerCAFile: caFile,
		},
		AttestedTLS:                   true,
		AttestationVerificationPolicy: httpAttestationVerificationPolicy(),
		AttestationRequestContextHex:  "01020304",
	}

	transport, security, err := createTransport(config)

	assert.NoError(t, err)
	assert.NotNil(t, transport)
	assert.Equal(t, tls.WithMATLS, security)
	assert.NotNil(t, transport.DialTLSContext)
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
	replay := newHTTPReplayCache()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agcfg := &clients.AttestedClientConfig{
		AttestationVerificationPolicy: httpAttestationVerificationPolicy(),
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

	assert.NoError(t, err)
	assert.Equal(t, agcfg.AttestationVerificationPolicy, atlsConfig.AttestationPolicy)
	assert.Equal(t, agcfg.IdentityPolicy, atlsConfig.IdentityPolicy)
	assert.Same(t, grant, atlsConfig.IdentityGrant)
	assert.Same(t, binding, atlsConfig.IdentityBinding)
	assert.Same(t, replay, atlsConfig.IdentityReplay)
	assert.Same(t, logger, atlsConfig.IdentityLogger)
}

func TestBuildATLSClientConfigWiresAGTPObservedIdentity(t *testing.T) {
	agcfg := &clients.AttestedClientConfig{
		AttestationVerificationPolicy: httpAttestationVerificationPolicy(),
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
			KeyFunc:          httpTestKeyFunc(map[string][]byte{"manager-key": []byte("manager-secret")}),
		},
		IdentityBindingJWTOptions: clients.JWTVerifyOptions{
			ExpectedIssuer:   "agent-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          httpTestKeyFunc(map[string][]byte{"agent-key": []byte("agent-secret")}),
		},
		IdentityReplay: newHTTPReplayCache(),
	}

	atlsConfig, err := buildATLSClientConfig(agcfg, &stdtls.Config{})

	assert.NoError(t, err)
	assert.NotNil(t, atlsConfig.ObservedIdentity)
}

func TestCreateTransport_ATLSInvalidRequestContext(t *testing.T) {
	caFile := createHTTPTestCAFile(t)

	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:          "https://agent.example.com",
			Timeout:      60 * time.Second,
			ServerCAFile: caFile,
		},
		AttestedTLS:                   true,
		AttestationVerificationPolicy: httpAttestationVerificationPolicy(),
		AttestationRequestContextHex:  "xyz",
	}

	transport, security, err := createTransport(config)

	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
	assert.Contains(t, err.Error(), "invalid attestation request context")
}

type httpReplayCache struct{}

type httpAcceptEvidenceVerifier struct{}

func (httpAcceptEvidenceVerifier) VerifyEvidence([]byte, eaattestation.EvidenceBinding) error {
	return nil
}

func httpAttestationVerificationPolicy() eaattestation.VerificationPolicy {
	return eaattestation.VerificationPolicy{EvidenceVerifier: httpAcceptEvidenceVerifier{}}
}

func newHTTPReplayCache() *httpReplayCache {
	return &httpReplayCache{}
}

func (c *httpReplayCache) MarkUsed(string, time.Time) error {
	return nil
}

func httpTestKeyFunc(keys map[string][]byte) clients.KeyFunc {
	return func(keyID string) (interface{}, error) {
		key, ok := keys[keyID]
		if !ok {
			return nil, clients.ErrMissingKeyID
		}
		return key, nil
	}
}

func createHTTPTestCAFile(t *testing.T) string {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caFile, err := os.CreateTemp("", "http-client-ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(caFile.Name())
	})

	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		_ = caFile.Close()
		t.Fatal(err)
	}
	if err := caFile.Close(); err != nil {
		t.Fatal(err)
	}

	return caFile.Name()
}

func TestCreateTransport_BasicTLSError(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:          "https://example.com",
		Timeout:      30 * time.Second,
		ServerCAFile: "invalid",
	}

	transport, security, err := createTransport(config)

	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Equal(t, tls.WithoutTLS, security)
	assert.Contains(t, err.Error(), "failed to load root ca file")
}

func TestClientInterface_Implementation(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	// Verify that client implements the Client interface
	var _ Client = client

	// Test all interface methods
	assert.NotNil(t, client.Transport())
	assert.NotEmpty(t, client.Secure())
	assert.Greater(t, client.Timeout(), time.Duration(0))
}

func TestAgentClientConfig_FieldAccess(t *testing.T) {
	config := &clients.AttestedClientConfig{
		StandardClientConfig: clients.StandardClientConfig{
			URL:     "https://agent.example.com",
			Timeout: 60 * time.Second,
		},
		AttestationPolicy: "test-policy",
		AttestedTLS:       true,
		ProductName:       "TestProduct",
	}

	assert.Equal(t, "test-policy", config.AttestationPolicy)
	assert.True(t, config.AttestedTLS)
	assert.Equal(t, "TestProduct", config.ProductName)
	assert.Equal(t, "https://agent.example.com", config.URL)
	assert.Equal(t, 60*time.Second, config.Timeout)
}

func TestProxyClientConfig_FieldAccess(t *testing.T) {
	config := clients.StandardClientConfig{
		URL:          "http://proxy.example.com",
		Timeout:      45 * time.Second,
		ClientCert:   "proxy-cert.pem",
		ClientKey:    "proxy-key.pem",
		ServerCAFile: "proxy-ca.pem",
	}

	assert.Equal(t, "http://proxy.example.com", config.URL)
	assert.Equal(t, 45*time.Second, config.Timeout)
	assert.Equal(t, "proxy-cert.pem", config.ClientCert)
	assert.Equal(t, "proxy-key.pem", config.ClientKey)
	assert.Equal(t, "proxy-ca.pem", config.ServerCAFile)
}

func TestClientConfiguration_Interface(t *testing.T) {
	// Test that all config types implement ClientConfiguration interface
	var configs []clients.ClientConfiguration

	configs = append(configs, clients.StandardClientConfig{})
	configs = append(configs, &clients.AttestedClientConfig{})

	for i, config := range configs {
		t.Run(t.Name()+"_"+string(rune(i+'0')), func(t *testing.T) {
			result := config.Config()
			assert.IsType(t, clients.StandardClientConfig{}, result)
		})
	}
}
