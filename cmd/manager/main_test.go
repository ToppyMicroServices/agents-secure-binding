// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	smqserver "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLocalBindHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "localhost", host: "localhost", want: true},
		{name: "IPv4 loopback", host: "127.0.0.1", want: true},
		{name: "IPv6 loopback", host: "::1", want: true},
		{name: "bracketed IPv6 loopback", host: "[::1]", want: true},
		{name: "all IPv4 interfaces", host: "0.0.0.0", want: false},
		{name: "all IPv6 interfaces", host: "::", want: false},
		{name: "empty host", host: "", want: false},
		{name: "public host", host: "manager.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isLocalBindHost(tt.host))
		})
	}
}

func TestManagerRequiresMTLSOnEveryBind(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "0.0.0.0", ""} {
		for _, cfg := range []smqserver.Config{
			{Host: host},
			{Host: host, CertFile: "server-cert", KeyFile: "server-key"},
			{Host: host, CertFile: "server-cert", ClientCAFile: "client-ca"},
			{Host: host, KeyFile: "server-key", ClientCAFile: "client-ca"},
		} {
			if err := validateManagerGRPCConfig(cfg); err == nil {
				t.Fatalf("accepted missing mTLS credentials on %q", host)
			}
		}
	}
}

func TestManagerValidatesMTLSCredentials(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	cfg := smqserver.Config{Host: "127.0.0.1", CertFile: certPEM, KeyFile: keyPEM, ClientCAFile: certPEM}
	require.NoError(t, validateManagerGRPCConfig(cfg))
	cfg.ClientCAFile = "invalid CA"
	require.Error(t, validateManagerGRPCConfig(cfg))
	cfg.ClientCAFile = filepath.Join(t.TempDir(), "empty.pem")
	require.NoError(t, os.WriteFile(cfg.ClientCAFile, nil, 0o600))
	require.Error(t, validateManagerGRPCConfig(cfg))
	cfg.ClientCAFile, cfg.KeyFile = certPEM, "invalid key"
	require.Error(t, validateManagerGRPCConfig(cfg))
}
