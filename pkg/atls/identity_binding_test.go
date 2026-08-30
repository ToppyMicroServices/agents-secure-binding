// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
)

func TestIdentityBindingFromConnectionStateRejectsInvalidTLSState(t *testing.T) {
	validation := testIdentityBindingValidation(t)

	tests := []struct {
		name    string
		state   *tls.ConnectionState
		wantErr string
	}{
		{
			name:    "missing state",
			state:   nil,
			wantErr: "missing TLS connection state",
		},
		{
			name: "handshake incomplete",
			state: &tls.ConnectionState{
				Version: tls.VersionTLS13,
			},
			wantErr: "TLS handshake is not complete",
		},
		{
			name: "not TLS 1.3",
			state: &tls.ConnectionState{
				Version:           tls.VersionTLS12,
				HandshakeComplete: true,
			},
			wantErr: "expected TLS 1.3 connection",
		},
		{
			name: "missing accepted leaf",
			state: &tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
			},
			wantErr: "missing validated leaf certificate",
		},
		{
			name: "missing validation context",
			state: &tls.ConnectionState{
				Version:           tls.VersionTLS13,
				HandshakeComplete: true,
			},
			wantErr: "missing certificate request context",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			currentValidation := validation
			if tt.name == "missing accepted leaf" {
				currentValidation = &ea.ValidationResult{Context: validation.Context}
			}
			if tt.name == "missing validation context" {
				currentValidation = &ea.ValidationResult{Chain: validation.Chain}
			}
			_, err := IdentityBindingFromConnectionState(tt.state, currentValidation)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("IdentityBindingFromConnectionState() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func testIdentityBindingValidation(t *testing.T) *ea.ValidationResult {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "identity-binding-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return &ea.ValidationResult{
		Context: []byte("identity-binding-test-context"),
		Chain:   []*x509.Certificate{leaf},
	}
}
