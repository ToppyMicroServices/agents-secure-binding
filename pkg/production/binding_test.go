// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func productionTestTLS13(t *testing.T) (*tls.Conn, *tls.Conn, *x509.Certificate) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "production-binding"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}

	serverSide, clientSide := net.Pipe()
	server := tls.Server(serverSide, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	client := tls.Client(clientSide, &tls.Config{
		InsecureSkipVerify: true, // The generated certificate is scoped to this test.
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	errCh := make(chan error, 2)
	go func() { errCh <- server.Handshake() }()
	go func() { errCh <- client.Handshake() }()
	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("TLS 1.3 handshake: %v", err)
		}
	}
	return server, client, leaf
}

func TestSoftwareBindingFromTLSOmitsOnlyAttestationBinder(t *testing.T) {
	server, client, leaf := productionTestTLS13(t)
	defer server.Close()
	defer client.Close()

	state := client.ConnectionState()
	action := []byte(`{"operation":"offer.create","candidate":"candidate-42"}`)
	nonce := "verifier-nonce-42"
	attested, err := BindingFromTLS(&state, leaf, action, nonce)
	if err != nil {
		t.Fatal(err)
	}
	softwareOnly, err := SoftwareBindingFromTLS(&state, leaf, action, nonce)
	if err != nil {
		t.Fatal(err)
	}

	if softwareOnly.LeafPublicKeySHA256 != attested.LeafPublicKeySHA256 ||
		softwareOnly.TLSExporterSHA256 != attested.TLSExporterSHA256 ||
		softwareOnly.RequestContextSHA256 != attested.RequestContextSHA256 ||
		softwareOnly.Nonce != attested.Nonce {
		t.Fatalf("software-only binding changed a shared TLS/action field")
	}
	if attested.AttestationBinderSHA256 == "" {
		t.Fatal("attested binding omitted attestation binder")
	}
	if softwareOnly.AttestationBinderSHA256 != "" {
		t.Fatal("software-only binding included attestation binder")
	}
}

func TestSoftwareBindingFromTLSRejectsIncompleteInputs(t *testing.T) {
	server, client, leaf := productionTestTLS13(t)
	defer server.Close()
	defer client.Close()
	state := client.ConnectionState()

	tests := []struct {
		name   string
		state  *tls.ConnectionState
		leaf   *x509.Certificate
		action []byte
		nonce  string
	}{
		{name: "missing state", leaf: leaf, action: []byte("action"), nonce: "nonce"},
		{name: "missing leaf", state: &state, action: []byte("action"), nonce: "nonce"},
		{name: "missing action", state: &state, leaf: leaf, nonce: "nonce"},
		{name: "blank nonce", state: &state, leaf: leaf, action: []byte("action"), nonce: "  "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := SoftwareBindingFromTLS(test.state, test.leaf, test.action, test.nonce)
			if !errors.Is(err, ErrInvalidAcceptedBinding) {
				t.Fatalf("got %v, want %v", err, ErrInvalidAcceptedBinding)
			}
		})
	}
}
