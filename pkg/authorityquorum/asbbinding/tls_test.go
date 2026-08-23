// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	eaattestation "github.com/thinksyncs/agents-secure-binding/pkg/atls/eaattestation"
	"github.com/thinksyncs/agents-secure-binding/pkg/authorityquorum"
)

func TestBindingFromTLSDerivesVerifiedPeerBinding(t *testing.T) {
	t.Parallel()
	serverCertificate, clientCertificate, roots := testTLSCertificates(t)
	serverConfig, err := ServerTLSConfig(serverCertificate, roots)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: "server.test",
		Certificates: []tls.Certificate{clientCertificate},
	}
	serverPipe, clientPipe := net.Pipe()
	defer serverPipe.Close()
	defer clientPipe.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverPipe.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientPipe.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	server := tls.Server(serverPipe, serverConfig)
	client := tls.Client(clientPipe, clientConfig)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	request := authorityquorum.ApprovalRequest{
		DecisionID:      "decision:tls",
		PolicyDigest:    "sha256:" + strings.Repeat("a", 64),
		OperationDigest: "sha256:" + strings.Repeat("b", 64),
	}
	digest, err := authorityquorum.ApprovalDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	state := server.ConnectionState()
	binding, err := BindingFromTLS(&state, digest, "nonce:tls")
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := eaattestation.PublicKeyBytes(state.PeerCertificates[0])
	if err != nil {
		t.Fatal(err)
	}
	peerDigest := sha256.Sum256(peerKey)
	if binding.LeafPublicKeySHA256 != hex.EncodeToString(peerDigest[:]) ||
		binding.RequestContextSHA256 != authorityquorum.RequestContextSHA256(digest) ||
		binding.Nonce != "nonce:tls" || len(binding.TLSExporterSHA256) != 64 {
		t.Fatalf("TLS binding = %+v", binding)
	}

	invalid := state
	invalid.Version = tls.VersionTLS12
	if _, err := BindingFromTLS(&invalid, digest, "nonce:tls"); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("TLS 1.2 error = %v", err)
	}
	invalid = state
	invalid.VerifiedChains = nil
	if _, err := BindingFromTLS(&invalid, digest, "nonce:tls"); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("unverified peer error = %v", err)
	}
	invalid = state
	invalid.PeerCertificates = []*x509.Certificate{serverCertificate.Leaf}
	if _, err := BindingFromTLS(&invalid, digest, "nonce:tls"); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("mismatched verified leaf error = %v", err)
	}
	if _, err := BindingFromTLS(&state, digest, ""); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("missing nonce error = %v", err)
	}
}

func TestServerTLSConfigFailsClosed(t *testing.T) {
	t.Parallel()
	serverCertificate, _, roots := testTLSCertificates(t)
	if _, err := ServerTLSConfig(tls.Certificate{}, roots); err == nil {
		t.Fatal("empty server certificate was accepted")
	}
	if _, err := ServerTLSConfig(serverCertificate, nil); err == nil {
		t.Fatal("nil client CA pool was accepted")
	}
	config, err := ServerTLSConfig(serverCertificate, roots)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("server TLS config = %+v", config)
	}
}

func testTLSCertificates(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "authority quorum test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	server := testLeafCertificate(t, ca, caPrivate, 2, "server.test", x509.ExtKeyUsageServerAuth, now)
	client := testLeafCertificate(t, ca, caPrivate, 3, "client.test", x509.ExtKeyUsageClientAuth, now)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return server, client, roots
}

func testLeafCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caPrivate ed25519.PrivateKey,
	serial int64,
	commonName string,
	usage x509.ExtKeyUsage,
	now time.Time,
) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
		DNSNames: []string{commonName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: private, Leaf: leaf}
}
