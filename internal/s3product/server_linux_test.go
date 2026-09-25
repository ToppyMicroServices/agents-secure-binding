// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
)

func TestProductServerRequiresMutualTLSAndASBProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	public, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rawCA, err := x509.CreateCertificate(rand.Reader, ca, ca, public, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rawCA})
	pair := func(serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		raw, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		rawKey, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})
	}
	serverCert, serverKey := pair(2, x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := pair(3, x509.ExtKeyUsageClientAuth)
	authority, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actor, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "store")
	store, err := lp.CreateSQLiteStore(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	namespace := store.Namespace()
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	profile := []byte(`{"schema":"asb.least-privilege.aws-s3/v1","role_arn":"arn:aws:iam::111122223333:role/asb-reader","region":"eu-west-1","credential_profile":"oidc","objects":[{"arn":"arn:aws:s3:::asb-test-bucket/read.txt","cost":1,"owner_account":"111122223333"}],"grants":[{"id":"read","policy":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::asb-test-bucket/read.txt"]}]}}],"required":["arn:aws:s3:::asb-test-bucket/read.txt"],"allowed":["arn:aws:s3:::asb-test-bucket/read.txt"],"max_response_bytes":1024}`)
	cli := write("aws", []byte("#!/bin/sh\nexit 91\n"))
	if err = os.Chmod(cli, 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: ConfigSchema, Namespace: namespace, Listen: address, StoreDirectory: directory, ProfileFile: write("profile.json", profile), MandatesFile: write("mandates.json", []byte("[]")), SigningKeyFile: write("signer.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingDER})), CertificateFile: write("server.pem", serverCert), TLSKeyFile: write("server-key.pem", serverKey), ClientCAFile: write("ca.pem", caPEM), AWSCLI: cli, WebIdentityTokenFile: write("token", []byte("header.payload.signature")), Issuer: "authority", Audience: "s3-reader", GrantKeys: map[string]ed25519.PublicKey{"authority": authority}, ActorKeys: map[string]ed25519.PublicKey{"actor": actor}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := write("config.json", raw)
	serverContext, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- Serve(serverContext, configPath) }()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	clientPair, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientPair}}, MaxConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	op := asbbinding.Operation{ID: namespace + "/read", MandateID: namespace + "/mandate", Action: lp.Action{Operation: "s3:GetObject", Resource: "arn:aws:s3:::asb-test-bucket/read.txt"}}
	body, err := json.Marshal(asbbinding.HTTPChallengeRequest{Mode: "execute", Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	var response *http.Response
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+"/challenge", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err = client.Do(request)
		if err == nil {
			break
		}
		select {
		case err = <-done:
			t.Fatalf("server failed: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	raw, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("TLS challenge: %d %s %v", response.StatusCode, raw, err)
	}
	var challenge asbbinding.HTTPChallenge
	if err = json.Unmarshal(raw, &challenge); err != nil || challenge.ChallengeID == "" {
		t.Fatal("invalid challenge")
	}
	input, err := json.Marshal(asbbinding.HTTPExecuteRequest{ChallengeID: challenge.ChallengeID, Operation: op})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+"/execute", bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("execution accepted without mandate/proof")
	}
	anonymous := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost"}}
	defer anonymous.CloseIdleConnections()
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+"/challenge", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if response, err = (&http.Client{Transport: anonymous, Timeout: time.Second}).Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("listener accepted missing client certificate")
	}
	stop()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("server did not stop")
	}
}
