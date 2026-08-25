// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caFile                 = "ca.pem"
	tlsCertFile            = "tls-cert.pem"
	tlsKeyFile             = "tls-key.pem"
	signingKeyFile         = "signing-key.pem"
	managerPublicFile      = "manager-public.pem"
	agentPublicFile        = "agent-public.pem"
	verifierPublicFile     = "verifier-public.pem"
	simPublicFile          = "simulation-attester-public.pem"
	resultSealingKeyFileV2 = "result-sealing.key"
)

type certificateSpec struct {
	Role       string
	CommonName string
	DNSName    string
}

func bootstrapState(stateDir string) error {
	if stateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	roles := []certificateSpec{
		{Role: "manager", CommonName: "manager", DNSName: "manager"},
		{Role: "attester", CommonName: "attester", DNSName: "attester"},
		{Role: "verifier", CommonName: "verifier", DNSName: "verifier"},
		{Role: "replay", CommonName: "replay", DNSName: "replay"},
		{Role: "agent-a", CommonName: demoAgentIssuer, DNSName: "agent-a"},
		{Role: "agent-b", CommonName: demoAudience, DNSName: "agent-b"},
	}
	for _, spec := range roles {
		if err := os.MkdirAll(roleDirectory(stateDir, spec.Role), 0o700); err != nil {
			return fmt.Errorf("create %s state directory: %w", spec.Role, err)
		}
	}

	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate demo CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ASB multiprocess demo CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create demo CA: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parse demo CA: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	for i, spec := range roles {
		dir := roleDirectory(stateDir, spec.Role)
		if err := writeFile(filepath.Join(dir, caFile), caPEM, 0o644); err != nil {
			return err
		}
		if err := issueRoleCertificate(now, big.NewInt(int64(i+2)), spec, ca, caKey, caPEM, dir); err != nil {
			return err
		}
	}

	managerKey, err := generateAndWriteSigningKey(filepath.Join(roleDirectory(stateDir, "manager"), signingKeyFile))
	if err != nil {
		return err
	}
	agentKey, err := generateAndWriteSigningKey(filepath.Join(roleDirectory(stateDir, "agent-a"), signingKeyFile))
	if err != nil {
		return err
	}
	verifierKey, err := generateAndWriteSigningKey(filepath.Join(roleDirectory(stateDir, "verifier"), signingKeyFile))
	if err != nil {
		return err
	}
	simulationKey, err := generateAndWriteSigningKey(filepath.Join(roleDirectory(stateDir, "attester"), signingKeyFile))
	if err != nil {
		return err
	}

	if err := writePublicKey(filepath.Join(roleDirectory(stateDir, "agent-b"), managerPublicFile), &managerKey.PublicKey); err != nil {
		return err
	}
	if err := writePublicKey(filepath.Join(roleDirectory(stateDir, "agent-b"), agentPublicFile), &agentKey.PublicKey); err != nil {
		return err
	}
	if err := writePublicKey(filepath.Join(roleDirectory(stateDir, "agent-b"), verifierPublicFile), &verifierKey.PublicKey); err != nil {
		return err
	}
	if err := writePublicKey(filepath.Join(roleDirectory(stateDir, "verifier"), simPublicFile), &simulationKey.PublicKey); err != nil {
		return err
	}
	resultSealingKey := make([]byte, 32)
	if _, err := rand.Read(resultSealingKey); err != nil {
		return fmt.Errorf("generate Agent B result sealing key: %w", err)
	}
	if err := writeFile(filepath.Join(roleDirectory(stateDir, "agent-b"), resultSealingKeyFileV2), resultSealingKey, 0o600); err != nil {
		return err
	}
	return nil
}

func issueRoleCertificate(now time.Time, serial *big.Int, spec certificateSpec, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate %s TLS key: %w", spec.Role, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: spec.CommonName},
		DNSNames:     []string{spec.DNSName, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create %s TLS certificate: %w", spec.Role, err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal %s TLS key: %w", spec.Role, err)
	}
	if err := writeFile(filepath.Join(dir, tlsCertFile), certPEM, 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, tlsKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
}

func generateAndWriteSigningKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal signing key: %w", err)
	}
	if err := writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func writePublicKey(path string, key *ecdsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("set permissions on %s: %w", path, err)
	}
	return nil
}

func roleDirectory(stateDir, role string) string {
	return filepath.Join(stateDir, role)
}
