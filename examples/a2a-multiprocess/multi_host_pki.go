// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bootstrapMultiHostState(stateDir string, deployment multiHostDeploymentV1, trustManifestPath string) error {
	if stateDir == "" {
		return fmt.Errorf("state directory is required")
	}
	if err := requireEmptyBootstrapDirectory(stateDir); err != nil {
		return err
	}
	if trustManifestPath == "" {
		return fmt.Errorf("trust manifest path is required")
	}
	if _, err := os.Stat(trustManifestPath); err == nil {
		return fmt.Errorf("trust manifest already exists: %s", trustManifestPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect trust manifest path: %w", err)
	}
	for _, role := range append([]string{"agent-a"}, multiHostServerRoles...) {
		if pathWithin(trustManifestPath, roleDirectory(stateDir, role)) {
			return fmt.Errorf("trust manifest must be outside role credential directories")
		}
	}

	// The common bootstrap creates the signing-key trust relationships and any
	// role-local state. Only its TLS PKI is replaced below.
	if err := bootstrapState(stateDir); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := replaceTLSCredentialsForMultiHost(stateDir, deployment, now); err != nil {
		return err
	}
	manifest, err := buildMultiHostTrustManifest(stateDir, deployment, now)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode multi-host trust manifest: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeReportAtomically(trustManifestPath, payload); err != nil {
		return fmt.Errorf("write multi-host trust manifest: %w", err)
	}
	return nil
}

func requireEmptyBootstrapDirectory(stateDir string) error {
	entries, err := os.ReadDir(stateDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("multi-host bootstrap requires a new or empty state directory")
	}
	return nil
}

func replaceTLSCredentialsForMultiHost(stateDir string, deployment multiHostDeploymentV1, now time.Time) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate multi-host CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ASB multi-host test CA " + deployment.DeploymentID},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create multi-host CA: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parse multi-host CA: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	roles := append([]string{"agent-a"}, multiHostServerRoles...)
	for index, role := range roles {
		commonName := role
		switch role {
		case "agent-a":
			commonName = demoAgentIssuer
		case "agent-b":
			commonName = demoAudience
		}
		var dnsNames []string
		var ipAddresses []net.IP
		if endpoint, ok := deployment.Endpoints[role]; ok {
			parsed, err := url.Parse(endpoint.URL)
			if err != nil {
				return fmt.Errorf("parse %s endpoint: %w", role, err)
			}
			if address := net.ParseIP(parsed.Hostname()); address != nil {
				ipAddresses = []net.IP{address}
			} else {
				dnsNames = []string{parsed.Hostname()}
			}
		}
		if err := issueMultiHostRoleCertificate(now, big.NewInt(int64(index+2)), role, commonName, dnsNames, ipAddresses, ca, caKey, caPEM, roleDirectory(stateDir, role)); err != nil {
			return err
		}
	}
	return nil
}

func issueMultiHostRoleCertificate(now time.Time, serial *big.Int, role, commonName string, dnsNames []string, ipAddresses []net.IP, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate %s multi-host TLS key: %w", role, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     append([]string(nil), dnsNames...),
		IPAddresses:  append([]net.IP(nil), ipAddresses...),
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create %s multi-host TLS certificate: %w", role, err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal %s multi-host TLS key: %w", role, err)
	}
	if err := writeFile(filepath.Join(dir, caFile), caPEM, 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, tlsCertFile), certPEM, 0o644); err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, tlsKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
}

func pathWithin(path, directory string) bool {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absoluteDirectory, err := filepath.Abs(directory)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(absoluteDirectory, absolutePath)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
