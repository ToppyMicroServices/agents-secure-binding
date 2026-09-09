// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const credentialsVersion = "asb-local-human-v1\n"

// Initialize creates private local demo credentials once. It never replaces
// an existing deployment or repairs partial initialization by discarding data.
func Initialize(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return ErrInvalid
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data directory must be a real directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("data directory must be private (mode 0700)")
	}
	if marker, err := os.ReadFile(filepath.Join(dir, "initialized")); err == nil {
		if string(marker) != credentialsVersion {
			return fmt.Errorf("unsupported local credentials version")
		}
		_, err = loadCredentials(dir)
		return err
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("incomplete initialization: use a new empty data directory; existing files were preserved")
	}
	now := time.Now().UTC()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ASB local approval CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		return err
	}
	if err := writePrivate(dir, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); err != nil {
		return err
	}
	// The CA signing key is deliberately not persisted; this is a fixed local
	// trust set, not a remotely accessible certificate enrollment service.
	for i, name := range []string{"server", "agent", "gateway"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		if name == "server" {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.DNSNames = []string{"localhost"}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
		} else {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		if err != nil {
			return err
		}
		if err := writePrivate(dir, name+".pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		if err := writePrivate(dir, name+"-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
			return err
		}
	}
	_, authorityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(authorityKey)
	if err != nil {
		return err
	}
	if err := writePrivate(dir, "authority-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	if err := writePrivate(dir, "ui-token", []byte(base64.RawURLEncoding.EncodeToString(token))); err != nil {
		return err
	}
	if err := writePrivate(dir, "initialized", []byte(credentialsVersion)); err != nil {
		return err
	}
	_, err = loadCredentials(dir)
	return err
}

func writePrivate(dir, name string, data []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Close()
}

func LoginToken(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "ui-token"))
	if err != nil {
		return "", err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid local login token")
	}
	return string(raw), nil
}

type credentials struct {
	server    tls.Certificate
	ca        *x509.CertPool
	authority ed25519.PrivateKey
	peers     map[string]*x509.Certificate
}

func loadCredentials(dir string) (*credentials, error) {
	marker, err := os.ReadFile(filepath.Join(dir, "initialized"))
	if err != nil || string(marker) != credentialsVersion {
		return nil, fmt.Errorf("initialize a complete local deployment first")
	}
	roots, err := loadRoots(dir)
	if err != nil {
		return nil, err
	}
	server, err := loadPair(dir, "server")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "authority-key.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid authority key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	authority, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("authority key must be Ed25519")
	}
	peers := make(map[string]*x509.Certificate)
	for actor, name := range map[string]string{ActorAgent: "agent", ActorGateway: "gateway"} {
		pair, err := loadPair(dir, name)
		if err != nil {
			return nil, err
		}
		if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return nil, fmt.Errorf("local client credentials are invalid or expired: %w", err)
		}
		peers[actor] = pair.Leaf
	}
	if _, err := server.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost"}); err != nil {
		return nil, fmt.Errorf("local server credentials are invalid or expired: %w", err)
	}
	if _, err := LoginToken(dir); err != nil {
		return nil, err
	}
	return &credentials{server, roots, authority, peers}, nil
}

func loadRoots(dir string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("invalid local CA")
	}
	return roots, nil
}

func loadPair(dir, name string) (tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
	if err != nil {
		return pair, err
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return pair, err
	}
	if _, ok := pair.PrivateKey.(ed25519.PrivateKey); !ok {
		return pair, fmt.Errorf("local key must be Ed25519")
	}
	return pair, nil
}

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
