// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEATKeyPair(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	privatePath := filepath.Join(t.TempDir(), "eat-signing-key.pem")
	publicPath := filepath.Join(t.TempDir(), "eat-verification-key.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	loadedPrivate, err := LoadSigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	loadedPublic, err := LoadVerificationKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPrivate.D.Cmp(privateKey.D) != 0 || !loadedPublic.Equal(&privateKey.PublicKey) {
		t.Fatal("loaded EAT keys do not match the encoded key pair")
	}
	fingerprint, err := VerificationKeyFingerprint(loadedPublic)
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d, want 64", len(fingerprint))
	}
}

func TestLoadSigningKeyRejectsBroadPermissions(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "insecure.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(path); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("LoadSigningKey() error = %v, want ErrInvalidSigningKey", err)
	}
}

func TestLoadEATKeysRejectP384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(t.TempDir(), "p384-private.pem")
	publicPath := filepath.Join(t.TempDir(), "p384-public.pem")
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(privatePath); !errors.Is(err, ErrInvalidSigningKey) {
		t.Fatalf("LoadSigningKey() error = %v, want ErrInvalidSigningKey", err)
	}
	if _, err := LoadVerificationKey(publicPath); !errors.Is(err, ErrInvalidVerificationKey) {
		t.Fatalf("LoadVerificationKey() error = %v, want ErrInvalidVerificationKey", err)
	}
}
