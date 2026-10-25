// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredEATSigningKeyPersistsAcrossStartup(t *testing.T) {
	want, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(want)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "eat-signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := configuredEATSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := configuredEATSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.D.Cmp(want.D) != 0 || second.D.Cmp(first.D) != 0 {
		t.Fatal("configured signing key changed across startup")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := configuredEATSigningKey(path); err == nil {
		t.Fatal("accepted a signing key readable by other users")
	}
}

func TestConfiguredEATSigningKeyDefaultsToEphemeral(t *testing.T) {
	first, err := configuredEATSigningKey("")
	if err != nil {
		t.Fatal(err)
	}
	second, err := configuredEATSigningKey("")
	if err != nil {
		t.Fatal(err)
	}
	if first.D.Cmp(second.D) == 0 {
		t.Fatal("unconfigured signing key was reused")
	}
}
