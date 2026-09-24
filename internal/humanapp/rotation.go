// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	credentialPointerFile = "credential-generation"
	credentialSetsDir     = "credential-generations"
	credentialLegacy      = "legacy"
	goosWindows           = "windows"
)

// CredentialStatus describes the active local trust generation without
// exposing private key or bootstrap-token material.
type CredentialStatus struct {
	Generation    string
	LegacyLayout  bool
	NotAfter      time.Time
	CAFingerprint string
}

func validateInitializedDirectory(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return ErrInvalid
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data directory must be a real directory")
	}
	if runtime.GOOS != goosWindows && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("data directory must be private (mode 0700)")
	}
	marker, err := os.ReadFile(filepath.Join(dir, "initialized"))
	if err != nil || string(marker) != credentialsVersion {
		return fmt.Errorf("initialize a complete local deployment first")
	}
	return nil
}

// HoldDataDirectory prevents offline credential maintenance while a process is
// using the local trust set. The caller must close the returned lock.
func HoldDataDirectory(dir string) (*DataDirectoryLock, error) {
	if err := validateInitializedDirectory(dir); err != nil {
		return nil, err
	}
	return acquireDataDirectoryLock(dir, false)
}

// RotateLoginToken replaces the bootstrap token without printing it. Existing
// in-memory sessions are invalidated at the documented service restart boundary.
func RotateLoginToken(dir string) error {
	if err := validateInitializedDirectory(dir); err != nil {
		return err
	}
	lock, err := acquireDataDirectoryLock(dir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := LoginToken(dir); err != nil {
		return err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(token))
	if err := writeAtomicPrivate(dir, "ui-token", encoded); err != nil {
		return err
	}
	_, err = LoginToken(dir)
	return err
}

// RotateCredentials creates and validates a complete trust generation before
// atomically activating it. Database files, receipts, and the login token are
// not moved or rewritten.
func RotateCredentials(dir string) (CredentialStatus, error) {
	if err := validateInitializedDirectory(dir); err != nil {
		return CredentialStatus{}, err
	}
	lock, err := acquireDataDirectoryLock(dir, true)
	if err != nil {
		return CredentialStatus{}, err
	}
	defer lock.Close()
	if _, _, err := activeCredentialDirectory(dir); err != nil {
		return CredentialStatus{}, err
	}
	if _, err := LoginToken(dir); err != nil {
		return CredentialStatus{}, err
	}
	setsDir := filepath.Join(dir, credentialSetsDir)
	if err := os.MkdirAll(setsDir, 0o700); err != nil {
		return CredentialStatus{}, err
	}
	if err := validatePrivateDirectory(setsDir); err != nil {
		return CredentialStatus{}, err
	}
	name, err := newCredentialGenerationName()
	if err != nil {
		return CredentialStatus{}, err
	}
	generationDir := filepath.Join(setsDir, name)
	if err := os.Mkdir(generationDir, 0o700); err != nil {
		return CredentialStatus{}, err
	}
	// Reuse the fully validated initializer in an isolated generation. The
	// generation-local bootstrap token is removed because the deployment-level
	// token has a separate rotation lifecycle.
	if err := Initialize(generationDir); err != nil {
		return CredentialStatus{}, fmt.Errorf("create staged credentials: %w", err)
	}
	if err := os.Remove(filepath.Join(generationDir, "ui-token")); err != nil {
		return CredentialStatus{}, err
	}
	if err := syncDirectory(generationDir); err != nil {
		return CredentialStatus{}, err
	}
	if err := writeAtomicPrivate(dir, credentialPointerFile, []byte(name+"\n")); err != nil {
		return CredentialStatus{}, err
	}
	return credentialStatusUnlocked(dir)
}

func validatePrivateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential directory must be a real directory")
	}
	if runtime.GOOS != goosWindows && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credential directory must be private (mode 0700)")
	}
	return nil
}

func newCredentialGenerationName() (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "gen-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + hex.EncodeToString(random[:]), nil
}

// CredentialsStatus returns non-secret metadata for the active trust set.
func CredentialsStatus(dir string) (CredentialStatus, error) {
	if err := validateInitializedDirectory(dir); err != nil {
		return CredentialStatus{}, err
	}
	lock, err := acquireDataDirectoryLock(dir, false)
	if err != nil {
		return CredentialStatus{}, err
	}
	defer lock.Close()
	return credentialStatusUnlocked(dir)
}

func credentialStatusUnlocked(dir string) (CredentialStatus, error) {
	credentialDir, generation, err := activeCredentialDirectory(dir)
	if err != nil {
		return CredentialStatus{}, err
	}
	raw, err := os.ReadFile(filepath.Join(credentialDir, "ca.pem"))
	if err != nil {
		return CredentialStatus{}, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return CredentialStatus{}, fmt.Errorf("invalid local CA")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA {
		return CredentialStatus{}, fmt.Errorf("invalid local CA")
	}
	fingerprint := sha256.Sum256(block.Bytes)
	return CredentialStatus{
		Generation:    generation,
		LegacyLayout:  generation == credentialLegacy,
		NotAfter:      ca.NotAfter.UTC(),
		CAFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
	}, nil
}

func activeCredentialDirectory(dir string) (string, string, error) {
	pointer := filepath.Join(dir, credentialPointerFile)
	info, err := os.Lstat(pointer)
	if errors.Is(err, os.ErrNotExist) {
		return dir, credentialLegacy, nil
	}
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 128 {
		return "", "", fmt.Errorf("invalid credential generation pointer")
	}
	if runtime.GOOS != goosWindows && info.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("credential generation pointer must be private")
	}
	raw, err := os.ReadFile(pointer)
	if err != nil {
		return "", "", err
	}
	name := strings.TrimSpace(string(raw))
	if !validGenerationName(name) {
		return "", "", fmt.Errorf("invalid credential generation pointer")
	}
	credentialDir := filepath.Join(dir, credentialSetsDir, name)
	if err := validatePrivateDirectory(credentialDir); err != nil {
		return "", "", err
	}
	marker, err := os.ReadFile(filepath.Join(credentialDir, "initialized"))
	if err != nil || string(marker) != credentialsVersion {
		return "", "", fmt.Errorf("unsupported credential generation")
	}
	return credentialDir, name, nil
}

func validGenerationName(name string) bool {
	if !strings.HasPrefix(name, "gen-") || len(name) < 16 || len(name) > 96 || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' && r != 'T' && r != 'Z' {
			return false
		}
	}
	return true
}

func writeAtomicPrivate(dir, name string, data []byte) error {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temporary := filepath.Join(dir, "."+name+"."+hex.EncodeToString(suffix[:])+".tmp")
	f, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = f.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporary, filepath.Join(dir, name)); err != nil {
		return err
	}
	remove = false
	return syncDirectory(dir)
}
