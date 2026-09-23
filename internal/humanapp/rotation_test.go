// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotateCredentialsPreservesStateAndToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.db")
	state := []byte("state-must-not-change")
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenBefore, err := LoginToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := CredentialsStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !before.LegacyLayout || before.Generation != "legacy" {
		t.Fatalf("unexpected initial status: %+v", before)
	}

	after, err := RotateCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.LegacyLayout || after.Generation == "legacy" || after.Generation == before.Generation {
		t.Fatalf("rotation did not activate a generation: %+v", after)
	}
	if after.CAFingerprint == before.CAFingerprint {
		t.Fatal("rotation retained the old CA")
	}
	if !time.Now().UTC().Before(after.NotAfter) {
		t.Fatalf("rotated credentials are already expired: %s", after.NotAfter)
	}
	if _, err := loadCredentials(dir); err != nil {
		t.Fatalf("rotated credentials do not load: %v", err)
	}
	tokenAfter, err := LoginToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tokenAfter != tokenBefore {
		t.Fatal("credential rotation changed the independently managed login token")
	}
	gotState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotState) != string(state) {
		t.Fatalf("state changed across credential rotation: %q", gotState)
	}

	second, err := RotateCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation == after.Generation || second.CAFingerprint == after.CAFingerprint {
		t.Fatal("second rotation did not create a new generation")
	}
	if err := Initialize(dir); err != nil {
		t.Fatalf("initialized deployment no longer validates after rotation: %v", err)
	}
}

func TestRotateLoginTokenDoesNotRotateCertificates(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	beforeToken, err := LoginToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	beforeStatus, err := CredentialsStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := RotateLoginToken(dir); err != nil {
		t.Fatal(err)
	}
	afterToken, err := LoginToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	afterStatus, err := CredentialsStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if beforeToken == afterToken {
		t.Fatal("login token did not change")
	}
	if beforeStatus.CAFingerprint != afterStatus.CAFingerprint {
		t.Fatal("token rotation changed the credential generation")
	}
}

func TestMaintenanceRefusesActiveDataDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	lock, err := HoldDataDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := RotateLoginToken(dir); err == nil {
		t.Fatal("token rotation succeeded while the data directory was active")
	}
	if _, err := RotateCredentials(dir); err == nil {
		t.Fatal("credential rotation succeeded while the data directory was active")
	}
}

func TestCredentialPointerRejectsTraversal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, credentialPointerFile), []byte("../outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CredentialsStatus(dir); err == nil {
		t.Fatal("traversal generation pointer was accepted")
	}
	if _, err := loadCredentials(dir); err == nil {
		t.Fatal("credentials loaded through a traversal pointer")
	}
}

func TestAtomicWriteDoesNotLeaveTemporaryFileOnReplacementFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicPrivate(dir, "target", []byte("value")); err == nil {
		t.Fatal("replaced a directory with a private file")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "target" {
			t.Fatalf("temporary file remained after failure: %s", entry.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
