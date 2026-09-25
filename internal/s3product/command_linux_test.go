// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

func TestAdministrationCreatesBacksUpAndRestoresNamespace(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "store")
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"init-store", "--directory", directory}, &output); err != nil {
		t.Fatal(err)
	}
	var initial lp.SQLiteStatus
	if err := json.Unmarshal(output.Bytes(), &initial); err != nil || initial.Namespace == "" {
		t.Fatal("missing namespace")
	}
	output.Reset()
	if err := Run(t.Context(), []string{"init-store", "--directory", directory}, &output); err == nil {
		t.Fatal("existing state reset")
	}
	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "snapshot.sqlite")
	if err := Run(t.Context(), []string{"backup", "--directory", directory, "--output", backup}, &output); err != nil {
		t.Fatal(err)
	}
	var manifest lp.SQLiteBackup
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := Run(t.Context(), []string{"restore", "--input", backup, "--directory", filepath.Join(t.TempDir(), "restored"), "--sha256", manifest.SHA256}, &output); err != nil {
		t.Fatal(err)
	}
	var restored lp.SQLiteStatus
	if err := json.Unmarshal(output.Bytes(), &restored); err != nil || restored.Namespace == initial.Namespace {
		t.Fatal("restore did not rotate authority")
	}
}

func TestAuthorityLeasePreventsConcurrentServers(t *testing.T) {
	directory := t.TempDir()
	first, err := authorityLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := authorityLock(directory); err == nil {
		_ = second.Close()
		t.Fatal("second authority acquired lease")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := authorityLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}
