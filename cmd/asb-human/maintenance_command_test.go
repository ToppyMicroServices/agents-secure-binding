// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func runMaintenanceCommand(t *testing.T, args ...string) map[string]any {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), args, &stdout, &stderr); err != nil {
		t.Fatalf("run %v: %v; stderr=%s", args, err, stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %v output %q: %v", args, stdout.String(), err)
	}
	return result
}

func TestMaintenanceCommandsRotateAndArchive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if event := runMaintenanceCommand(t, "init", "--data-dir", dir)["event"]; event != "initialized" {
		t.Fatalf("init event = %v", event)
	}
	before := runMaintenanceCommand(t, "credentials-status", "--data-dir", dir)
	if before["event"] != "credentials_status" || before["generation"] != "legacy" {
		t.Fatalf("initial status = %+v", before)
	}
	if event := runMaintenanceCommand(t, "token-rotate", "--data-dir", dir)["event"]; event != "token_rotated" {
		t.Fatalf("token event = %v", event)
	}
	after := runMaintenanceCommand(t, "credentials-rotate", "--data-dir", dir)
	if after["event"] != "credentials_rotated" || after["generation"] == "legacy" {
		t.Fatalf("rotation status = %+v", after)
	}
	status := runMaintenanceCommand(t, "storage-status", "--data-dir", dir)
	if status["event"] != "storage_status" {
		t.Fatalf("storage status = %+v", status)
	}
	archive := filepath.Join(t.TempDir(), "archive", "state.sqlite")
	exported := runMaintenanceCommand(t, "storage-export", "--data-dir", dir, "--output", archive)
	if exported["event"] != "storage_exported" {
		t.Fatalf("storage export = %+v", exported)
	}
	verified := runMaintenanceCommand(t, "storage-verify", "--data-dir", dir, "--archive", archive)
	if verified["event"] != "storage_verified" {
		t.Fatalf("storage verify = %+v", verified)
	}
}
