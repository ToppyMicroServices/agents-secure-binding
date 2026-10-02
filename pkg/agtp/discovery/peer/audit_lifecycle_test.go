// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditRotationRecoversAfterFilesystemFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event := AuditEvent{NodeID: testNodeID("01"), Action: "replicate", Result: "ok", Reason: strings.Repeat("x", 500)}
	if err := log.Write(event); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A non-empty backup directory makes rotation fail after the initial sync.
	backup := path + ".1"
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(backup, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := log.Write(event); err == nil {
		t.Fatal("rotation failure was acknowledged")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(backup); err != nil {
		t.Fatal(err)
	}
	if err := log.Write(event); err != nil {
		t.Fatalf("audit did not recover after rotation became available: %v", err)
	}
	rotated, err := os.ReadFile(backup)
	if err != nil || string(rotated) != string(original) {
		t.Fatalf("rotation lost the original audit event: %v", err)
	}
	current, err := os.ReadFile(path)
	if err != nil || len(current) == 0 || len(current) > 1024 {
		t.Fatalf("replacement audit file size = %d, error = %v", len(current), err)
	}
}

func TestAuditCloseReleasesDescriptorAfterSyncFailure(t *testing.T) {
	log, err := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	unflushable, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unflushable.Close() })
	if err := unflushable.Sync(); err == nil {
		t.Skip("this platform permits syncing the null device")
	}
	if err := log.file.Close(); err != nil {
		t.Fatal(err)
	}
	log.file = unflushable
	if err := log.Close(); err == nil {
		t.Fatal("flush failure was hidden")
	}
	if _, err := unflushable.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("failed flush left the descriptor open: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("repeated Close failed: %v", err)
	}
	if err := log.Write(AuditEvent{Action: "replicate"}); err == nil {
		t.Fatal("Write reopened an explicitly closed audit log")
	}
}

func TestAuditRejectsEventLargerThanRotationLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := NewAuditLog(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if err := log.Write(AuditEvent{Action: "replicate", Reason: strings.Repeat("x", 1024)}); err == nil {
		t.Fatal("oversized audit event was admitted")
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() != 0 {
		t.Fatalf("rejected event changed the audit file: %v", err)
	}
	if err := log.Write(AuditEvent{Action: "replicate", Result: "ok"}); err != nil {
		t.Fatalf("bounded event did not recover after rejection: %v", err)
	}
}
