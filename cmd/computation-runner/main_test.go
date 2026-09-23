// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenRunnerSocketIsOwnerOnly(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "asb-runner-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "runtime", "runner.sock")
	requireMode := os.FileMode(0o755)
	if err := os.Mkdir(filepath.Dir(path), requireMode); err != nil {
		t.Fatal(err)
	}
	listener, err := listenRunnerSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != requireMode {
		t.Fatalf("socket directory mode changed to %o, want %o", got, requireMode)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("owner could not connect: %v", err)
	}
	_ = conn.Close()
}

func TestListenRunnerSocketRefusesNonSocketPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runner.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenRunnerSocket(path); err == nil {
		t.Fatal("non-socket path was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not replace" {
		t.Fatalf("non-socket content changed: %q", data)
	}
}
