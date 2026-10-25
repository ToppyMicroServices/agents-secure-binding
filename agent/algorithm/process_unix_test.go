//go:build !windows && !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCommandRejectedBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	cmd := exec.Command("/bin/sh", "-c", ": > \"$1\"", "sh", marker)
	ConfigureCommand(cmd)
	if err := StartCommand(cmd); err == nil || !strings.Contains(err.Error(), "containment is unavailable") {
		t.Fatalf("StartCommand = %v, want unavailable containment error", err)
	}
	if cmd.Process != nil {
		t.Fatal("unsupported command was started")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("computation executed despite unsupported containment: %v", err)
	}
	if err := StopCommand(cmd); err != nil {
		t.Fatal(err)
	}
}
