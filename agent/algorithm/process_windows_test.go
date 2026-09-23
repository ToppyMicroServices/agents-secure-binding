//go:build windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestConfigureCommandPreservesCreationFlagsAndSuspends(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	ConfigureCommand(cmd)
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatal("ConfigureCommand discarded an existing creation flag")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_SUSPENDED == 0 {
		t.Fatal("ConfigureCommand did not require suspended launch")
	}
}

func TestStartAndWaitContainedCommand(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit", "0")
	ConfigureCommand(cmd)
	if err := StartCommand(cmd); err != nil {
		t.Fatal(err)
	}
	if err := WaitCommand(cmd); err != nil {
		t.Fatal(err)
	}
}
