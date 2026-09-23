//go:build !windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// ConfigureCommand places a computation command and its ordinary descendants
// in a private process group. WaitDelay bounds waits on descriptors retained by
// a descendant that deliberately leaves that group.
func ConfigureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
}

// StartCommand starts a configured computation process.
func StartCommand(cmd *exec.Cmd) error {
	return cmd.Start()
}

// WaitCommand waits for the configured computation process.
func WaitCommand(cmd *exec.Cmd) error {
	return cmd.Wait()
}

// StopCommand terminates the computation process group.
func StopCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
