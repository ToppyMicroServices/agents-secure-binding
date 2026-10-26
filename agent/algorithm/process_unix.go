//go:build !windows && !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// ConfigureCommand bounds descriptor cleanup. Native execution is unavailable
// on these platforms because process groups cannot contain detached children.
func ConfigureCommand(cmd *exec.Cmd) {
	if cmd != nil {
		cmd.WaitDelay = time.Second
	}
}

// StartCommand fails before executing code without a complete lifetime boundary.
func StartCommand(cmd *exec.Cmd) error {
	return fmt.Errorf("native computation process containment is unavailable on %s", runtime.GOOS)
}

// WaitCommand waits for the configured computation process.
func WaitCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return errors.New("nil command")
	}
	return cmd.Wait()
}

// StopCommand handles commands already started outside StartCommand.
func StopCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
