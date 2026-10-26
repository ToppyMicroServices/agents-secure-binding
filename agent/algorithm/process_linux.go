//go:build linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// ConfigureCommand makes the computation the init process of a new PID
// namespace. Its exit makes the kernel kill and reap every descendant,
// including children that create another session or nested PID namespace.
// The user namespace permits atomic creation by the unprivileged runner.
func ConfigureCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1,
		}},
		GidMappingsEnableSetgroups: false,
	}
	cmd.WaitDelay = time.Second
}

// StartCommand establishes containment before any computation code executes.
// A kernel or service policy that disallows namespaces causes launch to fail;
// there is no process-group fallback.
func StartCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return errors.New("nil command")
	}
	ConfigureCommand(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start contained computation: %w", err)
	}
	return nil
}

// WaitCommand waits for namespace init to be reaped. Linux does not permit
// that until every process in the namespace has exited, so callers retain
// their running state throughout descendant teardown, including on error.
func WaitCommand(cmd *exec.Cmd) error {
	if cmd == nil {
		return errors.New("nil command")
	}
	return cmd.Wait()
}

// StopCommand kills namespace init from the parent namespace. SIGKILL cannot
// be ignored by init; the kernel also terminates all of its descendants.
// WaitCommand remains responsible for waiting for complete teardown.
func StopCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}
