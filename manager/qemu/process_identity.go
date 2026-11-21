// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"errors"
	"fmt"
	"os"
)

// ErrVMProcessGone means the target process no longer exists. Other errors,
// including ordinary filesystem errors and identity mismatches, can require
// manual reconciliation and must not be treated as proof of exit.
var ErrVMProcessGone = errors.New("VM process exited")

// ProcessIdentity records the kernel boot, process start time, and per-process
// inode. An empty identity in an older state file cannot authorize reattachment.
type ProcessIdentity struct {
	BootID     string
	StartTicks uint64
	Inode      uint64
	InodeFS    string
}

// CaptureProcessIdentity is used while the Manager still owns its unreaped child.
func CaptureProcessIdentity(pid int) (ProcessIdentity, error) {
	process, id, err := identifyProcess(pid)
	if process != nil {
		_ = process.Release()
	}
	return id, err
}

// RestoreProcess returns an owned, pinned process handle on success. The caller
// must release it or transfer it to the VM.
func RestoreProcess(pid int, expected ProcessIdentity) (*os.Process, error) {
	if expected == (ProcessIdentity{}) {
		return nil, errors.New("persisted VM has no process identity")
	}
	process, actual, err := identifyProcess(pid)
	if err != nil {
		return nil, err
	}
	if actual != expected {
		_ = process.Release()
		return nil, fmt.Errorf("persisted VM process identity differs from live PID %d", pid)
	}
	return process, nil
}
