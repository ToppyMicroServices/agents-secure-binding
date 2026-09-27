// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func confineCommand(cmd *exec.Cmd) {
	// Cancellation reaches ordinary CLI children as well as its direct process.
	// systemd's cgroup is still required for crash cleanup and processes which
	// deliberately leave this process group. The operator controls the CLI path.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
