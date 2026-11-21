// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func identifyProcess(pid int) (*os.Process, ProcessIdentity, error) {
	if pid <= 0 {
		return nil, ProcessIdentity{}, fmt.Errorf("invalid PID %d", pid)
	}
	// procfs must refer to the same PID namespace as pidfd_open.
	self, err := os.Readlink("/proc/self")
	if err != nil {
		return nil, ProcessIdentity{}, err
	}
	if self != strconv.Itoa(os.Getpid()) {
		return nil, ProcessIdentity{}, errors.New("procfs PID namespace mismatch")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, ProcessIdentity{}, err
	}
	var id ProcessIdentity
	var readErr error
	err = process.WithHandle(func(fd uintptr) {
		id, readErr = processIdentityFromFD(pid, int(fd))
	})
	if err == nil {
		err = readErr
	} else if errors.Is(err, os.ErrNoHandle) {
		// FindProcess can also return a handle-less process for an absent PID.
		// Probe procfs for absence only. Never send signals through a PID fallback.
		if _, statErr := os.Stat("/proc/" + strconv.Itoa(pid)); errors.Is(statErr, os.ErrNotExist) {
			err = ErrVMProcessGone
		}
	}
	if err != nil {
		_ = process.Release()
		return nil, ProcessIdentity{}, err
	}
	return process, id, nil
}

func processIdentityFromFD(pid, fd int) (ProcessIdentity, error) {
	procDir := "/proc/" + strconv.Itoa(pid)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProcessIdentity{}, err
	}
	stat, err := os.ReadFile(procDir + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		if exited, pollErr := pollProcess(fd, 0); pollErr == nil && exited {
			return ProcessIdentity{}, ErrVMProcessGone
		}
	}
	if err != nil {
		return ProcessIdentity{}, err
	}
	// The second field, comm, can contain spaces and parentheses. Everything
	// following its last closing parenthesis starts at field 3 (state).
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return ProcessIdentity{}, errors.New("malformed proc stat record")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) <= 19 {
		return ProcessIdentity{}, errors.New("missing proc stat start time")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcessIdentity{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return ProcessIdentity{}, err
	}
	id := ProcessIdentity{BootID: strings.TrimSpace(string(boot)), StartTicks: ticks}
	var st unix.Stat_t
	if fs.Type == unix.PID_FS_MAGIC {
		// Linux 6.9+ gives each kernel process a stable pidfs inode.
		id.InodeFS = "pidfs"
		err = unix.Fstat(fd, &st)
	} else {
		// Older pidfds use a shared anonymous inode. Compare the procfs
		// directory inode instead. If procfs changes, recovery fails closed.
		id.InodeFS = "procfs"
		err = unix.Stat(procDir, &st)
	}
	if err != nil {
		return ProcessIdentity{}, err
	}
	id.Inode = st.Ino
	if id.BootID == "" || id.Inode == 0 {
		return ProcessIdentity{}, errors.New("missing kernel process identity")
	}
	// If the pinned process exited while reading /proc/PID, those reads might
	// already describe a replacement. Never adopt that mixed identity.
	exited, err := pollProcess(fd, 0)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if exited {
		return ProcessIdentity{}, ErrVMProcessGone
	}
	return id, nil
}

func waitForRestoredProcess(p *os.Process, timeout time.Duration) (bool, error) {
	var exited bool
	var pollErr error
	if err := p.WithHandle(func(fd uintptr) {
		exited, pollErr = pollProcess(int(fd), timeout)
	}); err != nil {
		return false, err
	}
	return exited, pollErr
}

func pollProcess(fd int, timeout time.Duration) (bool, error) {
	pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		ms := max(0, (time.Until(deadline)+time.Millisecond-1)/time.Millisecond)
		n, err := unix.Poll(pfds, int(ms))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return false, err
		}
		if pfds[0].Revents&(unix.POLLIN|unix.POLLHUP) == 0 {
			return false, fmt.Errorf("unexpected pidfd poll events %#x", pfds[0].Revents)
		}
		return true, nil
	}
}
