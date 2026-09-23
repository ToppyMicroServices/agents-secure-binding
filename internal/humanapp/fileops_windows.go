//go:build windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// DataDirectoryLock is released automatically by the OS if the process exits.
type DataDirectoryLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireDataDirectoryLock(dir string, exclusive bool) (*DataDirectoryLock, error) {
	file, err := os.OpenFile(filepath.Join(dir, ".asb-human.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	lock := &DataDirectoryLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("data directory is in use: %w", err)
	}
	return lock, nil
}

func (l *DataDirectoryLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

func replaceFile(temporary, target string) error {
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func moveNewFile(temporary, target string) error {
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func syncDirectory(string) error {
	// MoveFileEx with MOVEFILE_WRITE_THROUGH is the Windows durability boundary
	// for the pointer replacement.
	return nil
}
