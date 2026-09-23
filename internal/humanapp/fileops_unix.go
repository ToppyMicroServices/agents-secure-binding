//go:build !windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// DataDirectoryLock is released automatically by the OS if the process exits.
type DataDirectoryLock struct {
	file *os.File
}

func acquireDataDirectoryLock(dir string, exclusive bool) (*DataDirectoryLock, error) {
	file, err := os.OpenFile(filepath.Join(dir, ".asb-human.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	op := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		op = unix.LOCK_EX | unix.LOCK_NB
	}
	if err := unix.Flock(int(file.Fd()), op); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("data directory is in use: %w", err)
	}
	return &DataDirectoryLock{file: file}, nil
}

func (l *DataDirectoryLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

func replaceFile(temporary, target string) error {
	return os.Rename(temporary, target)
}

func moveNewFile(temporary, target string) error {
	if err := os.Link(temporary, target); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		_ = os.Remove(target)
		return err
	}
	return nil
}

func syncDirectory(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
