//go:build !windows

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openStoreArchiveSnapshot copies one open source descriptor into a private
// temporary directory. Digest and SQLite checks then share bytes that neither
// path replacement nor an in-place write to the source can change.
func openStoreArchiveSnapshot(path string) (*storeArchiveSnapshot, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	original := os.NewFile(uintptr(fd), path)
	if original == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open archive file descriptor")
	}
	closeOriginal := true
	defer func() {
		if closeOriginal {
			_ = original.Close()
		}
	}()
	info, err := original.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("archive must be a regular file")
	}

	dir, err := os.MkdirTemp("", "asb-store-archive-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	temporary := filepath.Join(dir, "snapshot.sqlite")
	snapshot, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	closeSnapshot := true
	cleanupSnapshot := true
	defer func() {
		if closeSnapshot {
			_ = snapshot.Close()
		}
		if cleanupSnapshot {
			_ = os.Remove(temporary)
			_ = os.Remove(dir)
		}
	}()
	if _, err := io.Copy(snapshot, original); err != nil {
		return nil, err
	}
	if err := snapshot.Sync(); err != nil {
		return nil, err
	}
	if err := snapshot.Chmod(0o400); err != nil {
		return nil, err
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	closeOriginal = false
	closeSnapshot = false
	cleanupSnapshot = false
	return &storeArchiveSnapshot{
		file:         snapshot,
		original:     original,
		databasePath: temporary,
		cleanupPath:  temporary,
		cleanupDir:   dir,
	}, nil
}
