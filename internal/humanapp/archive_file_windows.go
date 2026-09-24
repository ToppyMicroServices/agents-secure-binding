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

// openStoreArchiveSnapshot keeps a read handle that denies write and delete sharing.
// The SQLite read-only open can share reads, while another process cannot
// replace the pathname between the digest and database checks.
func openStoreArchiveSnapshot(path string) (*storeArchiveSnapshot, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("archive must be a regular file")
	}
	name, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), abs)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("open archive handle")
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	current, err := os.Lstat(abs)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, current) || !os.SameFile(opened, current) {
		_ = file.Close()
		return nil, fmt.Errorf("archive path changed while opening")
	}
	return &storeArchiveSnapshot{file: file, original: file, databasePath: abs}, nil
}
