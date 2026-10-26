//go:build unix

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"fmt"
	"os"
	"syscall"
)

func checkStateOwnership(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || (info.Mode().IsRegular() && stat.Nlink != 1) {
		return fmt.Errorf("VM state path %q must be owned by the service user and not hard-linked", info.Name())
	}
	return nil
}
