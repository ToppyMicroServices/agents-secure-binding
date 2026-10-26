//go:build !unix

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package qemu

import (
	"fmt"
	"os"
)

func checkStateOwnership(info os.FileInfo) error {
	return fmt.Errorf("VM state ownership validation is unsupported on this platform")
}
