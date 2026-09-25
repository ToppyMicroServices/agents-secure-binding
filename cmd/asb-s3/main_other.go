//go:build !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "asb-s3 requires Linux")
	os.Exit(1)
}
