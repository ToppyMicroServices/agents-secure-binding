//go:build !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import "os/exec"

// The product runs on Linux; other platforms retain the library's direct-child
// cancellation behavior and do not claim process-tree confinement.
func confineCommand(_ *exec.Cmd) {}
