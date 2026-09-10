//go:build !darwin && !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"os"
)

func acquireDurableLock(context.Context, string) (*os.File, error) { return nil, ErrStoreUnavailable }
func releaseDurableLock(f *os.File)                                { _ = f.Close() }
