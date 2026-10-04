//go:build !linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"os"
)

const durableReachabilitySupported = false

func singleLinkDatabaseFile(_ os.FileInfo) bool { return true }

// Existing TaskCoord SQLite operations retain their database locking on other
// platforms. The new external-callback reachability profile is Linux-only.
func (s *Store) acquireGrantGuard(_ context.Context, _ bool) (func(), error) {
	return func() {}, nil
}
