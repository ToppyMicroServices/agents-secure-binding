// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"os"
	"path/filepath"
)

// Backup creates a consistent standalone SQLite snapshot at a new local path.
// It never replaces an existing file. Close all writers before restoring by
// opening the backup path as a database. Restoring an older snapshot also rolls
// back replay/outcome knowledge; operators must fence old clients/workers and
// reconcile later external effects before resuming. This is not rollback
// protection or a substitute for an application recovery plan.
func (s *Store) Backup(ctx context.Context, destination string) error {
	if ctx == nil || destination == "" {
		return unavailable(os.ErrInvalid)
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return unavailable(err)
	}
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return unavailable(err)
	}
	if err := f.Close(); err != nil {
		return unavailable(err)
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", abs); err != nil {
		return unavailable(err)
	}
	// SQLite VACUUM INTO does not promise an fsync of its output. Flush both
	// the complete backup and directory entry before reporting success.
	f, err = os.OpenFile(abs, os.O_RDWR, 0)
	if err != nil {
		return unavailable(err)
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return unavailable(err)
	}
	if closeErr != nil {
		return unavailable(closeErr)
	}
	dir, err := os.Open(filepath.Dir(abs))
	if err != nil {
		return unavailable(err)
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil {
		return unavailable(err)
	}
	if closeErr != nil {
		return unavailable(closeErr)
	}
	return nil
}
