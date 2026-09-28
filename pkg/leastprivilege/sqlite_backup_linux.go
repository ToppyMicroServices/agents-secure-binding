// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SQLiteBackup identifies a sealed snapshot. The digest detects corruption; it
// is not an authenticity signature. Backups cannot be opened for execution.
type SQLiteBackup struct {
	SHA256    string `json:"sha256"`
	Namespace string `json:"namespace"`
}

func privateDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode().Perm()&0o077 == 0
}

func syncSQLiteFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Backup atomically publishes a new sealed snapshot in an owner-only directory.
// WAL is included by SQLite, rather than copying a live main database file.
func (s *SQLiteStore) Backup(ctx context.Context, destination string) (SQLiteBackup, error) {
	return s.backup(ctx, destination, func(string) {})
}

// checkpoint observes publication boundaries for process-interruption tests.
func (s *SQLiteStore) backup(ctx context.Context, destination string, checkpoint func(string)) (SQLiteBackup, error) {
	if s == nil || s.db == nil || ctx == nil || !filepath.IsAbs(destination) || !privateDirectory(filepath.Dir(destination)) || strings.HasPrefix(filepath.Base(destination), ".asb-s3-backup") {
		return SQLiteBackup{}, ErrStoreUnavailable
	}
	lock, err := backupLock(filepath.Dir(destination))
	if err != nil {
		return SQLiteBackup{}, err
	}
	defer lock.Close()
	if _, err = recoverSQLiteBackups(ctx, filepath.Dir(destination)); err != nil {
		return SQLiteBackup{}, err
	}
	path, err := newBackupWorkspace(filepath.Dir(destination))
	if err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	defer removeBackupTemporary(path)
	checkpoint("created")
	if _, err = s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	checkpoint("snapshot")
	db, err := openSQLiteFile(path)
	if err != nil {
		return SQLiteBackup{}, err
	}
	defer db.Close()
	namespace, backup, err := sqliteMetadata(ctx, db)
	if err != nil || backup != 0 || namespace != s.namespace {
		return SQLiteBackup{}, ErrStoreUnavailable
	}
	if _, err = db.ExecContext(ctx, `PRAGMA journal_mode=DELETE`); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE metadata SET backup=1 WHERE id=1`); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if err = db.Close(); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if err = syncSQLiteFile(path); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	checkpoint("sealed")
	f, err := os.Open(path)
	if err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	h := sha256.New()
	_, err = copySQLiteContext(ctx, h, f)
	closeErr := f.Close()
	if err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if closeErr != nil {
		return SQLiteBackup{}, storeError(closeErr)
	}
	// link is an atomic no-replace publication on the same filesystem.
	if err = ctx.Err(); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if err = os.Link(path, destination); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	if err = syncDirectory(filepath.Dir(destination)); err != nil {
		return SQLiteBackup{}, storeError(err)
	}
	checkpoint("published")
	return SQLiteBackup{SHA256: hex.EncodeToString(h.Sum(nil)), Namespace: namespace}, nil
}

// RestoreSQLiteStore restores only a sealed, hash-matched backup to a new
// directory. It rotates the authority namespace before any admission is
// possible. Old operation and mandate IDs cannot execute, including identities
// absent from the snapshot. Stop old authorities and issue new trusted mandates;
// restoring never asserts outcomes for effects missing from the backup.
func RestoreSQLiteStore(ctx context.Context, source, directory, expectedSHA256 string) (*SQLiteStore, error) {
	if ctx == nil || !filepath.IsAbs(source) || !filepath.IsAbs(directory) || !canonicalDigest("sha256:"+expectedSHA256) {
		return nil, ErrStoreUnavailable
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrStoreUnavailable
	}
	input, err := os.Open(source)
	if err != nil {
		return nil, storeError(err)
	}
	defer input.Close()
	if err = os.Mkdir(directory, 0o700); err != nil {
		return nil, storeError(err)
	}
	marker := filepath.Join(directory, "restore.pending")
	if err = os.WriteFile(marker, []byte("Incomplete restore; execution disabled.\n"), 0o600); err != nil {
		return nil, storeError(err)
	}
	if err = syncSQLiteFile(marker); err != nil {
		return nil, storeError(err)
	}
	if err = syncDirectory(directory); err != nil {
		return nil, storeError(err)
	}
	path := filepath.Join(directory, "journal.sqlite")
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, storeError(err)
	}
	h := sha256.New()
	_, err = copySQLiteContext(ctx, io.MultiWriter(output, h), input)
	if err != nil {
		_ = output.Close()
		return nil, storeError(err)
	}
	syncErr := output.Sync()
	closeErr := output.Close()
	if syncErr != nil {
		return nil, storeError(syncErr)
	}
	if closeErr != nil {
		return nil, storeError(closeErr)
	}
	if hex.EncodeToString(h.Sum(nil)) != expectedSHA256 {
		return nil, ErrStoreUnavailable
	}
	db, err := openSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	_, backup, err := sqliteMetadata(ctx, db)
	if err != nil || backup != 1 {
		return nil, ErrStoreUnavailable
	}
	namespace, err := newStoreNamespace()
	if err != nil {
		return nil, storeError(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE metadata SET namespace=?,backup=0 WHERE id=1`, namespace); err != nil {
		return nil, storeError(err)
	}
	if err = db.Close(); err != nil {
		return nil, storeError(err)
	}
	if err = syncSQLiteFile(path); err != nil {
		return nil, storeError(err)
	}
	if err = ctx.Err(); err != nil {
		return nil, storeError(err)
	}
	if err = os.Remove(marker); err != nil {
		return nil, storeError(err)
	}
	if err = syncDirectory(directory); err != nil {
		return nil, storeError(err)
	}
	if err = syncDirectory(filepath.Dir(directory)); err != nil {
		return nil, storeError(err)
	}
	return OpenSQLiteStore(ctx, directory)
}

// Check between bounded chunks. A syscall stalled inside the kernel requires
// the external process deadline; context cannot interrupt arbitrary disk I/O.
func copySQLiteContext(ctx context.Context, out io.Writer, in io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, readErr := in.Read(buffer)
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if n > 0 {
			written, err := out.Write(buffer[:n])
			total += int64(written)
			if err != nil {
				return total, err
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, ctx.Err()
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
