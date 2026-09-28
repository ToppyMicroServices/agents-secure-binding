// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
)

const (
	backupWorkspaceMarker = "ASB temporary backup workspace v1\n"
	backupPayloadName     = "snapshot.sqlite"
	backupOwnerName       = "owner"
)

var backupTemporaryName = regexp.MustCompile(`^\.asb-s3-backup-work-[0-9]+$`)

func backupLock(directory string) (*os.File, error) {
	if !filepath.IsAbs(directory) || !privateDirectory(directory) {
		return nil, ErrStoreUnavailable
	}
	path := filepath.Join(directory, ".asb-s3-backup.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, storeError(err)
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = f.Close()
		return nil, ErrStoreUnavailable
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrStoreUnavailable
	}
	return f, nil
}

// SQLiteBackupRecovery counts removed payload aliases and allocated payload bytes.
// Marker/directory overhead is excluded. A published hard link is not a second copy.
type SQLiteBackupRecovery struct {
	Removed        int   `json:"removed"`
	ReclaimedBytes int64 `json:"reclaimed_bytes"`
}

// RecoverSQLiteBackups removes only marked private workspaces under the same
// exclusive lock used by Backup. Legacy flat temporary files are intentionally
// left for operator inspection: their names alone cannot prove ownership.
func RecoverSQLiteBackups(ctx context.Context, directory string) (SQLiteBackupRecovery, error) {
	if ctx == nil {
		return SQLiteBackupRecovery{}, ErrStoreUnavailable
	}
	lock, err := backupLock(directory)
	if err != nil {
		return SQLiteBackupRecovery{}, err
	}
	defer lock.Close()
	return recoverSQLiteBackups(ctx, directory)
}

func newBackupWorkspace(directory string) (string, error) {
	dir, err := os.MkdirTemp(directory, ".asb-s3-backup-work-")
	if err != nil {
		return "", err
	}
	marker := filepath.Join(dir, backupOwnerName)
	if err = os.WriteFile(marker, []byte(backupWorkspaceMarker), 0o600); err != nil {
		return "", err
	}
	if err = syncSQLiteFile(marker); err != nil {
		return "", err
	}
	if err = syncDirectory(dir); err != nil {
		return "", err
	}
	if err = syncDirectory(directory); err != nil {
		return "", err
	}
	path := filepath.Join(dir, backupPayloadName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func recoverSQLiteBackups(ctx context.Context, directory string) (SQLiteBackupRecovery, error) {
	var result SQLiteBackupRecovery
	dir, err := os.Open(directory)
	if err != nil {
		return result, storeError(err)
	}
	defer dir.Close()
	for {
		if err = ctx.Err(); err != nil {
			return result, storeError(err)
		}
		entries, readErr := dir.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return result, storeError(readErr)
		}
		for _, entry := range entries {
			if !backupTemporaryName.MatchString(entry.Name()) {
				continue
			}
			workspace := filepath.Join(directory, entry.Name())
			var stat unix.Stat_t
			if err = unix.Lstat(workspace, &stat); err != nil {
				return result, storeError(err)
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
				return result, ErrStoreUnavailable
			}
			marker := filepath.Join(workspace, backupOwnerName)
			if err = unix.Lstat(marker, &stat); errors.Is(err, os.ErrNotExist) {
				// A crash before the durable marker can leave an empty directory.
				// Do not assume ownership when no marker exists.
				continue
			}
			if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Size != int64(len(backupWorkspaceMarker)) {
				return result, ErrStoreUnavailable
			}
			raw, err := os.ReadFile(marker)
			if err != nil || string(raw) != backupWorkspaceMarker {
				return result, ErrStoreUnavailable
			}
			files, err := os.ReadDir(workspace)
			if err != nil {
				return result, storeError(err)
			}
			// Validate the entire workspace before deleting any payload.
			for _, file := range files {
				if file.Name() != backupOwnerName && file.Name() != backupPayloadName && file.Name() != backupPayloadName+"-journal" && file.Name() != backupPayloadName+"-wal" && file.Name() != backupPayloadName+"-shm" {
					return result, ErrStoreUnavailable
				}
				if err = unix.Lstat(filepath.Join(workspace, file.Name()), &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Uid != uint32(os.Geteuid()) {
					return result, ErrStoreUnavailable
				}
			}
			for _, file := range files {
				if file.Name() == backupOwnerName {
					continue
				}
				path := filepath.Join(workspace, file.Name())
				if err = unix.Lstat(path, &stat); err != nil {
					return result, storeError(err)
				}
				if err = os.Remove(path); err != nil {
					return result, storeError(err)
				}
				result.Removed++
				if stat.Nlink == 1 {
					result.ReclaimedBytes += stat.Blocks * 512
				}
			}
			if err = os.Remove(marker); err != nil {
				return result, storeError(err)
			}
			if err = os.Remove(workspace); err != nil {
				return result, storeError(err)
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if err = syncDirectory(directory); err != nil {
		return result, storeError(err)
	}
	return result, nil
}

func removeBackupTemporary(path string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		_ = os.Remove(path + suffix)
	}
	_ = os.Remove(filepath.Join(filepath.Dir(path), backupOwnerName))
	_ = os.Remove(filepath.Dir(path))
}
