// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const durableReachabilitySupported = true

func singleLinkDatabaseFile(info os.FileInfo) bool {
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && status.Nlink == 1
}

// Independent opens use independent file descriptions, so flock also orders
// handles in the same process. Never unlink this guard while writers exist.
func (s *Store) acquireGrantGuard(ctx context.Context, create bool) (func(), error) {
	if ctx == nil {
		return nil, unavailable(errors.New("missing context"))
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if create {
		flags |= unix.O_CREAT
	}
	fd, err := unix.Open(s.guardPath, flags, 0o600)
	if err != nil {
		return nil, unavailable(err)
	}
	file := os.NewFile(uintptr(fd), s.guardPath)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !singleLinkDatabaseFile(info) {
		_ = file.Close()
		return nil, unavailable(errors.New("grant guard must be an owner-only regular file"))
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			current, statErr := os.Lstat(s.guardPath)
			if statErr != nil || !os.SameFile(info, current) {
				_ = file.Close()
				return nil, unavailable(errors.New("grant guard was replaced"))
			}
			return func() { _ = file.Close() }, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			_ = file.Close()
			return nil, unavailable(err)
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
