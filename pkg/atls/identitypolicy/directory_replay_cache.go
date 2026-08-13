// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DirectoryReplayCache is a process-shared, fail-closed replay cache backed by
// atomic file creation. Entries are intentionally retained: a verifier nonce
// is one-shot even after the proof expires. Deployments that need bounded
// storage should use a transactional database/Redis adapter with equivalent
// insert-if-absent semantics and retention policy.
type DirectoryReplayCache struct {
	directory string
}

// NewDirectoryReplayCache opens or creates a private replay-state directory.
// Multiple verifier processes may use the same local/shared filesystem path.
func NewDirectoryReplayCache(directory string) (*DirectoryReplayCache, error) {
	directory = strings.TrimSpace(directory)
	if directory == "" {
		return nil, errors.New("identitypolicy: missing replay directory")
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("identitypolicy: resolve replay directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("identitypolicy: create replay directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("identitypolicy: inspect replay directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("identitypolicy: replay path is not a real directory")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, fmt.Errorf("identitypolicy: protect replay directory: %w", err)
	}
	return &DirectoryReplayCache{directory: abs}, nil
}

// MarkUsed atomically records one replay key. The raw key is never used as a
// path or written to disk; only its SHA-256 digest and proof expiry are stored.
func (c *DirectoryReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if c == nil || c.directory == "" {
		return errors.New("identitypolicy: replay directory is not configured")
	}
	if strings.TrimSpace(key) == "" || expiresAt.IsZero() {
		return errors.New("identitypolicy: invalid replay entry")
	}
	sum := sha256.Sum256([]byte(key))
	path := filepath.Join(c.directory, hex.EncodeToString(sum[:])+".used")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrReplayDetected
	}
	if err != nil {
		return fmt.Errorf("identitypolicy: reserve replay entry: %w", err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := fmt.Fprintf(file, "%d\n", expiresAt.UTC().UnixNano()); err != nil {
		return fmt.Errorf("identitypolicy: write replay entry: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("identitypolicy: sync replay entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("identitypolicy: close replay entry: %w", err)
	}
	remove = false
	return nil
}
