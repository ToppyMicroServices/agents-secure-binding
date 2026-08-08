// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

type replaySnapshot struct {
	Entries map[string]time.Time `json:"entries"`
}

// FileReplayCache is a single-host durable replay cache. It is intentionally
// small and synchronous for the three-node product scope.
type FileReplayCache struct {
	mu      sync.Mutex
	path    string
	entries map[string]time.Time
	now     func() time.Time
}

// NewFileReplayCache loads or creates a durable replay cache.
func NewFileReplayCache(path string, now func() time.Time) (*FileReplayCache, error) {
	if path == "" {
		return nil, errors.New("agtp discovery peer: missing replay path")
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	cache := &FileReplayCache{path: path, entries: make(map[string]time.Time), now: now}
	var snapshot replaySnapshot
	found, err := readChecksummedJSON(path, &snapshot)
	if err != nil {
		return nil, err
	}
	if found {
		cache.entries = snapshot.Entries
		if cache.entries == nil {
			cache.entries = make(map[string]time.Time)
		}
	}
	return cache, nil
}

// MarkUsed commits replay state before returning success.
func (c *FileReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if c == nil || key == "" || expiresAt.IsZero() {
		return identitypolicy.ErrReplayUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	next := make(map[string]time.Time, len(c.entries)+1)
	for existing, expiry := range c.entries {
		if expiry.After(now) {
			next[existing] = expiry
		}
	}
	if expiry, exists := next[key]; exists && expiry.After(now) {
		return identitypolicy.ErrReplayDetected
	}
	next[key] = expiresAt.UTC()
	if err := writeChecksummedJSON(c.path, replaySnapshot{Entries: next}); err != nil {
		return err
	}
	c.entries = next
	return nil
}
