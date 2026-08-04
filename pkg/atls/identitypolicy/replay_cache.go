// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"sync"
	"time"
)

// MemoryReplayCache is an in-process ReplayCache for one-shot session-binding
// nonces. It is suitable for a single process; distributed deployments should
// provide a shared replay cache.
type MemoryReplayCache struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]time.Time
}

// NewMemoryReplayCache returns an in-process replay cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return NewMemoryReplayCacheWithClock(time.Now)
}

// NewMemoryReplayCacheWithClock returns an in-process replay cache using a
// caller-supplied clock. It is primarily useful for deterministic tests.
func NewMemoryReplayCacheWithClock(now func() time.Time) *MemoryReplayCache {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayCache{
		now:  now,
		seen: make(map[string]time.Time),
	}
}

// MarkUsed records a one-shot binding key until its expiration time.
func (c *MemoryReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if c == nil {
		return ErrReplayUnavailable
	}
	if isEmpty(key) {
		return validationError(LayerSessionBinding, FieldNonce, ErrMissingBinding)
	}
	now := c.now()
	if expiresAt.IsZero() {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding)
	}
	if !now.IsZero() && now.After(expiresAt) {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for seenKey, seenExpiresAt := range c.seen {
		if !seenExpiresAt.IsZero() && !now.IsZero() && now.After(seenExpiresAt) {
			delete(c.seen, seenKey)
		}
	}
	if _, ok := c.seen[key]; ok {
		return ErrReplayDetected
	}
	c.seen[key] = expiresAt
	return nil
}
