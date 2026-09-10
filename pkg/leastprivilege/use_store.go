// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"sync"
	"time"
)

// MemoryUseStore is a bounded, process-local reference implementation. Restart
// loses consumption history. It is not suitable for durable production effects.
type MemoryUseStore struct {
	mu          sync.Mutex
	capacity    int
	used        map[string]time.Time
	prunedUntil time.Time
}

func NewMemoryUseStore(capacity int) (*MemoryUseStore, error) {
	if capacity <= 0 || capacity > 1_000_000 {
		return nil, ErrCapacity
	}
	return &MemoryUseStore{capacity: capacity, used: make(map[string]time.Time)}, nil
}

func (s *MemoryUseStore) Use(ctx context.Context, key string, expiresAt, now time.Time) error {
	if s == nil || ctx == nil || !boundedText(key, 512) {
		return ErrInvalidCapability
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if now.IsZero() || now.Before(s.prunedUntil) || !expiresAt.After(now) {
		return ErrExpired
	}
	for k, expiry := range s.used {
		if !now.Before(expiry) {
			// Never revive an authorization whose record we already pruned,
			// even if the wall clock rolls back. Concurrent timestamps may
			// arrive out of order while still newer than this expiry floor.
			if expiry.After(s.prunedUntil) {
				s.prunedUntil = expiry
			}
			delete(s.used, k)
		}
	}
	if _, exists := s.used[key]; exists {
		return ErrReplay
	}
	if s.used == nil || len(s.used) >= s.capacity {
		return ErrCapacity
	}
	s.used[key] = expiresAt
	return nil
}
