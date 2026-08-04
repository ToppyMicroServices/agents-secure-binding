// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"testing"
	"time"
)

func TestMemoryReplayCacheRejectsDuplicateKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewMemoryReplayCacheWithClock(func() time.Time { return now })

	if err := cache.MarkUsed("grant\x00aud\x00nonce", now.Add(time.Minute)); err != nil {
		t.Fatalf("MarkUsed() first error = %v", err)
	}
	err := cache.MarkUsed("grant\x00aud\x00nonce", now.Add(time.Minute))
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("MarkUsed() replay error = %v, want %v", err, ErrReplayDetected)
	}
}

func TestMemoryReplayCacheAllowsReuseAfterExpiryCleanup(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewMemoryReplayCacheWithClock(func() time.Time { return now })

	if err := cache.MarkUsed("grant\x00aud\x00nonce", now.Add(time.Minute)); err != nil {
		t.Fatalf("MarkUsed() first error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := cache.MarkUsed("grant\x00aud\x00nonce", now.Add(time.Minute)); err != nil {
		t.Fatalf("MarkUsed() after cleanup error = %v", err)
	}
}

func TestMemoryReplayCacheRejectsExpiredKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewMemoryReplayCacheWithClock(func() time.Time { return now })

	err := cache.MarkUsed("grant\x00aud\x00nonce", now.Add(-time.Minute))
	if !errors.Is(err, ErrExpiredAssertion) {
		t.Fatalf("MarkUsed() error = %v, want %v", err, ErrExpiredAssertion)
	}
}

func TestMemoryReplayCacheRejectsMissingKeyOrExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := NewMemoryReplayCacheWithClock(func() time.Time { return now })

	if err := cache.MarkUsed("", now.Add(time.Minute)); !errors.Is(err, ErrMissingBinding) {
		t.Fatalf("MarkUsed() missing key error = %v, want %v", err, ErrMissingBinding)
	}
	if err := cache.MarkUsed("grant\x00aud\x00nonce", time.Time{}); !errors.Is(err, ErrMissingBinding) {
		t.Fatalf("MarkUsed() missing expiry error = %v, want %v", err, ErrMissingBinding)
	}
}

func TestMemoryReplayCacheNilReceiverFailsClosed(t *testing.T) {
	t.Parallel()
	var cache *MemoryReplayCache
	if err := cache.MarkUsed("binding-key", time.Now().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("MarkUsed() error = %v, want %v", err, ErrReplayUnavailable)
	}
}
