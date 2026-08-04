// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSetNXReplayCacheRejectsDuplicateKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newTestSetNXStore()
	cache := NewSetNXReplayCacheWithClock(context.Background(), store, func() time.Time { return now })
	expiresAt := now.Add(time.Minute)

	if err := cache.MarkUsed("binding-key", expiresAt); err != nil {
		t.Fatalf("MarkUsed() first error = %v", err)
	}
	err := cache.MarkUsed("binding-key", expiresAt)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("MarkUsed() replay error = %v, want %v", err, ErrReplayDetected)
	}
	if got := store.ttlFor("binding-key"); got != time.Minute {
		t.Fatalf("SETNX ttl = %v, want %v", got, time.Minute)
	}
}

func TestSetNXReplayCacheAllowsReuseAfterStoreExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := newTestSetNXStore()
	store.now = func() time.Time { return now }
	cache := NewSetNXReplayCacheWithClock(context.Background(), store, func() time.Time { return now })

	if err := cache.MarkUsed("binding-key", now.Add(time.Second)); err != nil {
		t.Fatalf("MarkUsed() first error = %v", err)
	}
	now = now.Add(2 * time.Second)
	if err := cache.MarkUsed("binding-key", now.Add(time.Second)); err != nil {
		t.Fatalf("MarkUsed() after expiry error = %v", err)
	}
}

func TestSetNXReplayCacheRejectsMissingInputs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name      string
		cache     *SetNXReplayCache
		key       string
		expiresAt time.Time
		want      error
	}{
		{
			name:      "missing store",
			cache:     NewSetNXReplayCacheWithClock(context.Background(), nil, func() time.Time { return now }),
			key:       "binding-key",
			expiresAt: now.Add(time.Minute),
			want:      ErrMissingSetNXStore,
		},
		{
			name:      "missing key",
			cache:     NewSetNXReplayCacheWithClock(context.Background(), newTestSetNXStore(), func() time.Time { return now }),
			expiresAt: now.Add(time.Minute),
			want:      ErrMissingBinding,
		},
		{
			name:  "missing expiry",
			cache: NewSetNXReplayCacheWithClock(context.Background(), newTestSetNXStore(), func() time.Time { return now }),
			key:   "binding-key",
			want:  ErrMissingBinding,
		},
		{
			name:      "expired",
			cache:     NewSetNXReplayCacheWithClock(context.Background(), newTestSetNXStore(), func() time.Time { return now }),
			key:       "binding-key",
			expiresAt: now.Add(-time.Second),
			want:      ErrExpiredAssertion,
		},
		{
			name:      "store failure",
			cache:     NewSetNXReplayCacheWithClock(context.Background(), &testSetNXStore{fail: true}, func() time.Time { return now }),
			key:       "binding-key",
			expiresAt: now.Add(time.Minute),
			want:      ErrReplayStoreFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cache.MarkUsed(tt.key, tt.expiresAt)
			if !errors.Is(err, tt.want) {
				t.Fatalf("MarkUsed() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSetNXReplayCacheNilReceiverFailsClosed(t *testing.T) {
	t.Parallel()
	var cache *SetNXReplayCache
	if err := cache.MarkUsed("binding-key", time.Now().Add(time.Minute)); !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("MarkUsed() error = %v, want %v", err, ErrReplayUnavailable)
	}
}

type testSetNXStore struct {
	fail    bool
	entries map[string]time.Time
	ttls    map[string]time.Duration
	now     func() time.Time
}

func newTestSetNXStore() *testSetNXStore {
	now := time.Unix(1_700_000_000, 0)
	return &testSetNXStore{
		entries: make(map[string]time.Time),
		ttls:    make(map[string]time.Duration),
		now:     func() time.Time { return now },
	}
}

func (s *testSetNXStore) SetNX(_ context.Context, key string, ttl time.Duration) (bool, error) {
	if s.fail {
		return false, errors.New("store failed")
	}
	if s.entries == nil {
		s.entries = make(map[string]time.Time)
	}
	if s.ttls == nil {
		s.ttls = make(map[string]time.Duration)
	}
	now := s.now()
	if expiresAt, ok := s.entries[key]; ok && now.Before(expiresAt) {
		return false, nil
	}
	s.entries[key] = now.Add(ttl)
	s.ttls[key] = ttl
	return true, nil
}

func (s *testSetNXStore) ttlFor(key string) time.Duration {
	return s.ttls[key]
}
