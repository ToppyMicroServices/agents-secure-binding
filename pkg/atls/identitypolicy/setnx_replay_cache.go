// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"context"
	"errors"
	"time"
)

var (
	ErrMissingSetNXStore = errors.New("identitypolicy: missing SETNX replay store")
	ErrReplayStoreFailed = errors.New("identitypolicy: replay store failed")
)

// SetNXStore records a key only if it does not already exist.
//
// This mirrors Redis/Valkey SET key value NX EX ttl semantics without making
// Redis a dependency of the core identity-policy package.
type SetNXStore interface {
	SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// SetNXReplayCache uses a SETNX-style store for distributed replay prevention.
type SetNXReplayCache struct {
	ctx   context.Context
	store SetNXStore
	now   func() time.Time
}

// NewSetNXReplayCache returns a distributed replay cache backed by a SETNX-style
// store. The caller owns the concrete store implementation.
func NewSetNXReplayCache(ctx context.Context, store SetNXStore) *SetNXReplayCache {
	return NewSetNXReplayCacheWithClock(ctx, store, time.Now)
}

// NewSetNXReplayCacheWithClock returns a SETNX replay cache using a
// caller-supplied clock. It is primarily useful for deterministic tests.
//
//nolint:contextcheck // The cache intentionally stores the caller-owned context for store operations.
func NewSetNXReplayCacheWithClock(ctx context.Context, store SetNXStore, now func() time.Time) *SetNXReplayCache {
	if ctx == nil {
		ctx = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	return &SetNXReplayCache{
		ctx:   ctx,
		store: store,
		now:   now,
	}
}

// MarkUsed records a one-shot binding key until its expiration time.
func (c *SetNXReplayCache) MarkUsed(key string, expiresAt time.Time) error {
	if c == nil {
		return ErrReplayUnavailable
	}
	if c.store == nil {
		return validationError(LayerSessionBinding, FieldNonce, ErrMissingSetNXStore)
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

	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion)
	}

	ok, err := c.store.SetNX(c.ctx, key, ttl)
	if err != nil {
		return validationError(LayerSessionBinding, FieldNonce, ErrReplayStoreFailed)
	}
	if !ok {
		return ErrReplayDetected
	}
	return nil
}
