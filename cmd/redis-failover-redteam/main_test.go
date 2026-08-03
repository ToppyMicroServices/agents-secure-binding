// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type memorySetNXStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
	err  error
}

func (s *memorySetNXStore) SetNX(_ context.Context, key string, _ time.Duration) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[key]; ok {
		return false, nil
	}
	s.seen[key] = struct{}{}
	return true, nil
}

func TestRunPhaseRejectsReplayAfterFailover(t *testing.T) {
	t.Parallel()
	stateFile := t.TempDir() + "/state.json"
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	opts := options{Phase: "seed", StateFile: stateFile, TTL: time.Hour}
	store := &memorySetNXStore{seen: make(map[string]struct{})}
	if err := runPhase(context.Background(), opts, store, now, bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatalf("seed error = %v", err)
	}
	opts.Phase = "verify"
	if err := runPhase(context.Background(), opts, store, now.Add(time.Minute), bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatalf("verify error = %v", err)
	}
}

func TestRunPhaseDetectsLostReplayWrite(t *testing.T) {
	t.Parallel()
	stateFile := t.TempDir() + "/state.json"
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	opts := options{Phase: "seed", StateFile: stateFile, TTL: time.Hour}
	beforeFailover := &memorySetNXStore{seen: make(map[string]struct{})}
	if err := runPhase(context.Background(), opts, beforeFailover, now, bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatalf("seed error = %v", err)
	}

	opts.Phase = "verify"
	afterFailover := &memorySetNXStore{seen: make(map[string]struct{})}
	err := runPhase(context.Background(), opts, afterFailover, now.Add(time.Minute), bytes.NewReader(make([]byte, 32)))
	if !errors.Is(err, errReplayAcceptedAfterFailover) {
		t.Fatalf("verify error = %v, want %v", err, errReplayAcceptedAfterFailover)
	}
}

func TestRunPhaseRejectsExpiredEvidenceAndStoreOutage(t *testing.T) {
	t.Parallel()
	stateFile := t.TempDir() + "/state.json"
	now := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	opts := options{Phase: "seed", StateFile: stateFile, TTL: time.Minute}
	store := &memorySetNXStore{seen: make(map[string]struct{})}
	if err := runPhase(context.Background(), opts, store, now, bytes.NewReader(make([]byte, 32))); err != nil {
		t.Fatalf("seed error = %v", err)
	}
	opts.Phase = "verify"
	if err := runPhase(context.Background(), opts, store, now.Add(time.Minute), bytes.NewReader(make([]byte, 32))); !errors.Is(err, errEvidenceExpired) {
		t.Fatalf("expired verify error = %v, want %v", err, errEvidenceExpired)
	}

	outage := errors.New("replay service unavailable")
	opts = options{Phase: "seed", StateFile: t.TempDir() + "/state.json", TTL: time.Hour}
	store = &memorySetNXStore{seen: make(map[string]struct{}), err: outage}
	if err := runPhase(context.Background(), opts, store, now, bytes.NewReader(make([]byte, 32))); !errors.Is(err, outage) {
		t.Fatalf("outage error = %v, want %v", err, outage)
	}
}

func TestFailoverStateRejectsOverwriteAndBroadPermissions(t *testing.T) {
	t.Parallel()
	path := t.TempDir() + "/state.json"
	state := evidenceState{
		Version:         stateVersion,
		ReplayKey:       "test-replay-key",
		ReplayKeySHA256: "ignored-until-read",
		SeededAt:        time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, time.August, 3, 13, 0, 0, 0, time.UTC),
	}
	if err := writeState(path, state); err != nil {
		t.Fatalf("writeState() error = %v", err)
	}
	if err := writeState(path, state); err == nil {
		t.Fatal("writeState() overwrote existing evidence")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readState(path); err == nil {
		t.Fatal("readState() accepted broadly readable evidence")
	}
}
