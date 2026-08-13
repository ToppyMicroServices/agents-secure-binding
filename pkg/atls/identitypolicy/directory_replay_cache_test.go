// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestDirectoryReplayCacheSharesAtomicStateAcrossInstances(t *testing.T) {
	directory := t.TempDir()
	first, err := NewDirectoryReplayCache(directory)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDirectoryReplayCache(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.MarkUsed("grant\x00aud\x00exporter\x00context\x00nonce", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := second.MarkUsed("grant\x00aud\x00exporter\x00context\x00nonce", time.Now().Add(time.Minute)); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("second MarkUsed() error = %v, want ErrReplayDetected", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("replay entries = %d, want 1", len(entries))
	}
}

func TestDirectoryReplayCacheAcceptsAtMostOneConcurrentWriter(t *testing.T) {
	directory := t.TempDir()
	const attempts = 12
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wait sync.WaitGroup
	for range attempts {
		cache, err := NewDirectoryReplayCache(directory)
		if err != nil {
			t.Fatal(err)
		}
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- cache.MarkUsed("same-proof", time.Now().Add(time.Minute))
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	accepted := 0
	for err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrReplayDetected):
		default:
			t.Fatalf("unexpected MarkUsed() error = %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted writers = %d, want 1", accepted)
	}
}
