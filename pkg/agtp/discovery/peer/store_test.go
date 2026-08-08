// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/agtp/discovery"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

func TestStateStoreRoundTripAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node", "state.json")
	store, err := NewStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	want := PersistentState{
		Presence: discovery.Delta{Records: []discovery.Record{{
			AgentID: "agent-a", Capabilities: []string{"audit"}, Version: 1,
		}}},
		Peers: []discovery.NodeInfo{{ID: testNodeID("01"), Endpoint: "127.0.0.1:9001"}},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Load()
	if err != nil || !found {
		t.Fatalf("load = %+v, %v, %v", got, found, err)
	}
	if len(got.Presence.Records) != 1 || got.Presence.Records[0].AgentID != "agent-a" {
		t.Fatalf("state = %+v", got)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded[len(encoded)/2] ^= 1
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt load error = %v", err)
	}
}

func TestFileReplayCacheSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay", "used.json")
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	cache, err := NewFileReplayCache(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.MarkUsed("request-1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileReplayCache(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.MarkUsed("request-1", now.Add(time.Hour)); !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("replay error = %v", err)
	}
	now = now.Add(2 * time.Hour)
	if err := restarted.MarkUsed("request-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("expired key was not reusable: %v", err)
	}
}

func TestAuditLogRotatesAtConfiguredLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "events.jsonl")
	log, err := NewAuditLog(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := log.Write(AuditEvent{NodeID: testNodeID("01"), Action: "replicate", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated audit file missing: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1024 {
		t.Fatalf("active audit file size = %d", info.Size())
	}
}

func TestPeerRateLimiterIsBoundedPerIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	limiter := newPeerRateLimiter(1, 2, func() time.Time { return now })
	if !limiter.allow("peer-a") || !limiter.allow("peer-a") || limiter.allow("peer-a") {
		t.Fatal("peer-a burst was not enforced")
	}
	if !limiter.allow("peer-b") {
		t.Fatal("peer-b did not receive an independent bucket")
	}
	now = now.Add(time.Second)
	if !limiter.allow("peer-a") {
		t.Fatal("peer-a token did not refill")
	}
}

func testNodeID(prefix string) string {
	return prefix + "00000000000000000000000000000000000000000000000000000000000000"
}
