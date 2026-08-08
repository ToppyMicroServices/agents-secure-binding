// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestPresenceDiscoverUpdateAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	store := NewPresenceStoreWithOptions(PresenceOptions{
		TombstoneRetention: time.Hour,
		Now:                func() time.Time { return now },
	})
	changed, err := store.Announce(Record{
		AgentID:      "agent-x",
		Name:         "writer.example",
		Capabilities: []string{"generate", "summarize"},
		Visibility:   Visibility{Mode: VisibilityPublic},
		Version:      1,
		ExpiresAt:    now.Add(time.Minute),
	})
	if err != nil || !changed {
		t.Fatalf("announce = %v, %v", changed, err)
	}
	response, err := store.Discover(context.Background(), Query{Capability: "generate", Limit: 10}, Requester{})
	if err != nil {
		t.Fatal(err)
	}
	if response.TotalMatches != 1 || response.Results[0].AgentID != "agent-x" {
		t.Fatalf("response = %+v", response)
	}
	if changed, err = store.Announce(Record{
		AgentID:      "agent-x",
		Capabilities: []string{"analyze"},
		Version:      2,
		ExpiresAt:    now.Add(time.Minute),
	}); err != nil || !changed {
		t.Fatalf("update = %v, %v", changed, err)
	}
	response, _ = store.Discover(context.Background(), Query{Capability: "generate", Limit: 10}, Requester{})
	if response.TotalMatches != 0 {
		t.Fatalf("stale capability remained: %+v", response)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.Probe("agent-x"); ok {
		t.Fatal("expired record remained live")
	}
}

func TestPresenceRejectsInvalidQueryLimit(t *testing.T) {
	store := NewPresenceStore()
	_, err := store.Discover(context.Background(), Query{
		Capability: "generate",
		Limit:      MaxResultLimit + 1,
	}, Requester{})
	if err != ErrInvalidQuery {
		t.Fatalf("invalid query error = %v", err)
	}
}

func TestPresenceSelectiveVisibility(t *testing.T) {
	store := NewPresenceStore()
	records := []Record{
		{AgentID: "public-agent", Capabilities: []string{"audit"}, Visibility: Visibility{Mode: VisibilityPublic}, Version: 1},
		{AgentID: "domain-agent", Capabilities: []string{"audit"}, Visibility: Visibility{Mode: VisibilityOwnerDomain, OwnerDomain: "example.test"}, Version: 1},
		{AgentID: "invited-agent", Capabilities: []string{"audit"}, Visibility: Visibility{Mode: VisibilityExplicitOnly, AllowedAgents: []string{"requester-1"}}, Version: 1},
		{AgentID: "hidden-agent", Capabilities: []string{"audit"}, Visibility: Visibility{Mode: VisibilityInvisible}, Version: 1},
	}
	for _, record := range records {
		if _, err := store.Announce(record); err != nil {
			t.Fatal(err)
		}
	}
	response, err := store.Discover(context.Background(), Query{Capability: "audit", Limit: 10}, Requester{
		AgentID: "requester-1", OwnerDomain: "example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.TotalMatches != 3 {
		t.Fatalf("matches = %d, want 3: %+v", response.TotalMatches, response.Results)
	}
	response, _ = store.Discover(context.Background(), Query{Capability: "audit", Limit: 10}, Requester{AgentID: "requester-2"})
	if response.TotalMatches != 1 || response.Results[0].AgentID != "public-agent" {
		t.Fatalf("untrusted response = %+v", response)
	}
}

func TestPresenceDiscoversHundredRecordsDeterministically(t *testing.T) {
	store := NewPresenceStore()
	for i := 99; i >= 0; i-- {
		agentID := fmt.Sprintf("agent-%03d", i)
		if _, err := store.Announce(Record{
			AgentID: agentID, Capabilities: []string{"generate"}, Version: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	response, err := store.Discover(context.Background(), Query{Capability: "generate", Limit: 100}, Requester{})
	if err != nil {
		t.Fatal(err)
	}
	if response.TotalMatches != 100 || response.Returned != 100 {
		t.Fatalf("counts = %d/%d, want 100/100", response.TotalMatches, response.Returned)
	}
	if response.Results[0].AgentID != "agent-000" || response.Results[99].AgentID != "agent-099" {
		t.Fatalf("result order = %s ... %s", response.Results[0].AgentID, response.Results[99].AgentID)
	}
}

func TestPresenceTombstoneConvergesAfterPartition(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	newStore := func() *PresenceStore {
		return NewPresenceStoreWithOptions(PresenceOptions{TombstoneRetention: time.Hour, Now: func() time.Time { return now }})
	}
	a, b := newStore(), newStore()
	record := Record{AgentID: "agent-x", Capabilities: []string{"audit"}, Version: 1, ExpiresAt: now.Add(2 * time.Hour)}
	if _, err := a.Announce(record); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(a.Delta(b.Digest())); err != nil {
		t.Fatal(err)
	}
	if changed, err := a.Withdraw("agent-x", 2); err != nil || !changed {
		t.Fatalf("withdraw = %v, %v", changed, err)
	}
	if _, ok := b.Probe("agent-x"); !ok {
		t.Fatal("partitioned peer should still have its stale record")
	}
	if err := b.Merge(a.Delta(b.Digest())); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Probe("agent-x"); ok {
		t.Fatal("tombstone did not remove stale record")
	}
	if err := a.Merge(Delta{Records: []Record{record}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Probe("agent-x"); ok {
		t.Fatal("stale record resurrected after withdrawal")
	}
	if changed, err := a.Announce(Record{AgentID: "agent-x", Capabilities: []string{"audit"}, Version: 3}); err != nil || !changed {
		t.Fatalf("newer re-announce = %v, %v", changed, err)
	}
}

func TestPresenceIndefiniteLeaseWithdrawalPropagates(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	newStore := func() *PresenceStore {
		return NewPresenceStoreWithOptions(PresenceOptions{TombstoneRetention: time.Hour, Now: func() time.Time { return now }})
	}
	origin, relay := newStore(), newStore()
	stale := Record{AgentID: "agent-indefinite", Capabilities: []string{"audit"}, Version: 1}
	if _, err := origin.Announce(stale); err != nil {
		t.Fatal(err)
	}
	if _, err := origin.Withdraw(stale.AgentID, 2); err != nil {
		t.Fatal(err)
	}
	if err := relay.Merge(origin.Delta(relay.Digest())); err != nil {
		t.Fatal(err)
	}
	now = now.Add(48 * time.Hour)
	if changed, err := relay.Announce(stale); err != nil || changed {
		t.Fatalf("stale indefinite record = %v, %v", changed, err)
	}
}

func TestPresenceConfiguredRecordLimitPreservesTombstone(t *testing.T) {
	store := NewPresenceStoreWithOptions(PresenceOptions{
		TombstoneRetention: time.Hour,
		MaxRecords:         1,
		MaxTombstones:      1,
	})
	if _, err := store.Announce(Record{AgentID: "agent-a", Capabilities: []string{"audit"}, Version: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Announce(Record{AgentID: "agent-b", Capabilities: []string{"audit"}, Version: 1}); err != ErrLimitExceeded {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := store.Withdraw("agent-a", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Announce(Record{AgentID: "agent-b", Capabilities: []string{"audit"}, Version: 1}); err != nil {
		t.Fatal(err)
	}
	if changed, err := store.Announce(Record{AgentID: "agent-a", Capabilities: []string{"audit"}, Version: 1}); err != nil || changed {
		t.Fatalf("stale full-store announce = %v, %v", changed, err)
	}
	if _, ok := store.Probe("agent-a"); ok {
		t.Fatal("stale withdrawn record reappeared")
	}
}
