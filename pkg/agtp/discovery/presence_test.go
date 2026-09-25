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

func TestPresenceHigherWithdrawalPreservesSuppressionFloor(t *testing.T) {
	for _, indefinite := range []bool{false, true} {
		for _, merged := range []bool{false, true} {
			t.Run(fmt.Sprintf("indefinite=%t/merged=%t", indefinite, merged), func(t *testing.T) {
				now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
				store := NewPresenceStoreWithOptions(PresenceOptions{
					TombstoneRetention: time.Hour, Now: func() time.Time { return now },
				})
				stale := Record{AgentID: "agent-x", Capabilities: []string{"audit"}, Version: 1}
				if !indefinite {
					stale.ExpiresAt = now.Add(48 * time.Hour)
				}
				if _, err := store.Announce(stale); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Withdraw(stale.AgentID, 2); err != nil {
					t.Fatal(err)
				}
				now = now.Add(30 * time.Minute)
				var changed bool
				var err error
				if merged {
					changed, err = store.mergeTombstone(Tombstone{AgentID: stale.AgentID, Version: 3})
				} else {
					changed, err = store.Withdraw(stale.AgentID, 3)
				}
				if err != nil || !changed {
					t.Fatalf("newer withdrawal = %v, %v", changed, err)
				}
				tombstones := store.Snapshot().Tombstones
				if len(tombstones) != 1 || tombstones[0].Version != 3 ||
					tombstones[0].Indefinite != indefinite || !tombstones[0].SuppressUntil.Equal(stale.ExpiresAt) {
					t.Fatalf("withdrawal lost suppression floor: %+v", tombstones)
				}
				now = now.Add(2 * time.Hour)
				if changed, err := store.Announce(stale); err != nil || changed {
					t.Fatalf("stale lease after retention = %v, %v", changed, err)
				}
			})
		}
	}
}

func TestPresenceSuppressionFloorConvergesAcrossVersions(t *testing.T) {
	for _, peerVersion := range []uint64{2, 3} {
		for _, indefinite := range []bool{false, true} {
			t.Run(fmt.Sprintf("peerVersion=%d/indefinite=%t", peerVersion, indefinite), func(t *testing.T) {
				now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
				newStore := func() *PresenceStore {
					return NewPresenceStoreWithOptions(PresenceOptions{
						TombstoneRetention: time.Hour, Now: func() time.Time { return now },
					})
				}
				origin, peer := newStore(), newStore()
				if _, err := origin.Withdraw("agent-x", 2); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.Withdraw("agent-x", peerVersion); err != nil {
					t.Fatal(err)
				}
				stale := Record{AgentID: "agent-x", Capabilities: []string{"audit"}, Version: 1}
				if !indefinite {
					stale.ExpiresAt = now.Add(48 * time.Hour)
				}
				now = now.Add(30 * time.Minute)
				if changed, err := origin.Announce(stale); err != nil || changed {
					t.Fatalf("learn stale lease = %v, %v", changed, err)
				}
				if err := peer.Merge(origin.Delta(peer.Digest())); err != nil {
					t.Fatal(err)
				}
				tombstones := peer.Snapshot().Tombstones
				if len(tombstones) != 1 || tombstones[0].Version != peerVersion ||
					tombstones[0].Indefinite != indefinite || !tombstones[0].SuppressUntil.Equal(stale.ExpiresAt) {
					t.Fatalf("suppression floor did not converge: %+v", tombstones)
				}
				now = now.Add(2 * time.Hour)
				if changed, err := peer.Announce(stale); err != nil || changed {
					t.Fatalf("stale lease after retention = %v, %v", changed, err)
				}
				current := Record{AgentID: "agent-x", Capabilities: []string{"audit"}, Version: peerVersion + 1}
				if changed, err := peer.Announce(current); err != nil || !changed {
					t.Fatalf("new lease = %v, %v", changed, err)
				}
				if err := peer.Merge(origin.Delta(peer.Digest())); err != nil {
					t.Fatal(err)
				}
				if record, ok := peer.Probe(current.AgentID); !ok || record.Version != current.Version {
					t.Fatalf("older tombstone displaced newer live record: %+v, %v", record, ok)
				}
			})
		}
	}
}

func TestPresenceDuplicateTombstoneDoesNotRefreshExpiry(t *testing.T) {
	for _, floorDuration := range []time.Duration{0, 45 * time.Minute, 2 * time.Hour} {
		t.Run(floorDuration.String(), func(t *testing.T) {
			now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			start := now
			store := NewPresenceStoreWithOptions(PresenceOptions{
				TombstoneRetention: time.Hour, Now: func() time.Time { return now },
			})
			if _, err := store.Withdraw("agent-x", 2); err != nil {
				t.Fatal(err)
			}
			now = now.Add(30 * time.Minute)
			tombstone := Tombstone{AgentID: "agent-x", Version: 2}
			deadline := start.Add(time.Hour)
			if floorDuration > 0 {
				tombstone.SuppressUntil = start.Add(floorDuration)
				if tombstone.SuppressUntil.After(deadline) {
					deadline = tombstone.SuppressUntil
				}
			}
			if _, err := store.mergeTombstone(tombstone); err != nil {
				t.Fatal(err)
			}
			if got := store.tombstones["agent-x"]; !got.received.Equal(start) || !got.expiresAt.Equal(deadline) {
				t.Fatalf("floor merge refreshed local retention: %+v", got)
			}
			now = now.Add(15 * time.Minute)
			if changed, err := store.mergeTombstone(tombstone); err != nil || changed {
				t.Fatalf("duplicate tombstone = %v, %v", changed, err)
			}
			now = deadline
			if _, count := store.Counts(); count != 0 {
				t.Fatal("stable gossip prevented tombstone expiry")
			}
		})
	}
}

func TestPresenceFloorExtensionPreservesDisabledGarbageCollection(t *testing.T) {
	for _, merged := range []bool{false, true} {
		t.Run(fmt.Sprintf("merged=%t", merged), func(t *testing.T) {
			now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			store := NewPresenceStoreWithOptions(PresenceOptions{Now: func() time.Time { return now }})
			if _, err := store.Withdraw("agent-x", 2); err != nil {
				t.Fatal(err)
			}
			if merged {
				if _, err := store.mergeTombstone(Tombstone{AgentID: "agent-x", Version: 2, SuppressUntil: now.Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := store.Announce(Record{
				AgentID: "agent-x", Capabilities: []string{"audit"}, Version: 1, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatal(err)
			}
			now = now.Add(2 * time.Hour)
			if _, count := store.Counts(); count != 1 {
				t.Fatal("lease floor enabled tombstone garbage collection")
			}
		})
	}
}

// Local GC forgets receipt history. A peer's retained withdrawal can therefore
// be learned again; finite receiver retention does not ensure global reclamation.
func TestPresenceRelearningAfterGCUsesReceiverRetention(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	start := now
	newStore := func() *PresenceStore {
		return NewPresenceStoreWithOptions(PresenceOptions{
			TombstoneRetention: time.Hour,
			MaxTombstones:      1,
			Now:                func() time.Time { return now },
		})
	}
	a, b := newStore(), newStore()
	if _, err := a.Withdraw("agent-x", 2); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := b.Merge(a.Delta(b.Digest())); err != nil {
		t.Fatal(err)
	}
	for cycle := 1; cycle <= 3; cycle++ {
		now = start.Add(time.Duration(cycle) * time.Hour)
		for _, exchange := range []struct {
			sender   *PresenceStore
			receiver *PresenceStore
		}{{b, a}, {a, b}} {
			if records, tombstones := exchange.receiver.Counts(); records != 0 || tombstones != 0 {
				t.Fatalf("cycle %d: receiver did not expire its local tombstone: %d/%d", cycle, records, tombstones)
			}
			if err := exchange.receiver.Merge(exchange.sender.Delta(exchange.receiver.Digest())); err != nil {
				t.Fatal(err)
			}
			if records, tombstones := exchange.receiver.Counts(); records != 0 || tombstones != 1 {
				t.Fatalf("cycle %d: relearned state = %d/%d", cycle, records, tombstones)
			}
			got := exchange.receiver.tombstones["agent-x"]
			if !got.received.Equal(now) || !got.expiresAt.Equal(now.Add(time.Hour)) {
				t.Fatalf("cycle %d: relearning did not apply receiver retention: %+v", cycle, got)
			}
			now = now.Add(time.Minute)
		}
	}
}
