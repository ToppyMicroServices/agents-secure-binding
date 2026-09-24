// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestANSRegisterResolveAndDeregister(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	presence := NewPresenceStoreWithOptions(PresenceOptions{TombstoneRetention: time.Hour, Now: func() time.Time { return now }})
	names := NewNameService(presence, func() time.Time { return now })
	binding := NameBinding{
		Name:         "auditor.example",
		AgentID:      "agent-auditor",
		Endpoint:     "https://127.0.0.1:9443",
		Capabilities: []string{"audit"},
		Version:      1,
		ExpiresAt:    now.Add(time.Hour),
		Visibility:   Visibility{Mode: VisibilityPublic},
	}
	if changed, err := names.Register(binding); err != nil || !changed {
		t.Fatalf("register = %v, %v", changed, err)
	}
	resolved, ok := names.Resolve("auditor.example")
	if !ok || resolved.AgentID != binding.AgentID || resolved.Endpoint != binding.Endpoint {
		t.Fatalf("resolved = %+v, %v", resolved, ok)
	}
	response, err := presence.Discover(context.Background(), Query{Capability: "audit", Limit: 10}, Requester{})
	if err != nil || response.TotalMatches != 1 {
		t.Fatalf("presence response = %+v, %v", response, err)
	}
	if changed, err := names.Deregister("auditor.example", 2); err != nil || !changed {
		t.Fatalf("deregister = %v, %v", changed, err)
	}
	if _, ok := names.Resolve("auditor.example"); ok {
		t.Fatal("deregistered name still resolves")
	}
	if _, ok := presence.Probe(binding.AgentID); ok {
		t.Fatal("deregistered agent remains present")
	}
	if changed, err := presence.Announce(Record{
		AgentID: binding.AgentID, Capabilities: []string{"audit"}, Version: 1,
	}); err != nil || changed {
		t.Fatalf("stale Presence announce = %v, %v", changed, err)
	}
}

func TestANSConvergesWhenPresenceArrivesBeforeBinding(t *testing.T) {
	presence := NewPresenceStore()
	names := NewNameService(presence, nil)
	binding := NameBinding{Name: "audit.example", AgentID: "agent-one", Endpoint: "one", Capabilities: []string{"audit"}, Version: 1}
	if _, err := presence.Announce(Record{
		AgentID: binding.AgentID, Name: binding.Name, Capabilities: binding.Capabilities,
		Visibility: Visibility{Mode: VisibilityPublic}, Version: binding.Version,
	}); err != nil {
		t.Fatal(err)
	}
	if changed, err := names.Register(binding); err != nil || !changed {
		t.Fatalf("register after Presence = %v, %v", changed, err)
	}
	if got, ok := names.Resolve(binding.Name); !ok || got.Endpoint != binding.Endpoint {
		t.Fatalf("resolved binding = %+v, %v", got, ok)
	}
	if changed, err := names.Register(binding); err != nil || changed {
		t.Fatalf("duplicate registration = %v, %v", changed, err)
	}
}

func TestANSDoesNotBindContradictoryPresenceRevision(t *testing.T) {
	presence := NewPresenceStore()
	names := NewNameService(presence, nil)
	if _, err := presence.Announce(Record{
		AgentID: "agent-one", Name: "audit.example", Capabilities: []string{"audit"}, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	binding := NameBinding{Name: "audit.example", AgentID: "agent-one", Endpoint: "one", Capabilities: []string{"generate"}, Version: 1}
	if changed, err := names.Register(binding); changed || err != ErrInvalidRecord {
		t.Fatalf("contradictory registration = %v, %v", changed, err)
	}
	if _, ok := names.Resolve(binding.Name); ok {
		t.Fatal("contradictory binding resolved")
	}
	if got, _ := presence.Probe(binding.AgentID); len(got.Capabilities) != 1 || got.Capabilities[0] != "audit" {
		t.Fatalf("existing Presence changed: %+v", got)
	}
}

func TestANSRemovesBindingSupersededByPresence(t *testing.T) {
	for _, nextName := range []string{"audit.example", "review.example"} {
		t.Run(nextName, func(t *testing.T) {
			presence := NewPresenceStore()
			names := NewNameService(presence, nil)
			binding := NameBinding{Name: "audit.example", AgentID: "agent-one", Endpoint: "one", Capabilities: []string{"audit"}, Version: 1}
			if _, err := names.Register(binding); err != nil {
				t.Fatal(err)
			}
			if _, err := presence.Announce(Record{
				AgentID: binding.AgentID, Name: nextName, Capabilities: binding.Capabilities, Version: 2,
			}); err != nil {
				t.Fatal(err)
			}
			if _, ok := names.ResolveAgent(binding.AgentID); ok {
				t.Fatal("superseded binding still resolves by Agent-ID")
			}
			if _, ok := names.Resolve(binding.Name); ok {
				t.Fatal("superseded binding still resolves by name")
			}
			binding.Name = nextName
			binding.Endpoint = "two"
			binding.Version = 2
			if changed, err := names.Register(binding); err != nil || !changed {
				t.Fatalf("updated binding = %v, %v", changed, err)
			}
			if got, ok := names.Resolve(nextName); !ok || got.Endpoint != binding.Endpoint {
				t.Fatalf("updated resolution = %+v, %v", got, ok)
			}
		})
	}
}

func TestANSReusesNameAfterReplicatedWithdrawal(t *testing.T) {
	presence := NewPresenceStore()
	names := NewNameService(presence, nil)
	binding := NameBinding{Name: "audit.example", AgentID: "agent-one", Endpoint: "one", Capabilities: []string{"audit"}, Version: 1}
	if _, err := names.Register(binding); err != nil {
		t.Fatal(err)
	}
	if err := presence.Merge(Delta{Tombstones: []Tombstone{{AgentID: binding.AgentID, Version: 2}}}); err != nil {
		t.Fatal(err)
	}
	if changed, err := names.Register(binding); err != nil || changed {
		t.Fatalf("withdrawn binding = %v, %v", changed, err)
	}
	binding.AgentID = "agent-two"
	binding.Endpoint = "two"
	if changed, err := names.Register(binding); err != nil || !changed {
		t.Fatalf("replacement registration = %v, %v", changed, err)
	}
	if got, ok := names.Resolve(binding.Name); !ok || got.AgentID != binding.AgentID {
		t.Fatalf("replacement resolution = %+v, %v", got, ok)
	}
	if _, ok := names.ResolveAgent("agent-one"); ok {
		t.Fatal("withdrawn agent still has an ANS binding")
	}
}

func TestANSExpiredBindingChurnRemainsBounded(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	presence := NewPresenceStoreWithOptions(PresenceOptions{MaxRecords: 1, Now: func() time.Time { return now }})
	names := NewNameService(presence, func() time.Time { return now })
	for i := range 5 {
		binding := NameBinding{
			Name: fmt.Sprintf("audit-%d.example", i), AgentID: fmt.Sprintf("agent-%d", i),
			Endpoint: "one", Capabilities: []string{"audit"}, Version: 1,
			ExpiresAt: now.Add(time.Minute),
		}
		if changed, err := names.Register(binding); err != nil || !changed {
			t.Fatalf("register %d = %v, %v", i, changed, err)
		}
		if len(names.byName) != 1 || len(names.byAgent) != 1 {
			t.Fatalf("retained ANS entries = %d names, %d agents", len(names.byName), len(names.byAgent))
		}
		now = now.Add(2 * time.Minute)
	}
	if bindings := names.Bindings(); len(bindings) != 0 || len(names.byName) != 0 || len(names.byAgent) != 0 {
		t.Fatalf("expired bindings retained: %+v", bindings)
	}
}

func TestANSRejectsSilentNameTransfer(t *testing.T) {
	presence := NewPresenceStore()
	names := NewNameService(presence, nil)
	first := NameBinding{Name: "audit.example", AgentID: "agent-one", Endpoint: "one", Capabilities: []string{"audit"}, Version: 1}
	if _, err := names.Register(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.AgentID = "agent-two"
	second.Version = 2
	if _, err := names.Register(second); err != ErrNameConflict {
		t.Fatalf("transfer error = %v, want %v", err, ErrNameConflict)
	}
}
