// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
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
