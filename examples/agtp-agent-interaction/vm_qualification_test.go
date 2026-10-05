// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
)

func TestVMCommandRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	for _, raw := range []string{
		`{"id":1,"id":2,"action":"task"}`,
		`{"id":1,"action":"status","extra":true}`,
		`{"id":0,"action":"status"}`,
		`{"id":257,"action":"status"}`,
		`{"id":1,"action":"shell"}`,
		`{"id":1,"action":"status"} {}`,
		strings.Repeat(" ", 4097),
	} {
		path := filepath.Join(t.TempDir(), "request.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readVMCommand(path); err == nil {
			t.Fatalf("accepted invalid command: %.80s", raw)
		}
	}
	for _, action := range []string{"status", "task", "gossip", "withdraw", "stop"} {
		path := filepath.Join(t.TempDir(), "request.json")
		if err := writeJSONFile(path, vmCommand{ID: 1, Action: action}); err != nil {
			t.Fatal(err)
		}
		command, err := readVMCommand(path)
		if err != nil || command.ID != 1 || command.Action != action {
			t.Fatalf("valid command rejected: %v", err)
		}
	}
}

func TestVMRestartPreservesWithdrawalWithoutNewAnnouncement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux VM qualification restart")
	}
	configs, err := bootstrapDemo(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := configs[roleAgentB]
	config.VMQualification = true
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	node, err := startDiscoveryWithLease(ctx, config, vmLabTTL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if node != nil {
			if err := node.Stop(ctx); err != nil {
				t.Error(err)
			}
		}
	}()
	if _, live := node.Resolve(config.Target.Name); !live {
		t.Fatal("fresh VM state did not register the target")
	}
	if changed, err := node.Deregister(config.Target.Name, 2); err != nil || !changed {
		t.Fatalf("withdraw: changed=%v err=%v", changed, err)
	}
	if err := node.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	node = nil
	store, err := peer.NewStateStore(discoveryStatePath(config))
	if err != nil {
		t.Fatal(err)
	}
	before, found, err := store.Load()
	if err != nil || !found || len(before.Presence.Tombstones) != 1 {
		t.Fatalf("missing durable withdrawal: %v", err)
	}
	node, err = startDiscoveryWithLease(ctx, config, vmLabTTL)
	if err != nil {
		t.Fatal(err)
	}
	records, tombstones, _ := node.Counts()
	if records != 0 || tombstones != 1 {
		t.Fatal("restart changed the withdrawn population")
	}
	if _, live := node.Resolve(config.Target.Name); live {
		t.Fatal("restart restored a withdrawn name")
	}
	after, found, err := store.Load()
	if err != nil || !found || len(after.Presence.Tombstones) != 1 ||
		!after.Presence.Tombstones[0].SuppressUntil.Equal(before.Presence.Tombstones[0].SuppressUntil) {
		t.Fatal("restart extended the suppression floor with a stale announcement")
	}
}

func TestVMPreparationKeepsExplicitScopeAndRefusesOverwrite(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux VM qualification preparation")
	}
	root := filepath.Join(t.TempDir(), "credentials")
	if err := prepareVMConfigs(root); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{roleAgentA, roleRelay, roleAgentB} {
		path := filepath.Join(root, role, "config.json")
		config, err := readConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if !config.VMQualification || config.Self.Role != role || config.StateDir != "/var/lib/asb-vm" || len(config.AllowedCIDRs) != 3 || len(config.Peers) != 2 {
			t.Fatal("VM configuration escaped its fixed scope")
		}
		for _, remote := range config.Peers {
			if !strings.HasPrefix(remote.Node.Endpoint, "10.203.0.") || !strings.HasSuffix(remote.Node.Endpoint, ":9443") {
				t.Fatal("VM config retained a loopback peer")
			}
		}
		profile, err := profileFor(config, config.Self, peerAudience(role), nil)
		if err != nil || profile.GrantAuthority.MaxTokenLifetime != 25*time.Minute+time.Second {
			t.Fatal("VM grants do not have the bounded qualification lifetime")
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareVMConfigs(root); err == nil {
			t.Fatal("VM preparation overwrote existing credentials")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("rejected preparation changed existing credentials")
		}
	}
}
