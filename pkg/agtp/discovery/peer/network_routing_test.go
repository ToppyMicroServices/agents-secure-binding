// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestLANRestoreRevalidatesPersistedPeers(t *testing.T) {
	for _, change := range []string{"unchanged", "unregistered", "outside-cidr", "stale-endpoint"} {
		t.Run(change, func(t *testing.T) {
			config := networkValidationConfig(t)
			first := discovery.NodeInfo{ID: testNodeID("40"), Endpoint: "10.20.30.8:9443"}
			second := discovery.NodeInfo{ID: testNodeID("fe"), Endpoint: "10.20.30.9:9443"}
			store, err := NewStateStore(config.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Save(PersistentState{Peers: []discovery.NodeInfo{first, second}}); err != nil {
				t.Fatal(err)
			}

			registered := first
			if change == "stale-endpoint" {
				registered.Endpoint = "10.20.30.10:9443"
			}
			if change != "unregistered" {
				certificate, _ := issueTestCA(t)
				if err := config.Directory.Add(certificate, PeerIdentity{Node: registered}); err != nil {
					t.Fatal(err)
				}
			}
			certificate, _ := issueTestCA(t)
			if err := config.Directory.Add(certificate, PeerIdentity{Node: second}); err != nil {
				t.Fatal(err)
			}
			if change == "outside-cidr" {
				config.NetworkPolicy = testNetworkPolicy("10.20.30.7/32", "10.20.30.9/32")
			}

			// Constructing and stopping this node performs only local state I/O.
			// No listener or gossip worker is started.
			node, err := NewNode(config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := node.Stop(context.Background()); err != nil {
					t.Error(err)
				}
			})
			want := []discovery.NodeInfo{second}
			if change == "unchanged" {
				want = []discovery.NodeInfo{first, second}
			}
			if got := node.routing.Peers(); !reflect.DeepEqual(got, want) {
				t.Fatalf("restored peers = %+v, want %+v", got, want)
			}
			if err := node.persist(); err != nil {
				t.Fatal(err)
			}
			assertStoredNetworkPeers(t, store, want)
		})
	}
}

func TestLANEndpointRotationAtCapacity(t *testing.T) {
	config := networkValidationConfig(t)
	first := discovery.NodeInfo{ID: testNodeID("40"), Endpoint: "10.20.30.8:9443"}
	second := discovery.NodeInfo{ID: testNodeID("fe"), Endpoint: "10.20.30.9:9443"}
	firstCertificate, _ := issueTestCA(t)
	secondCertificate, _ := issueTestCA(t)
	if err := config.Directory.Add(firstCertificate, PeerIdentity{Node: first}); err != nil {
		t.Fatal(err)
	}
	if err := config.Directory.Add(secondCertificate, PeerIdentity{Node: second}); err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	for _, peer := range []discovery.NodeInfo{first, second} {
		if err := node.AddPeer(peer); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(node.routing.Peers()); got != node.config.MaxPeers {
		t.Fatalf("routing table has %d peers, want a full table of %d", got, node.config.MaxPeers)
	}

	updated := first
	updated.Endpoint = "10.20.30.10:9443"
	if err := config.Directory.Add(firstCertificate, PeerIdentity{Node: updated}); err != nil {
		t.Fatal(err)
	}
	if err := node.AddPeer(first); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old endpoint AddPeer error = %v, want ErrUnauthorized", err)
	}
	if err := node.AddPeer(updated); err != nil {
		t.Fatalf("replace endpoint at capacity: %v", err)
	}
	want := []discovery.NodeInfo{updated, second}
	if got := node.routing.Peers(); !reflect.DeepEqual(got, want) {
		t.Fatalf("rotated peers = %+v, want %+v", got, want)
	}
	assertStoredNetworkPeers(t, node.state, want)
}

func assertStoredNetworkPeers(t *testing.T, store *StateStore, want []discovery.NodeInfo) {
	t.Helper()
	state, found, err := store.Load()
	if err != nil || !found {
		t.Fatalf("load routing snapshot = found:%v, error:%v", found, err)
	}
	if !reflect.DeepEqual(state.Peers, want) {
		t.Fatalf("persisted peers = %+v, want %+v", state.Peers, want)
	}
}
