// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"testing"
)

func TestDHTIterativeLocateFindsMultiPeerTarget(t *testing.T) {
	a := NodeInfo{ID: nodeID("01"), Endpoint: "127.0.0.1:9101"}
	b := NodeInfo{ID: nodeID("40"), Endpoint: "127.0.0.1:9102"}
	c := NodeInfo{ID: nodeID("fe"), Endpoint: "127.0.0.1:9103"}
	tables := map[string]*RoutingTable{}
	for _, node := range []NodeInfo{a, b, c} {
		table, err := NewRoutingTable(node, 20)
		if err != nil {
			t.Fatal(err)
		}
		tables[node.ID] = table
	}
	_, _ = tables[a.ID].Observe(b)
	_, _ = tables[b.ID].Observe(a)
	_, _ = tables[b.ID].Observe(c)
	_, _ = tables[c.ID].Observe(b)

	results, err := tables[a.ID].IterativeLocate(context.Background(), c.ID, 3, 2,
		func(_ context.Context, peer NodeInfo, target string) ([]NodeInfo, error) {
			return tables[peer.ID].HandleLocate(target, 3)
		})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, result := range results {
		if result.ID == c.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("multi-peer lookup did not find C: %+v", results)
	}
}

func TestDHTClosestUsesXORDistance(t *testing.T) {
	self := NodeInfo{ID: nodeID("00"), Endpoint: "self"}
	table, err := NewRoutingTable(self, 20)
	if err != nil {
		t.Fatal(err)
	}
	near := NodeInfo{ID: nodeID("02"), Endpoint: "near"}
	far := NodeInfo{ID: nodeID("f0"), Endpoint: "far"}
	_, _ = table.Observe(far)
	_, _ = table.Observe(near)
	closest, err := table.Closest(nodeID("01"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(closest) != 2 || closest[0].ID != near.ID {
		t.Fatalf("closest = %+v", closest)
	}
}

func nodeID(prefix string) string {
	return prefix + "00000000000000000000000000000000000000000000000000000000000000"
}
