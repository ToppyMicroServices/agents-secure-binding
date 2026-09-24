// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"testing"
	"time"
)

func TestLocateFindsThirdPeerWithLocalDirectoryEntry(t *testing.T) {
	for _, includeLocal := range []bool{false, true} {
		name := "remote-entries-only"
		if includeLocal {
			name = "shared-directory-includes-local"
		}
		t.Run(name, func(t *testing.T) {
			cluster := newTestCluster(t, time.Hour)
			defer cluster.stop()
			node := cluster.nodes[0]
			if includeLocal {
				if err := node.config.Directory.Add(cluster.materials[0].leaf, PeerIdentity{
					Node: node.Info(), Profile: cluster.peerProfile(0, 0, nil),
				}); err != nil {
					t.Fatal(err)
				}
			}
			// B returns A before C when the target is A. The local entry must
			// not consume the one remaining routing slot needed to learn C.
			peers, err := node.Locate(context.Background(), node.Info().ID, 2)
			if err != nil {
				t.Fatal(err)
			}
			if !containsNode(peers, cluster.nodes[2].Info().ID) {
				t.Fatalf("lookup did not find node C: %+v", peers)
			}
			known := node.routing.Peers()
			if len(known) != 2 || containsNode(known, node.Info().ID) || !containsNode(known, cluster.nodes[2].Info().ID) {
				t.Fatalf("routing table did not retain the two remote peers: %+v", known)
			}
		})
	}
}
