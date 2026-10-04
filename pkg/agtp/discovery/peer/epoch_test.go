// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func mustEpochGossip(t *testing.T, nodes ...*Node) {
	t.Helper()
	for _, node := range nodes {
		mustGossip(t, node)
	}
}

func restartAtEpoch(t *testing.T, cluster *testCluster, index int, epoch uint64, from *uint64) {
	t.Helper()
	config := cluster.nodes[index].config
	cluster.stopNode(index)
	config.Info = cluster.infos[index]
	config.ListenAddress = config.Info.Endpoint
	config.Epoch, config.ReclaimFromEpoch = epoch, from
	config.InitializeEpoch = false
	config.TombstoneRetention = 0
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	cluster.nodes[index] = node
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestEpochReclamationRejectsPartitionedPeerAndRestoredSnapshot(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	old := discovery.NameBinding{
		Name: "old.example", AgentID: "retired-agent", Endpoint: "https://127.0.0.1:9443",
		Capabilities: []string{"generate"}, Version: 1, ExpiresAt: time.Now().Add(72 * time.Hour),
	}
	if _, err := cluster.nodes[0].Register(old); err != nil {
		t.Fatal(err)
	}
	mustEpochGossip(t, cluster.nodes[0], cluster.nodes[1])
	cluster.nodes[1].SetPeerBlocked(cluster.infos[2].ID, true)
	cluster.nodes[2].SetPeerBlocked(cluster.infos[1].ID, true)
	if _, err := cluster.nodes[0].Deregister(old.Name, 2); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, cluster.nodes[0])
	oldSnapshot, err := os.ReadFile(cluster.statePath(0))
	if err != nil {
		t.Fatal(err)
	}
	from := uint64(0)
	restartAtEpoch(t, cluster, 0, 1, &from)
	restartAtEpoch(t, cluster, 1, 1, &from)
	cluster.nodes[2].SetPeerBlocked(cluster.infos[1].ID, false)
	if err := cluster.nodes[2].GossipOnce(context.Background()); err == nil {
		t.Fatal("old-epoch peer crossed the reclamation boundary")
	}
	if err := cluster.nodes[1].gossipPeer(context.Background(), cluster.infos[2]); err == nil {
		t.Fatal("new-epoch peer accepted an old-epoch response")
	}
	if _, err := cluster.nodes[2].config.Client.FindNode(context.Background(), cluster.infos[1], FindNodeRequest{
		Protocol: ProtocolVersion, Sender: cluster.infos[2], Target: cluster.infos[0].ID, Count: 2,
	}); err == nil {
		t.Fatal("old-epoch DHT request crossed the reclamation boundary")
	}
	for _, node := range cluster.nodes[:2] {
		assertMatchCount(t, node, "generate", 0)
		if _, ok := node.Resolve(old.Name); ok {
			t.Fatal("old ANS binding was retagged as current")
		}
		if records, tombstones, _ := node.Counts(); records != 0 || tombstones != 0 {
			t.Fatalf("reclamation retained population: %d/%d", records, tombstones)
		}
	}
	// The partitioned peer must discard its old live data too. Merely trusting
	// the peer's identity never gives it permission to change the epoch.
	restartAtEpoch(t, cluster, 2, 1, &from)
	mustEpochGossip(t, cluster.nodes...)
	assertMatchCount(t, cluster.nodes[2], "generate", 0)
	if _, err := cluster.nodes[0].Announce(discovery.Record{
		AgentID: "current-agent", Capabilities: []string{"generate"}, Version: 1,
	}); err != nil {
		t.Fatal(err)
	}
	mustEpochGossip(t, cluster.nodes[0], cluster.nodes[1])
	for cycle := 0; cycle < 2; cycle++ {
		for index := range cluster.nodes {
			restartAtEpoch(t, cluster, index, 1, nil)
			assertMatchCount(t, cluster.nodes[index], "generate", 1)
		}
	}
	// A stale snapshot alone cannot roll back the deployment's external epoch.
	cluster.stopNode(0)
	config := cluster.nodes[0].config
	config.ReclaimFromEpoch = nil
	if err := os.WriteFile(config.StatePath, oldSnapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	if node, err := NewNode(config); !errors.Is(err, ErrEpochMismatch) {
		if node != nil {
			_ = node.Stop(context.Background())
		}
		t.Fatalf("stale snapshot load = %v", err)
	}
}

func TestEpochReclamationIsExplicitAndOneTime(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	config := cluster.nodes[0].config
	config.StatePath = filepath.Join(t.TempDir(), "state.json")
	config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	config.Epoch, config.TombstoneRetention = 7, 0
	config.InitializeEpoch = true
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNode(config); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("reused initialization instruction = %v", err)
	}
	config.InitializeEpoch = false
	for _, epoch := range []uint64{0, 6, 8} {
		wrong := config
		wrong.Epoch = epoch
		if _, err := NewNode(wrong); !errors.Is(err, ErrEpochMismatch) {
			t.Fatalf("unapproved epoch %d = %v", epoch, err)
		}
	}
	from := uint64(7)
	config.Epoch, config.ReclaimFromEpoch = 8, &from
	node, err = NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.Announce(discovery.Record{AgentID: "new-agent", Capabilities: []string{"generate"}, Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := node.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewNode(config); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("reused migration instruction = %v", err)
	}
	config.ReclaimFromEpoch = nil
	node, err = NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := node.Stop(context.Background()); err != nil {
			t.Errorf("stop restored epoch node: %v", err)
		}
	}()
	assertMatchCount(t, node, "generate", 1)
	state, found, err := node.state.Load()
	if err != nil || !found || state.Epoch != 8 || state.Version != epochStateVersion {
		t.Fatalf("durable epoch = %+v, %v, %v", state, found, err)
	}
}

func TestEpochRetainsSuppressionUntilExplicitReclamation(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	config := cluster.nodes[0].config
	config.StatePath = filepath.Join(t.TempDir(), "state.json")
	config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	config.Epoch, config.TombstoneRetention = 1, 0
	now := time.Now().UTC()
	config.Now = func() time.Time { return now }
	for epoch := uint64(1); epoch <= 4; epoch++ {
		config.Epoch = epoch
		config.InitializeEpoch = epoch == 1
		if epoch > 1 {
			from := epoch - 1
			config.ReclaimFromEpoch = &from
		}
		node, err := NewNode(config)
		if err != nil {
			t.Fatal(err)
		}
		if records, tombstones, _ := node.Counts(); records != 0 || tombstones != 0 {
			t.Fatalf("epoch %d retained retired history: %d/%d", epoch, records, tombstones)
		}
		for i := 0; i < DefaultMaxTombstones; i++ {
			if _, err := node.Withdraw(fmt.Sprintf("old-agent-%d-%d", epoch, i), 2); err != nil {
				t.Fatal(err)
			}
		}
		now = now.Add(365 * 24 * time.Hour)
		if changed, err := node.Announce(discovery.Record{AgentID: fmt.Sprintf("old-agent-%d-0", epoch), Capabilities: []string{"generate"}, Version: 1}); err != nil || changed {
			t.Fatalf("old record after retention = %v, %v", changed, err)
		}
		if _, err := node.Withdraw("one-too-many", 2); !errors.Is(err, discovery.ErrLimitExceeded) {
			t.Fatalf("full epoch did not fail closed: %v", err)
		}
		if err := node.Stop(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEpochProtocolRejectsMismatchBeforeMerging(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	from := uint64(0)
	restartAtEpoch(t, cluster, 1, 3, &from)
	node := cluster.nodes[1]
	for _, message := range []ReplicateRequest{
		{Protocol: ProtocolVersion},
		{Protocol: EpochProtocolVersion},
		{Protocol: EpochProtocolVersion, Epoch: 2},
		{Protocol: EpochProtocolVersion, Epoch: 4},
		{Protocol: ProtocolVersion, Epoch: 3},
	} {
		message.Sender = cluster.infos[0]
		message.Delta.Records = []discovery.Record{{AgentID: "stale-agent", Capabilities: []string{"generate"}, Version: 1}}
		body, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		node.handleReplicate(response, nil, PeerIdentity{Node: message.Sender}, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("protocol=%d epoch=%d: status=%d", message.Protocol, message.Epoch, response.Code)
		}
	}
	assertMatchCount(t, node, "generate", 0)
	// A valid new-epoch envelope cannot be substituted for an old signed body.
	signed := ReplicateRequest{Protocol: EpochProtocolVersion, Epoch: 2, Sender: cluster.infos[0]}
	signedBody, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	signed.Epoch = 3
	sentBody, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if status := cluster.sendPrepared(0, 1, ActionReplicate, signedBody, sentBody, false); status != http.StatusUnauthorized {
		t.Fatalf("substituted epoch status = %d", status)
	}
	if status := cluster.sendPrepared(0, 1, ActionReplicate, sentBody, sentBody, true); status != http.StatusUnauthorized {
		t.Fatalf("epoch request replay status = %d", status)
	}
}

func TestEpochSnapshotVersionValidation(t *testing.T) {
	for _, state := range []PersistentState{
		{Version: stateVersion, Epoch: 1},
		{Version: epochStateVersion, Epoch: 0},
		{Version: 0, Epoch: 1},
		{Version: epochStateVersion + 1, Epoch: 1},
	} {
		store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := writeChecksummedJSON(store.path, state); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Load(); !errors.Is(err, ErrUnsupportedState) {
			t.Fatalf("version=%d epoch=%d load=%v", state.Version, state.Epoch, err)
		}
	}
}

func TestEpochStartupFailsClosedOnUnreadableOrMissingState(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	config := cluster.nodes[0].config
	config.Epoch, config.TombstoneRetention = 1, 0
	config.InitializeEpoch = true
	config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	// A directory can never become the atomically replaced state file.
	config.StatePath = t.TempDir()
	if node, err := NewNode(config); err == nil || node != nil {
		t.Fatalf("failed epoch initialization returned serving-capable node: %v", err)
	}
	// Migration cannot be guessed when the expected prior snapshot is absent.
	config.StatePath = filepath.Join(t.TempDir(), "missing.json")
	config.InitializeEpoch = false
	if node, err := NewNode(config); !errors.Is(err, ErrEpochMismatch) || node != nil {
		t.Fatalf("lost snapshot was silently reinitialized: %v", err)
	}
	from := uint64(0)
	config.ReclaimFromEpoch = &from
	if node, err := NewNode(config); !errors.Is(err, ErrEpochMismatch) || node != nil {
		t.Fatalf("migration without source snapshot: %v", err)
	}
}

func TestEpochClientRejectsMismatchedReplies(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	for _, reply := range []struct {
		protocol int
		epoch    uint64
	}{{ProtocolVersion, 0}, {EpochProtocolVersion, 0}, {EpochProtocolVersion, 2}, {ProtocolVersion, 3}} {
		t.Run(fmt.Sprintf("protocol-%d-epoch-%d", reply.protocol, reply.epoch), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case NoncePath:
					_ = writeJSON(writer, nonceResponse{Nonce: "test-epoch-nonce"})
				case ReplicatePath:
					_ = writeJSON(writer, ReplicateResponse{Protocol: reply.protocol, Epoch: reply.epoch})
				case FindNodePath:
					_ = writeJSON(writer, FindNodeResponse{Protocol: reply.protocol, Epoch: reply.epoch})
				default:
					http.NotFound(writer, request)
				}
			}))
			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{cluster.materials[1].tlsCert},
				ClientCAs:    cluster.roots, ClientAuth: tls.RequireAndVerifyClientCert,
				MinVersion: tls.VersionTLS13,
			}
			server.StartTLS()
			defer server.Close()
			remote := cluster.infos[1]
			remote.Endpoint = server.Listener.Addr().String()
			client := cluster.nodes[0].config.Client
			if _, err := client.Replicate(context.Background(), remote, ReplicateRequest{
				Protocol: EpochProtocolVersion, Epoch: 3, Sender: cluster.infos[0],
			}); !errors.Is(err, ErrInvalidProtocol) {
				t.Fatalf("mismatched replication reply = %v", err)
			}
			if _, err := client.FindNode(context.Background(), remote, FindNodeRequest{
				Protocol: EpochProtocolVersion, Epoch: 3, Sender: cluster.infos[0], Target: cluster.infos[2].ID, Count: 2,
			}); !errors.Is(err, ErrInvalidProtocol) {
				t.Fatalf("mismatched DHT reply = %v", err)
			}
		})
	}
}

func TestEpochFailedSnapshotEncodingPreservesCommittedState(t *testing.T) {
	store, err := NewStateStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(PersistentState{Epoch: 4}); err != nil {
		t.Fatal(err)
	}
	invalid := PersistentState{Epoch: 5, Presence: discovery.Delta{Records: []discovery.Record{{
		AgentID: "invalid-time", Version: 1, Capabilities: []string{"generate"},
		ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	}}}}
	if err := store.Save(invalid); err == nil {
		t.Fatal("invalid snapshot unexpectedly encoded")
	}
	state, found, err := store.Load()
	if err != nil || !found || state.Epoch != 4 {
		t.Fatalf("failed replacement changed committed epoch: %+v, %v, %v", state, found, err)
	}
}
