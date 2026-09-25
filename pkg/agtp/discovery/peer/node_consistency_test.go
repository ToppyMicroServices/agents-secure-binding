// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestGossipRetriesFailedPersistenceBeforeAcknowledging(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	sender, receiver := cluster.nodes[0], cluster.nodes[1]
	record := discovery.Record{AgentID: "durable-agent", Capabilities: []string{"generate"}, Version: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := sender.Announce(record); err != nil {
		t.Fatal(err)
	}
	original := receiver.state.path
	blocked := filepath.Join(t.TempDir(), "directory-not-file")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	receiver.state.path = blocked
	defer func() { receiver.state.path = original }()
	for attempt := 0; attempt < 2; attempt++ {
		if err := sender.GossipOnce(context.Background()); err == nil {
			t.Fatal("replication acknowledged an unsaved snapshot")
		}
		if _, err := receiver.Discover(context.Background(), discovery.Query{Capability: "generate", Limit: 10}, discovery.Requester{}); err == nil {
			t.Fatal("search exposed an uncommitted update")
		}
		assertHealthStatus(t, receiver, http.StatusServiceUnavailable)
	}
	receiver.state.path = original
	mustGossip(t, sender)
	state, found, err := receiver.state.Load()
	if err != nil || !found || len(state.Presence.Records) != 1 || state.Presence.Records[0].AgentID != record.AgentID {
		t.Fatalf("retry did not commit the replicated record: %+v, %v, %v", state, found, err)
	}
	assertMatchCount(t, receiver, "generate", 1)
	assertHealthStatus(t, receiver, http.StatusOK)
}

func assertHealthStatus(t *testing.T, node *Node, status int) {
	t.Helper()
	response := httptest.NewRecorder()
	node.handleHealth(response, httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody))
	if response.Code != status {
		t.Fatalf("health status = %d, want %d", response.Code, status)
	}
}

func TestGossipPersistsSuppressionMetadataAndDoesNotRewriteStableState(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	sender, receiver := cluster.nodes[0], cluster.nodes[1]
	if _, err := sender.Withdraw("retained-agent", 2); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, sender)
	lease := time.Now().Add(72 * time.Hour).UTC()
	if _, err := sender.Announce(discovery.Record{
		AgentID: "retained-agent", Capabilities: []string{"generate"}, Version: 1, ExpiresAt: lease,
	}); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, sender)
	state, found, err := receiver.state.Load()
	if err != nil || !found || len(state.Presence.Tombstones) != 1 {
		t.Fatalf("load retained state = %+v, %v, %v", state, found, err)
	}
	if !state.Presence.Tombstones[0].SuppressUntil.Equal(lease) {
		t.Fatal("same-version suppression metadata was not committed")
	}
	mustGossip(t, sender)
	after, _, err := receiver.state.Load()
	if err != nil || !reflect.DeepEqual(state, after) {
		t.Fatalf("stable gossip rewrote state: before=%+v after=%+v err=%v", state, after, err)
	}
}

func TestGossipReusesWithdrawnNameAtCapacity(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	sender, receiver := cluster.nodes[0], cluster.nodes[1]
	for i := 0; i < DefaultMaxRecords-1; i++ {
		if _, err := sender.Announce(discovery.Record{AgentID: fmt.Sprintf("agent-%03d", i), Capabilities: []string{"generate"}, Version: 1, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	binding := discovery.NameBinding{Name: "reusable.example", AgentID: "old-agent", Endpoint: "https://127.0.0.1:9443", Capabilities: []string{"generate"}, Version: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if _, err := sender.Register(binding); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, sender)
	if _, err := sender.Deregister(binding.Name, 2); err != nil {
		t.Fatal(err)
	}
	binding.AgentID = "new-agent"
	binding.Version = 2
	if _, err := sender.Register(binding); err != nil {
		t.Fatal(err)
	}
	mustGossip(t, sender)
	got, ok := receiver.Resolve(binding.Name)
	if !ok || got.AgentID != binding.AgentID {
		t.Fatalf("replacement name did not converge at capacity: %+v, %v", got, ok)
	}
	assertMatchCount(t, receiver, "generate", DefaultMaxRecords)
}

func TestStoppedNodeRejectsLateReplicationAndSearch(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	node := cluster.nodes[1]
	cluster.stopNode(1)
	body, err := json.Marshal(ReplicateRequest{Protocol: ProtocolVersion, Sender: cluster.nodes[0].Info(), Delta: discovery.Delta{Records: []discovery.Record{{AgentID: "late-agent", Capabilities: []string{"generate"}, Version: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	node.handleReplicate(response, nil, PeerIdentity{Node: cluster.nodes[0].Info()}, body)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("late replication status = %d", response.Code)
	}
	if records, _, _ := node.Counts(); records != 0 {
		t.Fatal("stopped node accepted a late record")
	}
	if _, err := node.Discover(context.Background(), discovery.Query{Capability: "generate", Limit: 10}, discovery.Requester{}); err == nil {
		t.Fatal("stopped node still serves discovery")
	}
}

func TestConcurrentStartStopCompletesShutdown(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	for attempt := 0; attempt < 8; attempt++ {
		config := cluster.nodeConfig(0, cluster.infos[0], cluster.nodes[0].config.Directory, cluster.newClient(0))
		config.ListenAddress = "127.0.0.1:0"
		config.StatePath = filepath.Join(t.TempDir(), "state.json")
		config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
		node, err := NewNode(config)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		started := make(chan error, 1)
		stopped := make(chan error, 1)
		go func() { <-start; started <- node.Start() }()
		go func() {
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			stopped <- node.Stop(ctx)
		}()
		close(start)
		<-started // Starting after Stop has won is intentionally rejected.
		if err := <-stopped; err != nil {
			t.Fatal(err)
		}
		if !node.closed.Load() || node.ready.Load() {
			t.Fatal("shutdown left a serving node")
		}
	}
}
