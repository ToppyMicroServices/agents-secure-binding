// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeBoundsTLSConnectionsAndRecoversCapacity(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	config := cluster.nodeConfig(0, cluster.infos[0], cluster.nodes[0].config.Directory, cluster.newClient(0))
	config.ListenAddress = "127.0.0.1:0"
	config.StatePath = filepath.Join(t.TempDir(), "state.json")
	config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	config.RequestTimeout = time.Hour // Only explicit closure frees a test slot.
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan struct{}, maxPeerConnections+1)
	node.server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted <- struct{}{}
		}
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = node.Stop(ctx)
	})
	var clients []net.Conn
	t.Cleanup(func() {
		for _, client := range clients {
			_ = client.Close()
		}
	})
	dial := func() {
		t.Helper()
		client, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", node.Info().Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	for range maxPeerConnections {
		dial()
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("listener did not accept an available connection slot")
		}
	}
	dial()
	select {
	case <-accepted:
		t.Fatal("listener allocated a TLS connection beyond its capacity")
	case <-time.After(100 * time.Millisecond):
	}
	if err := clients[0].Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("closing a stalled TLS connection did not release capacity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- node.Stop(ctx) }()
	select {
	case err := <-stopped:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown failed unexpectedly: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("saturated listener prevented shutdown")
	}
}
