// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMalformedPeerAndOuterRejectionsBoundAuditWork(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	now := time.Now()
	config := cluster.nodeConfig(0, cluster.infos[0], cluster.nodes[0].config.Directory, cluster.newClient(0))
	config.StatePath = filepath.Join(t.TempDir(), "state.json")
	config.AuditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	config.Now = func() time.Time { return now }
	config.RequestsPerSecond, config.RequestBurst = 1, 1
	node, err := NewNode(config)
	if err != nil {
		t.Fatal(err)
	}
	defer node.cancel()
	defer func() { _ = node.audit.Close() }()
	leaf := cluster.materials[1].leaf
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	request := func(method string, tlsState *tls.ConnectionState) int {
		t.Helper()
		r := httptest.NewRequest(method, ReplicatePath, nil)
		r.TLS = tlsState
		r.Header.Set("Content-Type", "text/plain")
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		node.routes().ServeHTTP(w, r)
		return w.Code
	}
	if status := request(http.MethodGet, state); status != http.StatusUnauthorized {
		t.Fatalf("first malformed request = %d", status)
	}
	if status := request(http.MethodPost, state); status != http.StatusTooManyRequests {
		t.Fatalf("malformed request bypassed peer limit: %d", status)
	}
	for range 20 {
		if status := request(http.MethodPost, nil); status != http.StatusUnauthorized {
			t.Fatalf("unknown peer status = %d", status)
		}
	}
	node.config.NetworkPolicy = &NetworkPolicy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	for range 20 {
		request(http.MethodGet, state)
	}
	count := func() int {
		t.Helper()
		raw, err := os.ReadFile(config.AuditPath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(raw), "\n")
	}
	if entries := count(); entries != 1 {
		t.Fatalf("rejected burst performed %d audit writes, want 1", entries)
	}
	if rejected := node.metrics.AuthRejected.Load(); rejected != 41 {
		t.Fatalf("rejections were lost from metrics: %d", rejected)
	}
	now = now.Add(time.Second)
	request(http.MethodGet, state)
	if entries := count(); entries != 2 {
		t.Fatalf("audit budget did not recover: %d", entries)
	}
}
