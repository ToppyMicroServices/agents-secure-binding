// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestClientTimeoutBoundsNonceReadWithLongerParentDeadline(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	client, remote, received := stalledNoncePeer(t, cluster)
	client.Timeout = 250 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := callStalledPeer(ctx, client, remote, cluster.nodes[0].Info())
	waitForNonceRequest(t, received, result)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("stalled nonce exchange succeeded")
		}
		if ctx.Err() != nil {
			t.Fatalf("exchange waited for the longer parent deadline: %v", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client timeout did not interrupt the nonce read")
	}
}

func TestClientCancellationInterruptsNonceRead(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	client, remote, received := stalledNoncePeer(t, cluster)
	client.Timeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := callStalledPeer(ctx, client, remote, cluster.nodes[0].Info())
	waitForNonceRequest(t, received, result)
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled nonce exchange succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt the nonce read")
	}
}

// stalledNoncePeer uses a configured peer's trusted certificate and accepts
// mutual TLS normally, then waits while handling the nonce request.
func stalledNoncePeer(t *testing.T, cluster *testCluster) (*Client, discovery.NodeInfo, <-chan struct{}) {
	t.Helper()
	received := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != NoncePath || request.Method != http.MethodPost {
			http.NotFound(writer, request)
			return
		}
		received <- struct{}{}
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cluster.materials[1].tlsCert},
		ClientCAs:    cluster.roots, ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	client := *cluster.nodes[0].config.Client
	remote := cluster.nodes[1].Info()
	remote.Endpoint = server.Listener.Addr().String()
	return &client, remote, received
}

func callStalledPeer(ctx context.Context, client *Client, remote, sender discovery.NodeInfo) <-chan error {
	result := make(chan error, 1)
	go func() {
		_, err := client.FindNode(ctx, remote, FindNodeRequest{
			Protocol: ProtocolVersion, Sender: sender, Target: remote.ID, Count: 2,
		})
		result <- err
	}()
	return result
}

func waitForNonceRequest(t *testing.T, received <-chan struct{}, result <-chan error) {
	t.Helper()
	select {
	case <-received:
	case err := <-result:
		t.Fatalf("client returned before sending its nonce request: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("client did not reach the trusted TLS peer")
	}
}
