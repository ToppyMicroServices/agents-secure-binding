// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

func TestClientRejectsOversizedResponseHeadersBeforeTimeout(t *testing.T) {
	cluster := newTestCluster(t, time.Hour)
	defer cluster.stop()
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.Header().Set("X-Oversized", strings.Repeat("x", (1<<20)+int(maxResponseOverheadBytes)+1))
		_, _ = writer.Write([]byte(`{"nonce":"unused"}`))
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cluster.materials[1].tlsCert},
		ClientCAs:    cluster.roots, ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := *cluster.nodes[0].config.Client
	client.Timeout = 10 * time.Second
	remote := cluster.nodes[1].Info()
	remote.Endpoint = server.Listener.Addr().String()
	result := callStalledPeer(t.Context(), &client, remote, cluster.nodes[0].Info())
	select {
	case err := <-result:
		var networkError net.Error
		if err == nil || errors.As(err, &networkError) && networkError.Timeout() {
			t.Fatalf("oversized response was not rejected by its byte budget: %v", err)
		}
		if requests.Load() != 1 {
			t.Fatal("client accepted an oversized nonce response and sent an action")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client waited for timeout while parsing oversized headers")
	}
}

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
