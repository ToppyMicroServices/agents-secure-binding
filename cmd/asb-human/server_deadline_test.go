// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/humanapp"
)

func TestServersBoundIncompleteRequestBodies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	running, err := startServers(t.Context(), serveOptions{dir: dir, coreAddress: "127.0.0.1:0", webAddress: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { running.close(t.Context()) })
	for name, server := range map[string]*http.Server{"core": running.core, "web": running.web} {
		if server.ReadTimeout != 15*time.Second {
			t.Fatalf("%s body deadline = %v, want 15s", name, server.ReadTimeout)
		}
		if server.WriteTimeout != 30*time.Second {
			t.Fatalf("%s write deadline = %v, want 30s", name, server.WriteTimeout)
		}
	}
	certificate, err := tls.LoadX509KeyPair(filepath.Join(dir, "agent.pem"), filepath.Join(dir, "agent-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test CA")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots, Certificates: []tls.Certificate{certificate}}
	webURL, err := url.Parse(running.webOrigin)
	if err != nil {
		t.Fatal(err)
	}
	// A complete authenticated request must still work with the same server
	// configuration. Existing approval tests cover the successful mutations.
	client, err := newClient(dir, humanapp.ActorAgent, running.coreAddress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Execute(context.Background(), humanapp.Command{CommandID: "deadline-control", Kind: humanapp.KindInbox}); err != nil {
		t.Fatalf("ordinary authenticated request: %v", err)
	}
	for _, route := range []string{humanapp.ChallengePath, humanapp.CommandPath, "/api/session"} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%v", route, chunked), func(t *testing.T) {
				t.Parallel()
				address := running.coreAddress
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				var conn net.Conn
				var err error
				if route == "/api/session" {
					address = webURL.Host
					conn, err = dialer.Dial("tcp", address)
				} else {
					conn, err = tls.DialWithDialer(dialer, "tcp", address, tlsConfig.Clone())
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
					t.Fatal(err)
				}
				framing, partial := "Content-Length: 2\r\n", "{"
				if chunked {
					framing, partial = "Transfer-Encoding: chunked\r\n", "1\r\n{\r\n"
				}
				started := time.Now()
				if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nContent-Type: application/json\r\nConnection: close\r\n%s\r\n%s", route, address, running.webOrigin, framing, partial); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
				if err != nil {
					t.Fatalf("server did not reject the incomplete body before client deadline: %v", err)
				}
				defer response.Body.Close()
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusBadRequest {
					t.Fatalf("incomplete body status = %d", response.StatusCode)
				}
				if elapsed := time.Since(started); elapsed < 14*time.Second || elapsed >= 20*time.Second {
					t.Fatalf("body read elapsed %v; want the server's 15s deadline", elapsed)
				}
			})
		}
	}
}
