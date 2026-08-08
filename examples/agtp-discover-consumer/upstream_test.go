// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package agtpdiscover

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPUpstreamSendsPopulationDiscover(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestLine := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		requestLine <- strings.TrimSpace(line)
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				serverErr <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		body := []byte(`{"results":[{"agent_id":"agent-01"}]}`)
		_, err = io.WriteString(conn, fmt.Sprintf(
			"AGTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			len(body),
			body,
		))
		serverErr <- err
	}()

	result, err := (TCPUpstream{Address: listener.Addr().String(), Timeout: 2 * time.Second}).Discover(
		context.Background(),
		testQuery("generate"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	line := <-requestLine
	if !strings.HasPrefix(line, "AGTP/1.0 DISCOVER /population?") ||
		!strings.Contains(line, "capability=generate") ||
		!strings.Contains(line, "limit=12") ||
		!strings.Contains(line, "scope_negotiate=true") {
		t.Fatalf("request line = %q", line)
	}
	if result.StatusCode != 200 || !strings.Contains(string(result.Body), "agent-01") {
		t.Fatalf("result = %+v", result)
	}
}
