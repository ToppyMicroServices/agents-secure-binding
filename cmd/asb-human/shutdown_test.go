// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/humanapp"
)

func TestCanceledCleanupStillDrainsActiveRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	store, err := humanapp.OpenStore(filepath.Join(t.TempDir(), "state.sqlite"))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "drained")
	})}
	core := &selfTestCore{server: server, store: store, done: make(chan error, 1)}
	go func() { core.done <- server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = store.Close() })
	requestDone := make(chan error, 1)
	client := &http.Client{Timeout: 5 * time.Second}
	go func() {
		response, err := client.Get("http://" + listener.Addr().String())
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	closed := make(chan error, 1)
	go func() { closed <- core.close(ctx) }()
	select {
	case err := <-closed:
		t.Fatalf("cleanup did not wait for active response: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	once.Do(func() { close(release) })
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
