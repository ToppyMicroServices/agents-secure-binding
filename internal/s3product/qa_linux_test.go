// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

func TestConnectionLimitBoundsAcceptAndRecovers(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := newConnectionLimit(listener, 2)
	defer limited.Close()
	var clients, servers []net.Conn
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
		for _, c := range servers {
			_ = c.Close()
		}
	}()
	for range 2 {
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		s, err := limited.Accept()
		if err != nil {
			t.Fatal(err)
		}
		servers = append(servers, s)
	}
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := limited.Accept(); accepted <- c }()
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clients = append(clients, c)
	select {
	case <-accepted:
		t.Fatal("accepted beyond cap")
	case <-time.After(50 * time.Millisecond):
	}
	_ = servers[0].Close()
	_ = servers[0].Close() // Release is idempotent.
	select {
	case c = <-accepted:
		if c == nil {
			t.Fatal("connection not recovered")
		}
		servers = append(servers, c)
	case <-time.After(time.Second):
		t.Fatal("slot not released")
	}
	if len(limited.slots) != 2 {
		t.Fatal("incorrect active slots")
	}
	go func() { c, _ := limited.Accept(); accepted <- c }()
	_ = limited.Close()
	select {
	case c = <-accepted:
		if c != nil {
			t.Fatal("accept succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock accept")
	}
}

func TestDiagnosticsAreBoundedAndRedactUntrustedText(t *testing.T) {
	var output bytes.Buffer
	d := newDiagnostics(&output)
	secret := "fixture-token-secret-and-object-body"
	for range 10000 {
		_, _ = d.Write([]byte(secret))
	}
	d.Close()
	if bytes.Contains(output.Bytes(), []byte(secret)) || bytes.Count(output.Bytes(), []byte("\n")) > 60 || output.Len() > 16000 {
		t.Fatal("unbounded or raw diagnostics")
	}
	output.Reset()
	d = newDiagnostics(&output)
	execute := d.executor(func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
		return lp.EffectResult{}, errors.New(secret)
	})
	_, _ = execute(t.Context(), secret, lp.Request{}, lp.Solution{})
	d.Close()
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), `"stage":"adapter"`) || !strings.Contains(output.String(), `"correlation":`) {
		t.Fatal("diagnostic did not preserve safe classification")
	}
}

type failOnceDiagnosticWriter struct {
	bytes.Buffer
	failed bool
}

func (w *failOnceDiagnosticWriter) Write(raw []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, io.ErrClosedPipe
	}
	return w.Buffer.Write(raw)
}

func TestDiagnosticsRetainSuppressedCountAfterWriteFailure(t *testing.T) {
	var output failOnceDiagnosticWriter
	d := newDiagnostics(&output)
	defer d.Close()
	// Represent seven earlier events lost to rate limiting or a full queue.
	d.mu.Lock()
	d.suppressed = 7
	d.mu.Unlock()
	d.emit("transport", "server_error", "")
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		count := d.suppressed
		d.mu.Unlock()
		if count > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed diagnostic write did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	d.emit("transport", "server_error", "")
	d.Close()
	var event diagnosticEvent
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.Suppressed != 8 {
		t.Fatalf("lost events were undercounted: got %d, want 8", event.Suppressed)
	}
}

type blockedDiagnosticWriter struct {
	started, release chan struct{}
	once             sync.Once
}

func (w *blockedDiagnosticWriter) Write(raw []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(raw), nil
}

func TestBlockedDiagnosticsBoundEmissionAndShutdown(t *testing.T) {
	output := &blockedDiagnosticWriter{started: make(chan struct{}), release: make(chan struct{})}
	d := newDiagnostics(output)
	var release sync.Once
	unblock := func() { release.Do(func() { close(output.release) }) }
	t.Cleanup(func() { unblock(); d.Close() })
	d.emit("transport", "server_error", "")
	select {
	case <-output.started:
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostic writer did not start")
	}
	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		for range 10000 {
			d.emit("transport", "server_error", "")
		}
	}()
	select {
	case <-emitted:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked diagnostics stalled emission")
	}
	closed := make(chan struct{})
	go func() { d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked diagnostics stalled shutdown")
	}
	d.emit("transport", "server_error", "") // Closed queues reject new events.
	unblock()
	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostic writer did not exit after the sink recovered")
	}
}

func TestConnectionCyclesReleaseDescriptorsAndGoroutines(t *testing.T) {
	countFD := func() int {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(files)
	}
	baseFD, baseGo := countFD(), runtime.NumGoroutine()
	for range 100 {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := newConnectionLimit(listener, 1)
		client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		server, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		_ = server.Close()
		_ = l.Close()
	}
	if countFD() > baseFD+2 || runtime.NumGoroutine() > baseGo+2 {
		t.Fatal("connection cycles retained resources")
	}
	t.Logf("cycles=100 fd_before=%d fd_after=%d goroutines_before=%d goroutines_after=%d", baseFD, countFD(), baseGo, runtime.NumGoroutine())
}

func TestJournalFailureIsDiagnosableWithoutChangingUnknown(t *testing.T) {
	store, err := lp.CreateSQLiteStore(t.Context(), filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	problem := lp.Problem{Schema: lp.ProblemSchemaV1, Permissions: []lp.Permission{{ID: "read", Cost: 1}}, Grants: []lp.Grant{{ID: "read", Permissions: []string{"read"}}}, Required: []string{"read"}, Allowed: []string{"read"}}
	solution, err := lp.Solve(t.Context(), problem, 2)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	request := lp.Request{ActorID: "actor", TaskID: "task", Action: lp.Action{Operation: "read", Resource: "private-fixture-resource"}}
	action, err := lp.DigestAction(request.Action)
	if err != nil {
		t.Fatal(err)
	}
	mandate := lp.Mandate{ID: store.Namespace() + "/mandate", PolicyRef: "test", ActorID: request.ActorID, TaskID: request.TaskID, ActionDigest: action, ProblemDigest: solution.ProblemDigest, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MaxTTLSeconds: 300, AllowAutomatic: true}
	authorizer, err := lp.NewAuthorizer(lp.AuthorizerConfig{Problem: problem, Mandate: mandate, SigningKey: private, MaxEvaluations: 2})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := authorizer.Authorize(t.Context(), request, solution)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	d := newDiagnostics(&output)
	observed := &observedStore{SQLiteStore: store, diagnostics: d}
	_, err = observed.Run(t.Context(), store.Namespace()+"/operation", capability, public, mandate, request, time.Now(), func(context.Context, string, lp.Request) (lp.EffectResult, error) {
		_ = store.Close()
		return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: action}, nil
	})
	d.Close()
	if !errors.Is(err, lp.ErrOutcomeUnknown) || !strings.Contains(output.String(), `"stage":"journal"`) || strings.Contains(output.String(), request.Action.Resource) {
		t.Fatal("persistence diagnosis/state/privacy failure")
	}
}
