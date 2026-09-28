// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
