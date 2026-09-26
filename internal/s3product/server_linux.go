// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/awsiam"
	"golang.org/x/sys/unix"
)

func authorityLock(directory string) (*os.File, error) {
	// The store validates its private directory before this lock is acquired.
	path := filepath.Join(directory, "authority.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrConfiguration
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, ErrConfiguration
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("S3 policy authority already running")
	}
	return f, nil
}

// Serve holds an exclusive authority lease until every handler has stopped.
// Restart applies a complete policy bundle and persists omitted-ID revocation
// before accepting traffic. It never auto-initializes or retries stored effects.
func Serve(ctx context.Context, path string) error {
	if ctx == nil {
		return ErrConfiguration
	}
	runtimeContext, stop := context.WithCancel(ctx)
	defer stop()
	loaded, err := loadConfig(path)
	if err != nil {
		return err
	}
	c := loaded.config
	store, err := lp.OpenSQLiteStore(ctx, c.StoreDirectory)
	if err != nil {
		return err
	}
	defer store.Close()
	if c.Namespace == "" || c.Namespace != store.Namespace() {
		return errors.New("configuration namespace does not match restored journal")
	}
	lock, err := authorityLock(c.StoreDirectory)
	if err != nil {
		return err
	}
	defer lock.Close()
	policies := asbbinding.NewPolicies()
	problem := loaded.profile.Problem()
	for _, mandate := range loaded.mandates {
		if !strings.HasPrefix(mandate.ID, c.Namespace+"/") {
			return ErrConfiguration
		}
		if err = policies.Put(asbbinding.PolicyRecord{Problem: problem, Mandate: mandate}); err != nil {
			return ErrConfiguration
		}
	}
	service, err := asbbinding.NewService(asbbinding.Config{Policies: policies, Store: store, Issuer: c.Issuer, Audience: c.Audience, GrantKeys: c.GrantKeys, ActorKeys: c.ActorKeys, SigningKey: loaded.signer, MaxEvaluations: 1 << lp.MaxGrants, Executors: map[string]asbbinding.Executor{awsiam.Operation: loaded.executor.Execute}})
	if err != nil {
		return ErrConfiguration
	}
	handler, err := asbbinding.NewHTTPHandler(asbbinding.HTTPConfig{Service: service, MaxChallenges: 1024, ChallengeTTL: 30 * time.Second})
	if err != nil {
		return err
	}
	// Reserve the configured listener before committing an operator policy update.
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Listen)
	if err != nil {
		return errors.New("S3 listener unavailable")
	}
	defer listener.Close()
	if err = store.SyncMandates(ctx, loaded.mandates); err != nil {
		return err
	}
	gate := &requestGate{handler: handler, slots: make(chan struct{}, 8)}
	server := &http.Server{Handler: gate, TLSConfig: loaded.tls, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return runtimeContext }}
	defer func() { stop(); _ = server.Close(); gate.stopAndWait() }()
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, loaded.tls)) }()
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("S3 server stopped unexpectedly")
	case <-ctx.Done():
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		if err = server.Shutdown(cleanup); err != nil {
			_ = server.Close()
			<-done
			return errors.New("S3 shutdown deadline exceeded; inspect uncertain operations")
		}
		<-done
		return nil
	}
}

type requestGate struct {
	handler http.Handler
	slots   chan struct{}
	mu      sync.Mutex
	closed  bool
	active  sync.WaitGroup
}

func (g *requestGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	select {
	case g.slots <- struct{}{}:
	default:
		g.mu.Unlock()
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	g.active.Add(1)
	g.mu.Unlock()
	defer func() { <-g.slots; g.active.Done() }()
	g.handler.ServeHTTP(w, r)
}

func (g *requestGate) stopAndWait() { g.mu.Lock(); g.closed = true; g.mu.Unlock(); g.active.Wait() }
