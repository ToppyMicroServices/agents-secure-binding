// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const replayStateFile = "replay-state.json"

type durableReplayStore struct {
	mu      sync.Mutex
	path    string
	expires map[string]int64
}

func runReplayStore(ctx context.Context, opts options, out outputWriter) error {
	store, err := openDurableReplayStore(filepath.Join(roleDirectory(opts.stateDir, "replay"), replayStateFile))
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /setnx", func(w http.ResponseWriter, r *http.Request) {
		if err := requirePeer(r, demoAudience); err != nil {
			writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", err.Error())
			return
		}
		var request replayRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		if request.Key == "" || request.TTLSeconds <= 0 || request.TTLSeconds > 300 {
			writeProblem(w, http.StatusBadRequest, "replay-key", "Invalid replay record", "key and TTL are outside the demo contract")
			return
		}
		inserted, err := store.SetNX(r.Context(), request.Key, time.Duration(request.TTLSeconds)*time.Second)
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "replay-store", "Replay store unavailable", "state could not be committed")
			return
		}
		writeJSON(w, http.StatusOK, "application/json", replayResponse{Inserted: inserted})
	})
	return serveTLS(ctx, opts, "replay", tls.RequireAndVerifyClientCert, mux, out)
}

func openDurableReplayStore(path string) (*durableReplayStore, error) {
	store := &durableReplayStore{path: path, expires: make(map[string]int64)}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read replay state: %w", err)
	}
	if len(raw) == 0 || json.Unmarshal(raw, &store.expires) != nil || store.expires == nil {
		return nil, fmt.Errorf("replay state is malformed; refusing to start")
	}
	for key, expires := range store.expires {
		if key == "" || expires <= 0 {
			return nil, fmt.Errorf("replay state contains an invalid record; refusing to start")
		}
	}
	return store, nil
}

func (s *durableReplayStore) SetNX(_ context.Context, key string, ttl time.Duration) (bool, error) {
	if s == nil || key == "" || ttl <= 0 {
		return false, fmt.Errorf("invalid replay record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	hashedKey := sha256String([]byte(key))
	for existing, expires := range s.expires {
		if expires <= now.Unix() {
			delete(s.expires, existing)
		}
	}
	if expires, exists := s.expires[hashedKey]; exists && expires > now.Unix() {
		return false, nil
	}
	s.expires[hashedKey] = now.Add(ttl).Unix()
	if err := s.persist(); err != nil {
		delete(s.expires, hashedKey)
		return false, err
	}
	return true, nil
}

func (s *durableReplayStore) persist() error {
	payload, err := json.Marshal(s.expires)
	if err != nil {
		return fmt.Errorf("encode replay state: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".replay-state-*")
	if err != nil {
		return fmt.Errorf("create replay state: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect replay state: %w", err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write replay state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync replay state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close replay state: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("commit replay state: %w", err)
	}
	removeTemporary = false
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("open replay state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync replay state directory: %w", err)
	}
	return nil
}

type httpSetNXStore struct {
	client *http.Client
	url    string
}

func (s *httpSetNXStore) SetNX(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("replay client is unavailable")
	}
	seconds := int64(ttl / time.Second)
	if ttl%time.Second != 0 {
		seconds++
	}
	var response replayResponse
	if err := postJSONContext(ctx, s.client, s.url+"/setnx", replayRequest{Key: key, TTLSeconds: seconds}, &response); err != nil {
		return false, err
	}
	return response.Inserted, nil
}
