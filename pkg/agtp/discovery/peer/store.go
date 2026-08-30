// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

const stateVersion = 1

var (
	ErrCorruptState     = errors.New("agtp discovery peer: corrupt persistent state")
	ErrUnsupportedState = errors.New("agtp discovery peer: unsupported persistent state version")
)

type diskEnvelope struct {
	Version int             `json:"version"`
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}

// PersistentState is the durable state owned by one discovery node.
type PersistentState struct {
	Version  int                     `json:"version"`
	SavedAt  time.Time               `json:"saved_at"`
	Presence discovery.Delta         `json:"presence"`
	Names    []discovery.NameBinding `json:"names"`
	Peers    []discovery.NodeInfo    `json:"peers"`
}

// StateStore persists a checksummed JSON snapshot with atomic replacement.
type StateStore struct {
	mu   sync.Mutex
	path string
}

// NewStateStore creates a snapshot store at path.
func NewStateStore(path string) (*StateStore, error) {
	if path == "" {
		return nil, errors.New("agtp discovery peer: missing state path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return &StateStore{path: path}, nil
}

// Load returns false when no snapshot exists yet.
func (s *StateStore) Load() (PersistentState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var state PersistentState
	found, err := readChecksummedJSON(s.path, &state)
	if err != nil || !found {
		return PersistentState{}, found, err
	}
	if state.Version != stateVersion {
		return PersistentState{}, true, ErrUnsupportedState
	}
	return state, true, nil
}

// Save atomically replaces the durable snapshot.
func (s *StateStore) Save(state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state.Version = stateVersion
	state.SavedAt = time.Now().UTC()
	return writeChecksummedJSON(s.path, state)
}

func writeChecksummedJSON(path string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	envelope := diskEnvelope{
		Version: stateVersion,
		Payload: payload,
		SHA256:  hex.EncodeToString(digest[:]),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".agtp-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return err
	}
	committed = true
	return nil
}

func readChecksummedJSON(path string, target any) (bool, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var envelope diskEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return true, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	if envelope.Version != stateVersion {
		return true, ErrUnsupportedState
	}
	digest := sha256.Sum256(envelope.Payload)
	if hex.EncodeToString(digest[:]) != envelope.SHA256 {
		return true, ErrCorruptState
	}
	if err := json.Unmarshal(envelope.Payload, target); err != nil {
		return true, fmt.Errorf("%w: %v", ErrCorruptState, err)
	}
	return true, nil
}
