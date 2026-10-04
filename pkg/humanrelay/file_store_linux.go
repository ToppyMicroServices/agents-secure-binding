//go:build linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"golang.org/x/sys/unix"
)

const relayLockMarker = "asb.human-relay-lock/v1\n"

const (
	relayFileSchema       = "asb.human-relay-store/v1"
	maxRelayStateBytes    = 16 << 20
	maxRelayRecords       = 10_000
	relayOperationTimeout = 30 * time.Second
)

type relayDiskRecord struct {
	Intent  Intent  `json:"intent"`
	Receipt Receipt `json:"receipt"`
	Events  []Event `json:"events"`
}

type relayDiskState struct {
	Schema  string                     `json:"schema"`
	Records map[string]relayDiskRecord `json:"records"`
}

// FileStore persists relay intents and the one-attempt dispatch marker on one
// Linux host. A permanent lock file serializes independent processes; atomic
// replacement and file/directory fsync precede provider callbacks. It does NOT
// persist reachability authority. The supplied directory must itself preserve
// grants/revocations and serialize its callbacks against all authorization
// changes across processes. MemoryReachabilityDirectory is only a test fixture.
//
// The private directory must be on a local filesystem, with trusted ownership.
// Operators must never remove/replace the lock file or restore old state while
// writers are active. A backup rollback requires fencing and provider recovery.
type FileStore struct {
	path      string
	directory GrantTransaction
	blocked   atomic.Bool
	// Fault cut points are test-only and are never called concurrently by a handle.
	beforePersist func(relayDiskState) error
	afterRename   func() error
}

var (
	_ Store               = (*FileStore)(nil)
	_ ReconciliationStore = (*FileStore)(nil)
)

func OpenFileStore(path string, directory GrantTransaction) (*FileStore, error) {
	if isNilDependency(directory) {
		return nil, ErrMissingDirectory
	}
	if strings.TrimSpace(path) == "" {
		return nil, ErrStoreUnavailable
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, ErrStoreUnavailable
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: state directory must be private (0700)", ErrStoreUnavailable)
	}
	s := &FileStore{path: filepath.Join(parent, filepath.Base(abs)), directory: directory}
	ctx, cancel := context.WithTimeout(context.Background(), relayOperationTimeout)
	defer cancel()
	err = s.withStore(ctx, func(*MemoryStore) error { return nil })
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) CommitAuthorizedIntent(ctx context.Context, commit QueueCommit) (receipt Receipt, err error) {
	if ctx == nil {
		return receipt, ErrStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayOperationTimeout)
	defer cancel()
	err = s.withStore(ctx, func(memory *MemoryStore) error {
		var err error
		receipt, err = memory.CommitAuthorizedIntent(ctx, commit)
		return err
	})
	return receipt, err
}

func (s *FileStore) LoadIntent(ctx context.Context, id string) (intent Intent, receipt Receipt, err error) {
	err = s.withStore(ctx, func(memory *MemoryStore) error {
		var err error
		intent, receipt, err = memory.LoadIntent(ctx, id)
		return err
	})
	return intent, receipt, err
}

func (s *FileStore) CommitAuthorizedDispatch(ctx context.Context, id string, dispatcher SessionDispatcher, now func() time.Time) (receipt Receipt, err error) {
	if ctx == nil {
		return receipt, ErrStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayOperationTimeout)
	defer cancel()
	err = s.withStore(ctx, func(memory *MemoryStore) error {
		var err error
		receipt, err = memory.CommitAuthorizedDispatch(ctx, id, dispatcher, now)
		return err
	})
	return receipt, err
}

func (s *FileStore) ReconcileDispatch(ctx context.Context, id string, provider ProviderReconciler, now func() time.Time) (receipt Receipt, err error) {
	if ctx == nil {
		return receipt, ErrStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayOperationTimeout)
	defer cancel()
	err = s.withStore(ctx, func(memory *MemoryStore) error {
		var err error
		receipt, err = memory.ReconcileDispatch(ctx, id, provider, now)
		return err
	})
	return receipt, err
}

// Pending returns a bounded deterministic batch for a trusted worker. QUEUED
// entries may be dispatched after fresh authorization; DISPATCHING entries may
// only be reconciled. It creates no lease and contains no provider/contact data.
// Racing workers are fenced by the durable marker inside Dispatch itself.
func (s *FileStore) Pending(ctx context.Context, after string, limit int) (receipts []Receipt, err error) {
	if limit < 1 || limit > 256 {
		return nil, ErrStoreLimit
	}
	err = s.withStore(ctx, func(memory *MemoryStore) error {
		ids := make([]string, 0, len(memory.records))
		for id, record := range memory.records {
			if id > after && (record.receipt.Status == StatusQueued || record.receipt.Status == StatusDispatching) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		if len(ids) > limit {
			ids = ids[:limit]
		}
		for _, id := range ids {
			receipts = append(receipts, memory.records[id].receipt)
		}
		return nil
	})
	return receipts, err
}

func (s *FileStore) withStore(ctx context.Context, fn func(*MemoryStore) error) error {
	if ctx == nil || s.blocked.Load() {
		return ErrStoreUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, relayOperationTimeout)
	defer cancel()
	lock, err := openRelayPrivate(s.path+".lock", unix.O_RDWR|unix.O_CREAT)
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = lock.Close() }()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return ErrStoreUnavailable
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	if s.blocked.Load() {
		return ErrStoreUnavailable
	}
	marker, err := io.ReadAll(io.LimitReader(lock, int64(len(relayLockMarker)+1)))
	if err != nil || (len(marker) != 0 && string(marker) != relayLockMarker) {
		return ErrStoreUnavailable
	}
	memory, err := s.load(len(marker) == 0)
	if err != nil {
		return err
	}
	if len(marker) == 0 {
		// Initialize state before marking the permanent lock. Once marked, a
		// missing state file is data loss, not permission to start from empty.
		if err := s.persist(memory.records); err != nil {
			return err
		}
		if _, err := lock.WriteAt([]byte(relayLockMarker), 0); err != nil {
			s.blocked.Store(true)
			return ErrStoreUnavailable
		}
		if err := lock.Sync(); err != nil {
			s.blocked.Store(true)
			return ErrStoreUnavailable
		}
	}
	memory.checkpoint = func(records map[string]memoryRecord) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return s.persist(records)
	}
	return fn(memory)
}

func openRelayPrivate(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		_ = f.Close()
		return nil, ErrStoreUnavailable
	}
	return f, nil
}

func (s *FileStore) load(allowMissing bool) (*MemoryStore, error) {
	memory, err := NewMemoryStore(s.directory)
	if err != nil {
		return nil, err
	}
	f, err := openRelayPrivate(s.path, unix.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return memory, nil
	}
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	defer func() { _ = f.Close() }()
	raw, err := strictjson.ReadDocument(f, maxRelayStateBytes)
	if err != nil {
		return nil, ErrStoreUnavailable
	}
	var state relayDiskState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, ErrStoreUnavailable
	}
	if err := validateRelayState(state); err != nil {
		return nil, err
	}
	for id, record := range state.Records {
		memory.records[id] = memoryRecord{intent: record.Intent, receipt: record.Receipt, events: record.Events}
		memory.grantUse[record.Intent.GrantID] = id
	}
	return memory, nil
}

func (s *FileStore) persist(records map[string]memoryRecord) error {
	state := relayDiskState{Schema: relayFileSchema, Records: make(map[string]relayDiskRecord, len(records))}
	for id, record := range records {
		state.Records[id] = relayDiskRecord{record.intent, record.receipt, record.events}
	}
	if err := validateRelayState(state); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return ErrStoreUnavailable
	}
	if len(raw) > maxRelayStateBytes {
		return ErrStoreLimit
	}
	if s.beforePersist != nil {
		if err := s.beforePersist(state); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".relay-*.tmp")
	if err != nil {
		return ErrStoreUnavailable
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if n, err := f.Write(raw); err != nil || n != len(raw) {
		return ErrStoreUnavailable
	}
	if err := f.Sync(); err != nil {
		return ErrStoreUnavailable
	}
	if err := f.Close(); err != nil {
		return ErrStoreUnavailable
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return ErrStoreUnavailable
	}
	// Any post-rename failure has an ambiguous durability outcome. Fence this
	// handle until a new Open validates state; never send a callback on error.
	s.blocked.Store(true)
	if s.afterRename != nil {
		if err := s.afterRename(); err != nil {
			return err
		}
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return ErrStoreUnavailable
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return ErrStoreUnavailable
	}
	s.blocked.Store(false)
	return nil
}

func validateRelayState(state relayDiskState) error {
	if state.Schema != relayFileSchema || state.Records == nil {
		return ErrStoreUnavailable
	}
	if len(state.Records) > maxRelayRecords {
		return ErrStoreLimit
	}
	grants := make(map[string]bool, len(state.Records))
	for id, record := range state.Records {
		intent, receipt, events := record.Intent, record.Receipt, record.Events
		if id != intent.IntentID || intent.Validate() != nil || receipt.Validate() != nil || len(events) < 1 || len(events) > 3 || grants[intent.GrantID] {
			return ErrStoreUnavailable
		}
		grants[intent.GrantID] = true
		digest, err := RequestDigest(RelayIntentRequest{
			IntentID: intent.IntentID, GrantID: intent.GrantID,
			RequesterParticipantID: intent.RequesterParticipantID, Purpose: intent.Purpose, Capability: intent.Capability,
			Channel: intent.Channel, ContentRef: intent.ContentRef, ContentDigest: intent.ContentDigest,
		})
		if err != nil || digest.String() != intent.RequestDigest {
			return ErrStoreUnavailable
		}
		previous := Status("")
		at := intent.QueuedAt
		for index, event := range events {
			if event.Validate() != nil || event.IntentID != id || event.At.Before(at) {
				return ErrStoreUnavailable
			}
			if index == 0 {
				if event.Status != StatusQueued || !event.At.Equal(intent.QueuedAt) {
					return ErrStoreUnavailable
				}
			} else if (previous == StatusQueued && event.Status != StatusDispatching && event.Status != StatusCanceled) ||
				(previous == StatusDispatching && event.Status != StatusProviderAcknowledged) ||
				(previous != StatusQueued && previous != StatusDispatching) {
				return ErrStoreUnavailable
			}
			previous, at = event.Status, event.At
		}
		if receipt.IntentID != id || receipt.GrantID != intent.GrantID || receipt.ContentDigest != intent.ContentDigest ||
			receipt.Status != previous || !receipt.QueuedAt.Equal(intent.QueuedAt) || !receipt.UpdatedAt.Equal(at) {
			return ErrStoreUnavailable
		}
	}
	return nil
}
