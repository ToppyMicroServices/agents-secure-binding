// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrStoreUnavailable  = errors.New("least privilege: durable store unavailable")
	ErrExecutionConflict = errors.New("least privilege: execution binding conflict")
	ErrExecutionNotFound = errors.New("least privilege: execution not found")
	ErrOutcomeUnknown    = errors.New("least privilege: effect outcome unknown; reconcile before further action")
)

const (
	durableSchema   = "asb.least-privilege.durable/v1"
	maxDurableBytes = 64 << 20
)

// ExecutionState records admission and the observed effect, not a claim of
// exactly-once execution. RUNNING after interruption has an unknown outcome.
type ExecutionState string

const (
	ExecutionAccepted  ExecutionState = "ACCEPTED"
	ExecutionRunning   ExecutionState = "RUNNING"
	ExecutionUnknown   ExecutionState = "UNKNOWN"
	ExecutionSucceeded ExecutionState = "SUCCEEDED"
	ExecutionFailed    ExecutionState = "FAILED"
)

// ExecutionRecord stores no raw action arguments or external response.
type ExecutionRecord struct {
	OperationID    string         `json:"operation_id"`
	RequestDigest  string         `json:"request_digest"`
	MandateID      string         `json:"mandate_id"`
	MandateDigest  string         `json:"mandate_digest"`
	ExpiresAt      time.Time      `json:"expires_at"`
	State          ExecutionState `json:"state"`
	EvidenceDigest string         `json:"evidence_digest,omitempty"`
}

func (r ExecutionRecord) Terminal() bool {
	return r.State == ExecutionSucceeded || r.State == ExecutionFailed
}

type durableUse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	OperationID string    `json:"operation_id,omitempty"`
}
type durableState struct {
	Schema      string                     `json:"schema"`
	Checksum    string                     `json:"checksum"`
	Capacity    int                        `json:"capacity"`
	PrunedUntil time.Time                  `json:"pruned_until"`
	Uses        map[string]durableUse      `json:"uses"`
	Executions  map[string]ExecutionRecord `json:"executions"`
}

// DurableStore coordinates processes sharing one private directory on a local
// Linux/macOS filesystem. Each transaction takes an OS file lock and fsyncs an
// atomic replacement. NFS, distributed replicas and rollback restores are not
// supported. The directory and lock file must never be removed while in use.
type DurableStore struct {
	directory string
	// Test-only fault hook. No production API permits skipping durability.
	cutpoint func(string) error
}

var _ UseStore = (*DurableStore)(nil)

// CreateDurableStore provisions a new directory. An existing directory is an
// error: use OpenDurableStore to recover, never reset missing/corrupt history.
// An initialization error can leave a published state with an unknown commit
// outcome, so this function never removes the directory on failure.
func CreateDurableStore(directory string, capacity int) (*DurableStore, error) {
	if capacity <= 0 || capacity > 10_000 {
		return nil, ErrCapacity
	}
	if directory == "" {
		return nil, ErrStoreUnavailable
	}
	dir, err := filepath.Abs(directory)
	if err != nil {
		return nil, storeError(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, storeError(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, storeError(err)
	}
	err = lock.Sync()
	closeErr := lock.Close()
	if err != nil {
		return nil, storeError(err)
	}
	if closeErr != nil {
		return nil, storeError(closeErr)
	}
	s := &DurableStore{directory: dir}
	if err := s.persist(durableState{Schema: durableSchema, Capacity: capacity, Uses: make(map[string]durableUse), Executions: make(map[string]ExecutionRecord)}); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(dir)); err != nil {
		return nil, storeError(err)
	}
	return OpenDurableStore(dir)
}

// OpenDurableStore never initializes or repairs state. All subsequent operations
// reload under the OS lock, including when different processes opened the store.
func OpenDurableStore(directory string) (*DurableStore, error) {
	if directory == "" {
		return nil, ErrStoreUnavailable
	}
	dir, err := filepath.Abs(directory)
	if err != nil {
		return nil, storeError(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, storeError(err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrStoreUnavailable
	}
	s := &DurableStore{directory: dir}
	err = s.transaction(context.Background(), func(*durableState) (bool, error) { return false, nil })
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *DurableStore) Use(ctx context.Context, key string, expiresAt, now time.Time) error {
	if !boundedText(key, 512) {
		return ErrInvalidCapability
	}
	return s.transaction(ctx, func(state *durableState) (bool, error) {
		if err := pruneDurable(state, now, expiresAt); err != nil {
			return false, err
		}
		if _, exists := state.Uses[key]; exists {
			return false, ErrReplay
		}
		if len(state.Uses) >= state.Capacity {
			return false, ErrCapacity
		}
		state.Uses[key] = durableUse{ExpiresAt: expiresAt.UTC()}
		return true, nil
	})
}

// DigestExecution binds the stable operation ID to the complete trusted mandate
// and exact request. Reissued capabilities for that mandate share this digest.
func DigestExecution(operationID string, current Mandate, request Request) (string, error) {
	if !boundedText(operationID, 256) {
		return "", ErrBinding
	}
	md, err := DigestMandate(current)
	if err != nil {
		return "", err
	}
	ad, err := DigestAction(request.Action)
	if err != nil {
		return "", err
	}
	if request.ActorID != current.ActorID || request.TaskID != current.TaskID || ad != current.ActionDigest {
		return "", ErrBinding
	}
	return digestValue("asb.least-privilege.execution/v1", struct{ OperationID, MandateDigest, ActorID, TaskID, ActionDigest string }{operationID, md, request.ActorID, request.TaskID, ad})
}

// Prepare atomically consumes the mandate and reserves its exact operation.
// An exact retry returns the existing record; another operation cannot consume
// the same mandate, including after issuer signing-key rotation.
func (s *DurableStore) Prepare(ctx context.Context, operationID string, cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time) (ExecutionRecord, bool, error) {
	if err := CheckCapability(cap, key, current, request, now); err != nil {
		return ExecutionRecord{}, false, err
	}
	digest, err := DigestExecution(operationID, current, request)
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	md, err := DigestMandate(current)
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	var result ExecutionRecord
	created := false
	err = s.transaction(ctx, func(state *durableState) (bool, error) {
		if err := pruneDurable(state, now, current.ExpiresAt); err != nil {
			return false, err
		}
		if existing, ok := state.Executions[operationID]; ok {
			if existing.RequestDigest != digest {
				return false, ErrExecutionConflict
			}
			result = existing
			return false, nil
		}
		useKey := "asb.least-privilege/" + current.ID
		if _, exists := state.Uses[useKey]; exists {
			return false, ErrReplay
		}
		if len(state.Uses) >= state.Capacity || len(state.Executions) >= state.Capacity {
			return false, ErrCapacity
		}
		result = ExecutionRecord{OperationID: operationID, RequestDigest: digest, MandateID: current.ID, MandateDigest: md, ExpiresAt: current.ExpiresAt.UTC(), State: ExecutionAccepted}
		state.Executions[operationID] = result
		state.Uses[useKey] = durableUse{ExpiresAt: current.ExpiresAt.UTC(), OperationID: operationID}
		created = true
		return true, nil
	})
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	return result, created, nil
}

func (s *DurableStore) Lookup(ctx context.Context, operationID, requestDigest string) (ExecutionRecord, error) {
	var result ExecutionRecord
	err := s.transaction(ctx, func(state *durableState) (bool, error) {
		var err error
		result, err = findExecution(state, operationID, requestDigest)
		return false, err
	})
	return result, err
}

// Start grants dispatch ownership once. A false started value MUST NOT dispatch.
// The caller must revalidate current authenticated policy immediately before
// this call. Start never resumes RUNNING or UNKNOWN operations after restart.
func (s *DurableStore) Start(ctx context.Context, operationID, requestDigest string) (ExecutionRecord, bool, error) {
	var result ExecutionRecord
	started := false
	err := s.transaction(ctx, func(state *durableState) (bool, error) {
		r, err := findExecution(state, operationID, requestDigest)
		if err != nil {
			return false, err
		}
		result = r
		if r.State != ExecutionAccepted {
			return false, nil
		}
		result.State = ExecutionRunning
		state.Executions[operationID] = result
		started = true
		return true, nil
	})
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	return result, started, nil
}

// CancelAccepted abandons an operation that has provably never been dispatched.
// It competes atomically with Start and cannot cancel RUNNING/UNKNOWN effects.
// The enclosing service must authorize this administrative action; it can use
// it to record a no-effect outcome without guessing effect state. Cancellation
// retains the operation and mandate identities and does not free their capacity.
func (s *DurableStore) CancelAccepted(ctx context.Context, operationID, requestDigest string) (ExecutionRecord, error) {
	var result ExecutionRecord
	err := s.transaction(ctx, func(state *durableState) (bool, error) {
		r, err := findExecution(state, operationID, requestDigest)
		if err != nil {
			return false, err
		}
		evidence, err := digestValue("asb.least-privilege.canceled-before-dispatch/v1", struct{ OperationID, RequestDigest string }{operationID, requestDigest})
		if err != nil {
			return false, err
		}
		if r.State == ExecutionFailed && r.EvidenceDigest == evidence {
			result = r
			return false, nil
		}
		if r.State != ExecutionAccepted {
			return false, ErrExecutionConflict
		}
		r.State, r.EvidenceDigest = ExecutionFailed, evidence
		state.Executions[operationID] = r
		result = r
		return true, nil
	})
	if err != nil {
		return ExecutionRecord{}, err
	}
	return result, nil
}

// Complete also supports reconciliation from RUNNING/UNKNOWN. The trusted
// adapter must independently query the exact external operation before passing
// a terminal result and evidence digest. It must never infer failure from a
// timeout or from missing eventually-consistent data. This is a storage API,
// not an authorization API, and must not be exposed directly to a model.
func (s *DurableStore) Complete(ctx context.Context, operationID, requestDigest string, outcome ExecutionState, evidenceDigest string) (ExecutionRecord, error) {
	if outcome != ExecutionUnknown && outcome != ExecutionSucceeded && outcome != ExecutionFailed {
		return ExecutionRecord{}, ErrExecutionConflict
	}
	if (outcome != ExecutionUnknown && !canonicalDigest(evidenceDigest)) || (evidenceDigest != "" && !canonicalDigest(evidenceDigest)) {
		return ExecutionRecord{}, ErrBinding
	}
	var result ExecutionRecord
	err := s.transaction(ctx, func(state *durableState) (bool, error) {
		r, err := findExecution(state, operationID, requestDigest)
		if err != nil {
			return false, err
		}
		if r.State == ExecutionAccepted {
			return false, ErrExecutionConflict
		}
		if r.Terminal() {
			if r.State != outcome || r.EvidenceDigest != evidenceDigest {
				return false, ErrExecutionConflict
			}
			result = r
			return false, nil
		}
		r.State = outcome
		r.EvidenceDigest = evidenceDigest
		state.Executions[operationID] = r
		result = r
		return true, nil
	})
	if err != nil {
		return ExecutionRecord{}, err
	}
	return result, nil
}

func findExecution(state *durableState, id, digest string) (ExecutionRecord, error) {
	if !boundedText(id, 256) || !canonicalDigest(digest) {
		return ExecutionRecord{}, ErrBinding
	}
	r, ok := state.Executions[id]
	if !ok {
		return ExecutionRecord{}, ErrExecutionNotFound
	}
	if r.RequestDigest != digest {
		return ExecutionRecord{}, ErrExecutionConflict
	}
	return r, nil
}

func pruneDurable(s *durableState, now, expiry time.Time) error {
	if now.IsZero() || now.Before(s.PrunedUntil) || !expiry.After(now) {
		return ErrExpired
	}
	for key, use := range s.Uses {
		if now.Before(use.ExpiresAt) {
			continue
		}
		if use.OperationID != "" {
			// Expiry ends execution authority, not operation/mandate identity.
			// Retain terminal records too, or a fresh grant could reuse an old
			// operation ID for another request after pruning and restart.
			continue
		}
		if use.ExpiresAt.After(s.PrunedUntil) {
			s.PrunedUntil = use.ExpiresAt
		}
		delete(s.Uses, key)
	}
	return nil
}

func (s *DurableStore) transaction(ctx context.Context, change func(*durableState) (bool, error)) error {
	if s == nil || s.directory == "" || ctx == nil {
		return ErrStoreUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := acquireDurableLock(ctx, filepath.Join(s.directory, "lock"))
	if err != nil {
		return storeError(err)
	}
	defer releaseDurableLock(f)
	state, err := s.load()
	if err != nil {
		return err
	}
	changed, err := change(&state)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDurable(state); err != nil {
		return err
	}
	return s.persist(state)
}

func (s *DurableStore) load() (durableState, error) {
	var state durableState
	path := filepath.Join(s.directory, "state.json")
	info, err := os.Lstat(path)
	if err != nil {
		return state, storeError(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maxDurableBytes {
		return state, ErrStoreUnavailable
	}
	f, err := os.Open(path)
	if err != nil {
		return state, storeError(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, maxDurableBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, storeError(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return state, ErrStoreUnavailable
	}
	checksum, err := durableChecksum(state)
	if err != nil || !canonicalDigest(state.Checksum) || checksum != state.Checksum {
		return state, ErrStoreUnavailable
	}
	return state, validateDurable(state)
}

// The checksum detects accidental corruption and missing history fields. It is
// not a MAC and cannot detect an operator restoring an older valid snapshot.
func durableChecksum(state durableState) (string, error) {
	state.Checksum = ""
	return digestValue("asb.least-privilege.durable-checksum/v1", state)
}

func validateDurable(s durableState) error {
	if s.Schema != durableSchema || s.Capacity <= 0 || s.Capacity > 10_000 || s.Uses == nil || s.Executions == nil || len(s.Uses) > s.Capacity || len(s.Executions) > s.Capacity {
		return ErrStoreUnavailable
	}
	for key, u := range s.Uses {
		if !boundedText(key, 512) || u.ExpiresAt.IsZero() {
			return ErrStoreUnavailable
		}
		if u.OperationID != "" {
			r, ok := s.Executions[u.OperationID]
			if !ok || key != "asb.least-privilege/"+r.MandateID || !u.ExpiresAt.Equal(r.ExpiresAt) {
				return ErrStoreUnavailable
			}
		}
	}
	for id, r := range s.Executions {
		if id != r.OperationID || !boundedText(id, 256) || !boundedText(r.MandateID, 256) || !canonicalDigest(r.RequestDigest) || !canonicalDigest(r.MandateDigest) || r.ExpiresAt.IsZero() {
			return ErrStoreUnavailable
		}
		u, ok := s.Uses["asb.least-privilege/"+r.MandateID]
		if !ok || u.OperationID != id {
			return ErrStoreUnavailable
		}
		switch r.State {
		case ExecutionAccepted, ExecutionRunning:
			if r.EvidenceDigest != "" {
				return ErrStoreUnavailable
			}
		case ExecutionUnknown:
			if r.EvidenceDigest != "" && !canonicalDigest(r.EvidenceDigest) {
				return ErrStoreUnavailable
			}
		case ExecutionSucceeded, ExecutionFailed:
			if !canonicalDigest(r.EvidenceDigest) {
				return ErrStoreUnavailable
			}
		default:
			return ErrStoreUnavailable
		}
	}
	return nil
}

func (s *DurableStore) persist(state durableState) error {
	checksum, err := durableChecksum(state)
	if err != nil {
		return storeError(err)
	}
	state.Checksum = checksum
	data, err := json.Marshal(state)
	if err != nil {
		return storeError(err)
	}
	if len(data) > maxDurableBytes {
		return ErrCapacity
	}
	f, err := os.CreateTemp(s.directory, ".state-*")
	if err != nil {
		return storeError(err)
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return storeError(err)
	}
	if err = s.inject("after-write"); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return storeError(err)
	}
	if err = f.Close(); err != nil {
		return storeError(err)
	}
	if err = s.inject("before-rename"); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(s.directory, "state.json")); err != nil {
		return storeError(err)
	}
	if err = s.inject("after-rename"); err != nil {
		return err
	}
	if err = syncDirectory(s.directory); err != nil {
		return storeError(err)
	}
	return s.inject("after-directory-sync")
}

func (s *DurableStore) inject(at string) error {
	if s.cutpoint != nil {
		return storeError(s.cutpoint(at))
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func storeError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
}
