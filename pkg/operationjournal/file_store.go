// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package operationjournal

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	legacyFileSchema       = "urn:asb:operation-journal:v1"
	fileSchema             = "urn:asb:operation-journal:v2"
	maxJournalBytes        = 16 << 20
	maxJournalRecords      = 10_000
	maxReplayRecords       = 100_000
	maxOperationIDBytes    = 256
	maxReplayKeyBytes      = 256
	maxResultMediaType     = 128
	maxResultPlaintext     = 256 << 10
	aesGCMNonceBytes       = 12
	aesGCMTagBytes         = 16
	SealedResultEnvelopeV1 = "urn:asb:sealed-result:aes-256-gcm:v1"
)

type persistedState struct {
	Schema  string                  `json:"schema"`
	Records map[string]Record       `json:"records"`
	Replay  map[string]time.Time    `json:"replay"`
	Results map[string]SealedResult `json:"sealed_results"`
}

// FileStore is a restart-safe, single-process Store implementation. Separate
// FileStore values for the same canonical path share an in-process lock. A
// shared database adapter is required for coordination between processes.
type FileStore struct {
	path         string
	lock         *pathLock
	now          func() time.Time
	beforeCommit func() error
}

type pathLock struct {
	token chan struct{}
}

var pathLocks sync.Map

var _ Store = (*FileStore)(nil)
var _ AcceptanceStore = (*FileStore)(nil)
var _ ResultStore = (*FileStore)(nil)

// OpenFileStore opens or prepares a versioned journal at path. The parent
// directory is created with owner-only permissions when absent. Existing
// malformed, oversized, symlinked, or non-regular state fails closed.
func OpenFileStore(path string) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: missing journal path", ErrInvalidRecord)
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve journal path: %v", ErrUnavailable, err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return nil, fmt.Errorf("%w: create journal directory: %v", ErrUnavailable, err)
	}
	lock := lockForPath(absPath)
	store := &FileStore{path: absPath, lock: lock, now: time.Now}
	if err := lock.acquire(context.Background()); err != nil {
		return nil, err
	}
	defer lock.release()
	if _, err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// Reserve creates an ACCEPTED record, or returns the current record for an
// exact retry. An existing ID with a different request digest is a conflict.
func (s *FileStore) Reserve(ctx context.Context, request Reservation) (Record, bool, error) {
	if err := validateReservation(request); err != nil {
		return Record{}, false, err
	}
	var created bool
	record, err := s.mutate(ctx, func(state *persistedState) (Record, bool, error) {
		if existing, ok := state.Records[request.OperationID]; ok {
			if existing.RequestDigest != request.RequestDigest {
				return Record{}, false, ErrConflict
			}
			return existing, false, nil
		}
		if len(state.Records) >= maxJournalRecords {
			return Record{}, false, fmt.Errorf("%w: record limit reached", ErrUnavailable)
		}
		now := s.currentTime(time.Time{})
		record := Record{
			OperationID: request.OperationID, RequestDigest: request.RequestDigest,
			State: StateAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
		state.Records[request.OperationID] = record
		created = true
		return record, true, nil
	})
	if err != nil {
		return Record{}, false, err
	}
	return record, created, nil
}

// ReserveAcceptance commits the replay reservation and operation record in a
// single file replacement. A failure before rename leaves neither value. An
// error reported while syncing the directory after rename has an unknown
// commit outcome; callers recover by looking up the exact operation and must
// not execute it blindly.
func (s *FileStore) ReserveAcceptance(ctx context.Context, request AcceptanceReservation) (Record, bool, error) {
	if err := validateAcceptanceReservation(request); err != nil {
		return Record{}, false, err
	}
	if err := s.acquire(ctx); err != nil {
		return Record{}, false, err
	}
	defer s.lock.release()
	state, err := s.load()
	if err != nil {
		return Record{}, false, err
	}
	now := s.currentTime(time.Time{})
	if !now.Before(request.ReplayRetainUntil) {
		return Record{}, false, fmt.Errorf("%w: replay retention is expired", ErrInvalidRecord)
	}
	for key, retainUntil := range state.Replay {
		if !now.Before(retainUntil) {
			delete(state.Replay, key)
		}
	}
	if retainUntil, exists := state.Replay[request.ReplayKey]; exists && now.Before(retainUntil) {
		return Record{}, false, ErrReplay
	}

	record, exists := state.Records[request.Operation.OperationID]
	created := false
	if exists {
		if record.RequestDigest != request.Operation.RequestDigest {
			return Record{}, false, ErrConflict
		}
	} else {
		if len(state.Records) >= maxJournalRecords {
			return Record{}, false, fmt.Errorf("%w: record limit reached", ErrUnavailable)
		}
		record = Record{
			OperationID: request.Operation.OperationID, RequestDigest: request.Operation.RequestDigest,
			State: StateAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
		state.Records[request.Operation.OperationID] = record
		created = true
	}
	if len(state.Replay) >= maxReplayRecords {
		return Record{}, false, fmt.Errorf("%w: replay record limit reached", ErrUnavailable)
	}
	state.Replay[request.ReplayKey] = request.ReplayRetainUntil.UTC()
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Record{}, false, err
		}
	}
	if err := validatePersistedState(state); err != nil {
		return Record{}, false, err
	}
	if err := s.persist(state); err != nil {
		return Record{}, false, err
	}
	return record, created, nil
}

// Lookup returns the current record only when both the operation ID and request
// digest match the reservation.
func (s *FileStore) Lookup(ctx context.Context, operationID, requestDigest string) (Record, error) {
	if err := validateReservation(Reservation{OperationID: operationID, RequestDigest: requestDigest}); err != nil {
		return Record{}, err
	}
	if err := s.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer s.lock.release()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	return lookupExact(state, operationID, requestDigest)
}

// MarkRunning moves an ACCEPTED record to RUNNING. The started result is true
// only for that transition. An exact retry returns the current RUNNING record
// with started=false, so a caller does not invoke an executor twice.
func (s *FileStore) MarkRunning(ctx context.Context, operationID, requestDigest string) (Record, bool, error) {
	if err := validateReservation(Reservation{OperationID: operationID, RequestDigest: requestDigest}); err != nil {
		return Record{}, false, err
	}
	started := false
	record, err := s.update(ctx, operationID, requestDigest, func(record Record) (Record, bool, error) {
		switch record.State {
		case StateRunning:
			return record, false, nil
		case StateAccepted:
			now := s.currentTime(record.UpdatedAt)
			record.State = StateRunning
			record.StartedAt = now
			record.UpdatedAt = now
			record.Revision++
			started = true
			return record, true, nil
		default:
			return Record{}, false, ErrInvalidTransition
		}
	})
	if err != nil {
		return Record{}, false, err
	}
	return record, started, nil
}

// MarkIndeterminate records that a RUNNING operation may have had an external
// effect whose terminal result is not known. Repeating the exact call is
// idempotent.
func (s *FileStore) MarkIndeterminate(ctx context.Context, operationID, requestDigest string) (Record, error) {
	if err := validateReservation(Reservation{OperationID: operationID, RequestDigest: requestDigest}); err != nil {
		return Record{}, err
	}
	return s.update(ctx, operationID, requestDigest, func(record Record) (Record, bool, error) {
		switch record.State {
		case StateIndeterminate:
			return record, false, nil
		case StateRunning:
			now := s.currentTime(record.UpdatedAt)
			record.State = StateIndeterminate
			record.UpdatedAt = now
			record.Revision++
			return record, true, nil
		default:
			return Record{}, false, ErrInvalidTransition
		}
	})
}

// Finalize records a terminal decision. RUNNING and INDETERMINATE operations
// may reach any terminal state. An ACCEPTED operation may only be canceled.
// Repeating an identical terminal decision is idempotent; a different terminal
// state or outcome digest is a conflict.
func (s *FileStore) Finalize(ctx context.Context, final Finalization) (Record, error) {
	if err := validateFinalization(final); err != nil {
		return Record{}, err
	}
	return s.update(ctx, final.OperationID, final.RequestDigest, func(record Record) (Record, bool, error) {
		return s.finalizeRecord(record, final)
	})
}

// FinalizeWithResult atomically stores a payload-free SUCCEEDED record and an
// opaque sealed result in one state-file replacement. A caller receiving an
// error must not release a result: an error after rename can mean the commit
// succeeded, so the exact tuple must be recovered through LookupResult.
func (s *FileStore) FinalizeWithResult(ctx context.Context, final Finalization, result SealedResult) (Record, error) {
	if err := validateFinalization(final); err != nil {
		return Record{}, err
	}
	if final.State != StateSucceeded || final.OutcomeDigest == "" {
		return Record{}, fmt.Errorf("%w: a recoverable result requires SUCCEEDED with an outcome digest", ErrInvalidRecord)
	}
	if err := ValidateSealedResult(result); err != nil {
		return Record{}, err
	}
	if result.OperationID != final.OperationID || result.RequestDigest != final.RequestDigest || result.OutcomeDigest != final.OutcomeDigest {
		return Record{}, ErrConflict
	}
	if err := s.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer s.lock.release()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	record, err := lookupExact(state, final.OperationID, final.RequestDigest)
	if err != nil {
		return Record{}, err
	}
	existing, hasResult := state.Results[final.OperationID]
	if record.State.Terminal() {
		if record.State == final.State && record.OutcomeDigest == final.OutcomeDigest && hasResult && sealedResultsEqual(existing, result) {
			return record, nil
		}
		return Record{}, ErrConflict
	}
	if hasResult {
		return Record{}, fmt.Errorf("%w: sealed result exists for a non-terminal operation", ErrUnavailable)
	}
	updated, changed, err := s.finalizeRecord(record, final)
	if err != nil {
		return Record{}, err
	}
	if !changed {
		return Record{}, ErrConflict
	}
	state.Records[final.OperationID] = updated
	state.Results[final.OperationID] = cloneSealedResult(result)
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Record{}, err
		}
	}
	if err := validatePersistedState(state); err != nil {
		return Record{}, err
	}
	if err := s.persist(state); err != nil {
		return Record{}, err
	}
	return updated, nil
}

// LookupResult returns a SUCCEEDED record and its opaque result only for the
// exact operation ID and request digest. The returned byte slices are copies.
func (s *FileStore) LookupResult(ctx context.Context, operationID, requestDigest string) (Record, SealedResult, error) {
	if err := validateReservation(Reservation{OperationID: operationID, RequestDigest: requestDigest}); err != nil {
		return Record{}, SealedResult{}, err
	}
	if err := s.acquire(ctx); err != nil {
		return Record{}, SealedResult{}, err
	}
	defer s.lock.release()
	state, err := s.load()
	if err != nil {
		return Record{}, SealedResult{}, err
	}
	record, err := lookupExact(state, operationID, requestDigest)
	if err != nil {
		return Record{}, SealedResult{}, err
	}
	if record.State != StateSucceeded || record.OutcomeDigest == "" {
		return Record{}, SealedResult{}, ErrInvalidTransition
	}
	result, ok := state.Results[operationID]
	if !ok {
		return Record{}, SealedResult{}, ErrNotFound
	}
	if result.RequestDigest != requestDigest || result.OutcomeDigest != record.OutcomeDigest {
		return Record{}, SealedResult{}, fmt.Errorf("%w: sealed result does not match its terminal record", ErrUnavailable)
	}
	return record, cloneSealedResult(result), nil
}

func (s *FileStore) finalizeRecord(record Record, final Finalization) (Record, bool, error) {
	if record.State.Terminal() {
		if record.State == final.State && record.OutcomeDigest == final.OutcomeDigest {
			return record, false, nil
		}
		return Record{}, false, ErrConflict
	}
	if record.State == StateAccepted && final.State != StateCanceled {
		return Record{}, false, ErrInvalidTransition
	}
	if record.State != StateAccepted && record.State != StateRunning && record.State != StateIndeterminate {
		return Record{}, false, ErrInvalidTransition
	}
	now := s.currentTime(record.UpdatedAt)
	record.State = final.State
	record.OutcomeDigest = final.OutcomeDigest
	record.CompletedAt = now
	record.UpdatedAt = now
	record.Revision++
	return record, true, nil
}

func (s *FileStore) update(ctx context.Context, operationID, requestDigest string, change func(Record) (Record, bool, error)) (Record, error) {
	return s.mutate(ctx, func(state *persistedState) (Record, bool, error) {
		record, err := lookupExact(*state, operationID, requestDigest)
		if err != nil {
			return Record{}, false, err
		}
		updated, changed, err := change(record)
		if err != nil {
			return Record{}, false, err
		}
		if changed {
			state.Records[operationID] = updated
		}
		return updated, changed, nil
	})
}

func (s *FileStore) mutate(ctx context.Context, change func(*persistedState) (Record, bool, error)) (Record, error) {
	if err := s.acquire(ctx); err != nil {
		return Record{}, err
	}
	defer s.lock.release()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	record, changed, err := change(&state)
	if err != nil {
		return Record{}, err
	}
	if !changed {
		return record, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Record{}, err
		}
	}
	if err := validatePersistedState(state); err != nil {
		return Record{}, err
	}
	if err := s.persist(state); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *FileStore) acquire(ctx context.Context) error {
	if s == nil || s.lock == nil || s.path == "" {
		return ErrUnavailable
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidRecord)
	}
	return s.lock.acquire(ctx)
}

func (l *pathLock) acquire(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.token:
		return nil
	}
}

func (l *pathLock) release() {
	l.token <- struct{}{}
}

func lockForPath(path string) *pathLock {
	candidate := &pathLock{token: make(chan struct{}, 1)}
	candidate.token <- struct{}{}
	actual, _ := pathLocks.LoadOrStore(path, candidate)
	return actual.(*pathLock)
}

func (s *FileStore) currentTime(notBefore time.Time) time.Time {
	now := time.Now().UTC()
	if s != nil && s.now != nil {
		now = s.now().UTC()
	}
	if now.IsZero() {
		now = time.Unix(0, 0).UTC()
	}
	if now.Before(notBefore) {
		return notBefore
	}
	return now
}

func (s *FileStore) load() (persistedState, error) {
	state := persistedState{
		Schema: fileSchema, Records: make(map[string]Record), Replay: make(map[string]time.Time), Results: make(map[string]SealedResult),
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return persistedState{}, fmt.Errorf("%w: inspect state: %v", ErrUnavailable, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return persistedState{}, fmt.Errorf("%w: state path is not a regular file", ErrUnavailable)
	}
	if info.Size() <= 0 || info.Size() > maxJournalBytes {
		return persistedState{}, fmt.Errorf("%w: state size is invalid", ErrUnavailable)
	}
	file, err := os.Open(s.path)
	if err != nil {
		return persistedState{}, fmt.Errorf("%w: open state: %v", ErrUnavailable, err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maxJournalBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return persistedState{}, fmt.Errorf("%w: decode state: %v", ErrUnavailable, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return persistedState{}, fmt.Errorf("%w: trailing state data", ErrUnavailable)
	}
	if state.Schema == legacyFileSchema {
		if len(state.Results) != 0 {
			return persistedState{}, fmt.Errorf("%w: legacy state contains sealed results", ErrUnavailable)
		}
		state.Schema = fileSchema
		if state.Results == nil {
			state.Results = make(map[string]SealedResult)
		}
	}
	if err := validatePersistedState(state); err != nil {
		return persistedState{}, err
	}
	return state, nil
}

func (s *FileStore) persist(state persistedState) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("%w: encode state: %v", ErrUnavailable, err)
	}
	if len(payload) > maxJournalBytes {
		return fmt.Errorf("%w: encoded state exceeds size limit", ErrUnavailable)
	}
	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".operation-journal-*")
	if err != nil {
		return fmt.Errorf("%w: create temporary state: %v", ErrUnavailable, err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: protect temporary state: %v", ErrUnavailable, err)
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write temporary state: %v", ErrUnavailable, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync temporary state: %v", ErrUnavailable, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close temporary state: %v", ErrUnavailable, err)
	}
	if s.beforeCommit != nil {
		if err := s.beforeCommit(); err != nil {
			return fmt.Errorf("%w: before state commit: %v", ErrUnavailable, err)
		}
	}
	if err := os.Rename(temporaryPath, s.path); err != nil {
		return fmt.Errorf("%w: replace state: %v", ErrUnavailable, err)
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("%w: open state directory: %v", ErrUnavailable, err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("%w: sync state directory: %v", ErrUnavailable, err)
	}
	return nil
}

func lookupExact(state persistedState, operationID, requestDigest string) (Record, error) {
	record, ok := state.Records[operationID]
	if !ok {
		return Record{}, ErrNotFound
	}
	if record.RequestDigest != requestDigest {
		return Record{}, ErrConflict
	}
	return record, nil
}

func validateReservation(request Reservation) error {
	if err := validateOperationID(request.OperationID); err != nil {
		return err
	}
	if err := validateDigest(request.RequestDigest, false); err != nil {
		return err
	}
	return nil
}

func validateAcceptanceReservation(request AcceptanceReservation) error {
	if err := validateReservation(request.Operation); err != nil {
		return err
	}
	if err := validateReplayKey(request.ReplayKey); err != nil {
		return err
	}
	if request.ReplayRetainUntil.IsZero() {
		return fmt.Errorf("%w: missing replay retention", ErrInvalidRecord)
	}
	return nil
}

func validateReplayKey(value string) error {
	if value == "" || len(value) > maxReplayKeyBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: invalid replay key", ErrInvalidRecord)
	}
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || separator+1+64 != len(value) {
		return fmt.Errorf("%w: replay key must be a domain-separated SHA-256 digest", ErrInvalidRecord)
	}
	domain, digest := value[:separator], value[separator+1:]
	if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
		return fmt.Errorf("%w: replay key must be a domain-separated SHA-256 digest", ErrInvalidRecord)
	}
	for _, character := range domain {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-') {
			return fmt.Errorf("%w: invalid replay key", ErrInvalidRecord)
		}
	}
	return nil
}

func validateFinalization(final Finalization) error {
	if err := validateReservation(Reservation{OperationID: final.OperationID, RequestDigest: final.RequestDigest}); err != nil {
		return err
	}
	if !final.State.Terminal() {
		return fmt.Errorf("%w: final state %q is not terminal", ErrInvalidRecord, final.State)
	}
	return validateDigest(final.OutcomeDigest, true)
}

func validateOperationID(value string) error {
	if value == "" || len(value) > maxOperationIDBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: invalid operation ID", ErrInvalidRecord)
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == unicode.ReplacementChar {
			return fmt.Errorf("%w: invalid operation ID", ErrInvalidRecord)
		}
	}
	return nil
}

func validateDigest(value string, optional bool) error {
	if value == "" && optional {
		return nil
	}
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%w: digest must use canonical sha256 encoding", ErrInvalidRecord)
	}
	raw := value[len(prefix):]
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 || strings.ToLower(raw) != raw {
		return fmt.Errorf("%w: digest must use canonical sha256 encoding", ErrInvalidRecord)
	}
	return nil
}

// ValidateSealedResult applies the common storage contract used by file and
// shared transactional adapters. It validates only the opaque envelope; the
// Agent B that owns the encryption key must verify authenticated decryption and
// the plaintext outcome digest before returning a result.
func ValidateSealedResult(result SealedResult) error {
	if err := validateReservation(Reservation{OperationID: result.OperationID, RequestDigest: result.RequestDigest}); err != nil {
		return err
	}
	if err := validateDigest(result.OutcomeDigest, false); err != nil {
		return err
	}
	if result.Envelope != SealedResultEnvelopeV1 {
		return fmt.Errorf("%w: unsupported sealed result envelope", ErrInvalidRecord)
	}
	if result.MediaType == "" || len(result.MediaType) > maxResultMediaType || !utf8.ValidString(result.MediaType) || strings.TrimSpace(result.MediaType) != result.MediaType {
		return fmt.Errorf("%w: invalid result media type", ErrInvalidRecord)
	}
	mediaType, parameters, err := mime.ParseMediaType(result.MediaType)
	if err != nil || mediaType == "" || mime.FormatMediaType(mediaType, parameters) != result.MediaType {
		return fmt.Errorf("%w: result media type must use canonical encoding", ErrInvalidRecord)
	}
	if result.PlaintextBytes > maxResultPlaintext || len(result.Nonce) != aesGCMNonceBytes ||
		len(result.Ciphertext) != int(result.PlaintextBytes)+aesGCMTagBytes || len(result.Ciphertext) > maxResultPlaintext+aesGCMTagBytes {
		return fmt.Errorf("%w: invalid sealed result bounds", ErrInvalidRecord)
	}
	return nil
}

func validatePersistedState(state persistedState) error {
	if state.Schema != fileSchema || state.Records == nil || state.Replay == nil || state.Results == nil ||
		len(state.Records) > maxJournalRecords || len(state.Replay) > maxReplayRecords || len(state.Results) > maxJournalRecords {
		return fmt.Errorf("%w: unsupported or invalid state envelope", ErrUnavailable)
	}
	for key, retainUntil := range state.Replay {
		if err := validateReplayKey(key); err != nil || retainUntil.IsZero() {
			return fmt.Errorf("%w: invalid replay record", ErrUnavailable)
		}
	}
	for key, record := range state.Records {
		if key != record.OperationID {
			return fmt.Errorf("%w: record key mismatch", ErrUnavailable)
		}
		if err := validatePersistedRecord(record); err != nil {
			return err
		}
	}
	for key, result := range state.Results {
		if key != result.OperationID {
			return fmt.Errorf("%w: sealed result key mismatch", ErrUnavailable)
		}
		if err := ValidateSealedResult(result); err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		record, ok := state.Records[key]
		if !ok || record.State != StateSucceeded || record.RequestDigest != result.RequestDigest || record.OutcomeDigest != result.OutcomeDigest {
			return fmt.Errorf("%w: sealed result does not match a successful record", ErrUnavailable)
		}
	}
	return nil
}

func cloneSealedResult(result SealedResult) SealedResult {
	result.Nonce = append([]byte(nil), result.Nonce...)
	result.Ciphertext = append([]byte(nil), result.Ciphertext...)
	return result
}

func sealedResultsEqual(left, right SealedResult) bool {
	return left.OperationID == right.OperationID && left.RequestDigest == right.RequestDigest &&
		left.OutcomeDigest == right.OutcomeDigest && left.MediaType == right.MediaType &&
		left.Envelope == right.Envelope && left.PlaintextBytes == right.PlaintextBytes &&
		bytes.Equal(left.Nonce, right.Nonce) && bytes.Equal(left.Ciphertext, right.Ciphertext)
}

func validatePersistedRecord(record Record) error {
	if err := validateReservation(Reservation{OperationID: record.OperationID, RequestDigest: record.RequestDigest}); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if record.Revision == 0 || record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
		return fmt.Errorf("%w: invalid record revision or time", ErrUnavailable)
	}
	if err := validateDigest(record.OutcomeDigest, true); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch record.State {
	case StateAccepted:
		if !record.StartedAt.IsZero() || !record.CompletedAt.IsZero() || record.OutcomeDigest != "" {
			return fmt.Errorf("%w: invalid ACCEPTED record", ErrUnavailable)
		}
	case StateRunning, StateIndeterminate:
		if record.StartedAt.IsZero() || !record.CompletedAt.IsZero() || record.OutcomeDigest != "" {
			return fmt.Errorf("%w: invalid non-terminal execution record", ErrUnavailable)
		}
	case StateSucceeded, StateFailed:
		if record.StartedAt.IsZero() || record.CompletedAt.IsZero() {
			return fmt.Errorf("%w: invalid terminal execution record", ErrUnavailable)
		}
	case StateCanceled:
		if record.CompletedAt.IsZero() {
			return fmt.Errorf("%w: invalid canceled record", ErrUnavailable)
		}
	default:
		return fmt.Errorf("%w: unsupported operation state", ErrUnavailable)
	}
	if !record.StartedAt.IsZero() && record.StartedAt.Before(record.CreatedAt) {
		return fmt.Errorf("%w: start time precedes reservation", ErrUnavailable)
	}
	if !record.StartedAt.IsZero() && record.StartedAt.After(record.UpdatedAt) {
		return fmt.Errorf("%w: start time follows the latest update", ErrUnavailable)
	}
	if !record.CompletedAt.IsZero() && (record.CompletedAt.Before(record.CreatedAt) || record.CompletedAt.Before(record.UpdatedAt)) {
		return fmt.Errorf("%w: completion time is inconsistent", ErrUnavailable)
	}
	if !record.CompletedAt.IsZero() && !record.CompletedAt.Equal(record.UpdatedAt) {
		return fmt.Errorf("%w: terminal update time mismatch", ErrUnavailable)
	}
	return nil
}
