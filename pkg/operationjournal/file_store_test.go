// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package operationjournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFileStoreReserveIsExactAndIdempotent(t *testing.T) {
	store := newTestFileStore(t)
	request := Reservation{OperationID: "message-0001", RequestDigest: testDigest("request-one")}

	first, created, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if !created || first.State != StateAccepted || first.Revision != 1 {
		t.Fatalf("Reserve() = (%+v, %v), want new ACCEPTED revision 1", first, created)
	}

	retry, created, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatalf("exact Reserve() error = %v", err)
	}
	if created || !reflect.DeepEqual(retry, first) {
		t.Fatalf("exact Reserve() = (%+v, %v), want unchanged %+v", retry, created, first)
	}

	lookedUp, err := store.Lookup(context.Background(), request.OperationID, request.RequestDigest)
	if err != nil || !reflect.DeepEqual(lookedUp, first) {
		t.Fatalf("Lookup() = (%+v, %v), want %+v", lookedUp, err, first)
	}

	wrongDigest := testDigest("request-two")
	if _, _, err := store.Reserve(context.Background(), Reservation{OperationID: request.OperationID, RequestDigest: wrongDigest}); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Reserve() error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.Lookup(context.Background(), request.OperationID, wrongDigest); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Lookup() error = %v, want %v", err, ErrConflict)
	}
	if _, err := store.Lookup(context.Background(), "missing-operation", request.RequestDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Lookup() error = %v, want %v", err, ErrNotFound)
	}
}

func TestFileStoreReserveAcceptanceCommitsReplayAndOperationTogether(t *testing.T) {
	store := newTestFileStore(t)
	now := time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)
	store.now = func() time.Time { return now }
	request := AcceptanceReservation{
		ReplayKey:         "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("nonce-one"), "sha256:"),
		ReplayRetainUntil: now.Add(time.Hour),
		Operation: Reservation{
			OperationID:   "operation-accepted",
			RequestDigest: testDigest("stable application request"),
		},
	}

	accepted, created, err := store.ReserveAcceptance(context.Background(), request)
	if err != nil {
		t.Fatalf("ReserveAcceptance() error = %v", err)
	}
	if !created || accepted.State != StateAccepted {
		t.Fatalf("ReserveAcceptance() = (%+v, %v), want new ACCEPTED record", accepted, created)
	}

	replayed := request
	replayed.Operation.OperationID = "operation-replay"
	replayed.Operation.RequestDigest = testDigest("another request")
	if _, _, err := store.ReserveAcceptance(context.Background(), replayed); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed ReserveAcceptance() error = %v, want %v", err, ErrReplay)
	}
	if _, err := store.Lookup(context.Background(), replayed.Operation.OperationID, replayed.Operation.RequestDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed operation Lookup() error = %v, want %v", err, ErrNotFound)
	}

	exactRetry := request
	exactRetry.ReplayKey = "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("nonce-two"), "sha256:")
	retry, created, err := store.ReserveAcceptance(context.Background(), exactRetry)
	if err != nil {
		t.Fatalf("fresh-nonce exact retry error = %v", err)
	}
	if created || !reflect.DeepEqual(retry, accepted) {
		t.Fatalf("fresh-nonce exact retry = (%+v, %v), want unchanged %+v", retry, created, accepted)
	}
}

func TestFileStoreReserveAcceptanceDoesNotConsumeReplayOnConflict(t *testing.T) {
	store := newTestFileStore(t)
	now := time.Date(2026, 8, 25, 2, 3, 4, 0, time.UTC)
	store.now = func() time.Time { return now }
	base := AcceptanceReservation{
		ReplayKey:         "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("initial nonce"), "sha256:"),
		ReplayRetainUntil: now.Add(time.Hour),
		Operation: Reservation{
			OperationID:   "operation-conflict",
			RequestDigest: testDigest("initial request"),
		},
	}
	if _, _, err := store.ReserveAcceptance(context.Background(), base); err != nil {
		t.Fatalf("initial ReserveAcceptance() error = %v", err)
	}

	freshReplayKey := "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("fresh nonce"), "sha256:")
	conflict := base
	conflict.ReplayKey = freshReplayKey
	conflict.Operation.RequestDigest = testDigest("different request")
	if _, _, err := store.ReserveAcceptance(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting ReserveAcceptance() error = %v, want %v", err, ErrConflict)
	}

	valid := conflict
	valid.Operation.OperationID = "operation-after-conflict"
	if _, created, err := store.ReserveAcceptance(context.Background(), valid); err != nil || !created {
		t.Fatalf("replay key after rejected conflict = (created %v, error %v), want new reservation", created, err)
	}
}

func TestFileStoreReserveAcceptanceSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore() error = %v", err)
	}
	now := time.Date(2026, 8, 25, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	request := AcceptanceReservation{
		ReplayKey:         "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("restart nonce"), "sha256:"),
		ReplayRetainUntil: now.Add(time.Hour),
		Operation: Reservation{
			OperationID:   "operation-restart-acceptance",
			RequestDigest: testDigest("restart request"),
		},
	}
	want, _, err := store.ReserveAcceptance(context.Background(), request)
	if err != nil {
		t.Fatalf("ReserveAcceptance() error = %v", err)
	}

	restarted, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("restart OpenFileStore() error = %v", err)
	}
	restarted.now = func() time.Time { return now }
	got, err := restarted.Lookup(context.Background(), request.Operation.OperationID, request.Operation.RequestDigest)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("restart Lookup() = (%+v, %v), want %+v", got, err, want)
	}
	request.Operation.OperationID = "operation-after-restart"
	request.Operation.RequestDigest = testDigest("another request")
	if _, _, err := restarted.ReserveAcceptance(context.Background(), request); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay after restart error = %v, want %v", err, ErrReplay)
	}
}

func TestFileStoreReserveAcceptanceFailureLeavesNeitherReservation(t *testing.T) {
	store := newTestFileStore(t)
	now := time.Date(2026, 8, 25, 4, 5, 6, 0, time.UTC)
	store.now = func() time.Time { return now }
	request := AcceptanceReservation{
		ReplayKey:         "sbaip-replay-v2:" + strings.TrimPrefix(testDigest("failed nonce"), "sha256:"),
		ReplayRetainUntil: now.Add(time.Hour),
		Operation: Reservation{
			OperationID:   "operation-failed-acceptance",
			RequestDigest: testDigest("failed acceptance request"),
		},
	}
	store.beforeCommit = func() error { return errors.New("injected pre-rename failure") }
	if _, _, err := store.ReserveAcceptance(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed ReserveAcceptance() error = %v, want %v", err, ErrUnavailable)
	}

	restarted, err := OpenFileStore(store.path)
	if err != nil {
		t.Fatalf("restart OpenFileStore() error = %v", err)
	}
	restarted.now = func() time.Time { return now }
	if _, err := restarted.Lookup(context.Background(), request.Operation.OperationID, request.Operation.RequestDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup() after failed acceptance error = %v, want %v", err, ErrNotFound)
	}
	if _, created, err := restarted.ReserveAcceptance(context.Background(), request); err != nil || !created {
		t.Fatalf("retry after failed acceptance = (created %v, error %v), want new reservation", created, err)
	}
}

func TestFileStoreTransitionsAndFinalizationAreIdempotent(t *testing.T) {
	store := newTestFileStore(t)
	base := time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)
	now := base
	store.now = func() time.Time { return now }
	operationID := "task-0001/message-0001"
	requestDigest := testDigest("bound request")

	accepted, _, err := store.Reserve(context.Background(), Reservation{OperationID: operationID, RequestDigest: requestDigest})
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	now = now.Add(time.Second)
	running, started, err := store.MarkRunning(context.Background(), operationID, requestDigest)
	if err != nil {
		t.Fatalf("MarkRunning() error = %v", err)
	}
	if !started || running.State != StateRunning || running.Revision != accepted.Revision+1 || !running.StartedAt.Equal(now) {
		t.Fatalf("running record = %+v", running)
	}
	if retry, started, err := store.MarkRunning(context.Background(), operationID, requestDigest); err != nil || started || !reflect.DeepEqual(retry, running) {
		t.Fatalf("exact MarkRunning() = (%+v, %v, %v), want unchanged and started=false", retry, started, err)
	}

	now = now.Add(time.Second)
	indeterminate, err := store.MarkIndeterminate(context.Background(), operationID, requestDigest)
	if err != nil {
		t.Fatalf("MarkIndeterminate() error = %v", err)
	}
	if indeterminate.State != StateIndeterminate || indeterminate.Revision != running.Revision+1 || !indeterminate.StartedAt.Equal(running.StartedAt) {
		t.Fatalf("indeterminate record = %+v", indeterminate)
	}
	if retry, err := store.MarkIndeterminate(context.Background(), operationID, requestDigest); err != nil || !reflect.DeepEqual(retry, indeterminate) {
		t.Fatalf("exact MarkIndeterminate() = (%+v, %v), want %+v", retry, err, indeterminate)
	}

	now = now.Add(time.Second)
	final := Finalization{
		OperationID: operationID, RequestDigest: requestDigest,
		State: StateSucceeded, OutcomeDigest: testDigest("stored outcome"),
	}
	succeeded, err := store.Finalize(context.Background(), final)
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}
	if succeeded.State != StateSucceeded || !succeeded.State.Terminal() || succeeded.Revision != indeterminate.Revision+1 || !succeeded.CompletedAt.Equal(now) {
		t.Fatalf("succeeded record = %+v", succeeded)
	}
	if retry, err := store.Finalize(context.Background(), final); err != nil || !reflect.DeepEqual(retry, succeeded) {
		t.Fatalf("exact Finalize() = (%+v, %v), want %+v", retry, err, succeeded)
	}

	conflicting := final
	conflicting.OutcomeDigest = testDigest("different outcome")
	if _, err := store.Finalize(context.Background(), conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting outcome error = %v, want %v", err, ErrConflict)
	}
	conflicting = final
	conflicting.State = StateFailed
	if _, err := store.Finalize(context.Background(), conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting terminal state error = %v, want %v", err, ErrConflict)
	}
	if _, _, err := store.MarkRunning(context.Background(), operationID, requestDigest); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal MarkRunning() error = %v, want %v", err, ErrInvalidTransition)
	}
	if StateAccepted.Terminal() || StateRunning.Terminal() || StateIndeterminate.Terminal() {
		t.Fatal("a non-terminal state reported Terminal() = true")
	}
}

func TestFileStoreAllowsCancelBeforeStartButNoOtherFinalization(t *testing.T) {
	store := newTestFileStore(t)
	request := Reservation{OperationID: "operation-cancel", RequestDigest: testDigest("cancel request")}
	if _, _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if _, err := store.Finalize(context.Background(), Finalization{
		OperationID: request.OperationID, RequestDigest: request.RequestDigest, State: StateFailed,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("ACCEPTED -> FAILED error = %v, want %v", err, ErrInvalidTransition)
	}
	canceled, err := store.Finalize(context.Background(), Finalization{
		OperationID: request.OperationID, RequestDigest: request.RequestDigest, State: StateCanceled,
	})
	if err != nil {
		t.Fatalf("ACCEPTED -> CANCELED error = %v", err)
	}
	if canceled.State != StateCanceled || !canceled.StartedAt.IsZero() || canceled.CompletedAt.IsZero() {
		t.Fatalf("canceled record = %+v", canceled)
	}
}

func TestFileStoreSurvivesRestartWithOwnerOnlyAtomicState(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "journal", "operations.json")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("OpenFileStore() error = %v", err)
	}
	request := Reservation{OperationID: "operation-restart", RequestDigest: testDigest("private request bytes")}
	if _, _, err := store.Reserve(context.Background(), request); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if _, started, err := store.MarkRunning(context.Background(), request.OperationID, request.RequestDigest); err != nil || !started {
		t.Fatalf("MarkRunning() error = %v", err)
	}
	if _, err := store.MarkIndeterminate(context.Background(), request.OperationID, request.RequestDigest); err != nil {
		t.Fatalf("MarkIndeterminate() error = %v", err)
	}
	want, err := store.Finalize(context.Background(), Finalization{
		OperationID: request.OperationID, RequestDigest: request.RequestDigest,
		State: StateFailed, OutcomeDigest: testDigest("known failure"),
	})
	if err != nil {
		t.Fatalf("Finalize() error = %v", err)
	}

	restarted, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("restart OpenFileStore() error = %v", err)
	}
	got, err := restarted.Lookup(context.Background(), request.OperationID, request.RequestDigest)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("restart Lookup() = (%+v, %v), want %+v", got, err, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if permission := info.Mode().Perm(); permission != 0o600 {
		t.Fatalf("journal permission = %04o, want 0600", permission)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(raw), "private request bytes") {
		t.Fatal("journal persisted raw request bytes")
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".operation-journal-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary journal files = %v, error = %v", matches, err)
	}
}

func TestFileStorePreservesPreviousStateWhenCommitFails(t *testing.T) {
	store := newTestFileStore(t)
	request := Reservation{OperationID: "operation-commit-failure", RequestDigest: testDigest("request")}
	want, _, err := store.Reserve(context.Background(), request)
	if err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	commitFailure := errors.New("injected pre-rename failure")
	store.beforeCommit = func() error { return commitFailure }
	if _, _, err := store.MarkRunning(context.Background(), request.OperationID, request.RequestDigest); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("MarkRunning() error = %v, want %v", err, ErrUnavailable)
	}

	restarted, err := OpenFileStore(store.path)
	if err != nil {
		t.Fatalf("restart OpenFileStore() error = %v", err)
	}
	got, err := restarted.Lookup(context.Background(), request.OperationID, request.RequestDigest)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("record after failed commit = (%+v, %v), want prior %+v", got, err, want)
	}
}

func TestFileStoreSerializesConcurrentExactReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	first, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("first OpenFileStore() error = %v", err)
	}
	second, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("second OpenFileStore() error = %v", err)
	}
	request := Reservation{OperationID: "operation-concurrent", RequestDigest: testDigest("same request")}
	stores := []*FileStore{first, second}
	const workers = 32
	var created atomic.Int32
	var wait sync.WaitGroup
	errorsFromWorkers := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(store *FileStore) {
			defer wait.Done()
			_, wasCreated, reserveErr := store.Reserve(context.Background(), request)
			if reserveErr != nil {
				errorsFromWorkers <- reserveErr
				return
			}
			if wasCreated {
				created.Add(1)
			}
		}(stores[index%len(stores)])
	}
	wait.Wait()
	close(errorsFromWorkers)
	for err := range errorsFromWorkers {
		t.Errorf("concurrent Reserve() error = %v", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("created reservations = %d, want 1", got)
	}

	var started atomic.Int32
	errorsFromWorkers = make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(store *FileStore) {
			defer wait.Done()
			_, wasStarted, startErr := store.MarkRunning(context.Background(), request.OperationID, request.RequestDigest)
			if startErr != nil {
				errorsFromWorkers <- startErr
				return
			}
			if wasStarted {
				started.Add(1)
			}
		}(stores[index%len(stores)])
	}
	wait.Wait()
	close(errorsFromWorkers)
	for err := range errorsFromWorkers {
		t.Errorf("concurrent MarkRunning() error = %v", err)
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("started operations = %d, want 1", got)
	}
}

func TestFileStoreRejectsMalformedStateAndInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "operations.json")
	if err := os.WriteFile(path, []byte(`{"schema":"urn:asb:operation-journal:v1","records":{},"unknown":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := OpenFileStore(path); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed OpenFileStore() error = %v, want %v", err, ErrUnavailable)
	}

	store := newTestFileStore(t)
	validDigest := testDigest("request")
	for _, request := range []Reservation{
		{OperationID: "", RequestDigest: validDigest},
		{OperationID: " operation", RequestDigest: validDigest},
		{OperationID: "operation", RequestDigest: strings.ToUpper(validDigest)},
		{OperationID: "operation", RequestDigest: "request bytes"},
	} {
		if _, _, err := store.Reserve(context.Background(), request); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("Reserve(%+v) error = %v, want %v", request, err, ErrInvalidRecord)
		}
	}
	for _, replayKey := range []string{
		"raw-verifier-nonce",
		"sbaip-replay-v2:short",
		"sbaip-replay-v2:" + strings.Repeat("A", 64),
	} {
		_, _, err := store.ReserveAcceptance(context.Background(), AcceptanceReservation{
			ReplayKey: replayKey, ReplayRetainUntil: time.Now().UTC().Add(time.Minute),
			Operation: Reservation{OperationID: "invalid-replay-key", RequestDigest: validDigest},
		})
		if !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("ReserveAcceptance(replay key %q) error = %v, want %v", replayKey, err, ErrInvalidRecord)
		}
	}
	if _, err := store.Finalize(context.Background(), Finalization{
		OperationID: "operation", RequestDigest: validDigest, State: StateRunning,
	}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("non-terminal Finalize() error = %v, want %v", err, ErrInvalidRecord)
	}
	if _, _, err := store.Reserve(nil, Reservation{OperationID: "operation", RequestDigest: validDigest}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("nil-context Reserve() error = %v, want %v", err, ErrInvalidRecord)
	}
}

func TestFileStoreHonorsCanceledContext(t *testing.T) {
	store := newTestFileStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := store.Reserve(ctx, Reservation{OperationID: "operation-canceled-context", RequestDigest: testDigest("request")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Reserve() error = %v, want %v", err, context.Canceled)
	}
}

func newTestFileStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "operations.json"))
	if err != nil {
		t.Fatalf("OpenFileStore() error = %v", err)
	}
	return store
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
