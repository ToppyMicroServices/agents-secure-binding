// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sqliteFixture(t *testing.T, s *SQLiteStore, suffix string) durableFixture {
	t.Helper()
	f := newDurableFixture(t)
	f.mandate.ID = s.Namespace() + "/mandate-" + suffix
	f.config.Mandate = f.mandate
	a, err := NewAuthorizer(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.cap, err = a.Authorize(context.Background(), f.request, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newSQLiteFixture(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := CreateSQLiteStore(t.Context(), filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteConcurrentAdmissionAndRestart(t *testing.T) {
	s := newSQLiteFixture(t)
	other, err := OpenSQLiteStore(t.Context(), s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	f := sqliteFixture(t, s, "one")
	id := s.Namespace() + "/operation-one"
	var calls atomic.Int32
	effect := func(context.Context, string, Request) (EffectResult, error) {
		calls.Add(1)
		return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store := s
			if i%2 == 0 {
				store = other
			}
			_, err := store.Run(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now, effect)
			if err != nil && !errors.Is(err, ErrOutcomeUnknown) {
				t.Errorf("run: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("dispatches: %d", calls.Load())
	}
	reopened, err := OpenSQLiteStore(t.Context(), s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r, err := reopened.Run(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now, effect)
	if err != nil || r.State != ExecutionSucceeded || calls.Load() != 1 {
		t.Fatalf("restart redispatched: %+v %v", r, err)
	}
	if _, _, err = reopened.Prepare(t.Context(), s.Namespace()+"/different", f.cap, f.key, f.mandate, f.request, f.now); !errors.Is(err, ErrReplay) {
		t.Fatalf("mandate replay: %v", err)
	}
}

func TestSQLiteBackupRestoreRotatesAuthority(t *testing.T) {
	s := newSQLiteFixture(t)
	f := sqliteFixture(t, s, "unknown")
	id := s.Namespace() + "/original"
	r, err := s.Run(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now, func(context.Context, string, Request) (EffectResult, error) {
		return EffectResult{}, errors.New("lost response")
	})
	if !errors.Is(err, ErrOutcomeUnknown) || r.State != ExecutionUnknown {
		t.Fatalf("uncertain: %+v %v", r, err)
	}
	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(backupDir, "journal.sqlite")
	manifest, err := s.Backup(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenSQLiteStore(t.Context(), backupDir); err == nil {
		t.Fatal("backup executable without restore")
	}
	if _, err = s.Backup(t.Context(), path); err == nil {
		t.Fatal("backup replaced existing file")
	}
	// This mandate was never present in the snapshot. A restored journal must
	// still reject it, rather than relying on the snapshot's replay records.
	absent := sqliteFixture(t, s, "absent")
	restored, err := RestoreSQLiteStore(t.Context(), path, filepath.Join(t.TempDir(), "restored"), manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.Namespace() == s.Namespace() {
		t.Fatal("restore retained authority namespace")
	}
	old, err := restored.Lookup(t.Context(), r.OperationID, r.RequestDigest)
	if err != nil || old.State != ExecutionUnknown {
		t.Fatalf("unknown lost: %+v %v", old, err)
	}
	for _, candidate := range []durableFixture{f, absent} {
		if _, _, err = restored.Prepare(t.Context(), restored.Namespace()+"/new-op", candidate.cap, candidate.key, candidate.mandate, candidate.request, candidate.now); !errors.Is(err, ErrBinding) {
			t.Fatalf("old mandate admitted after restore: %v", err)
		}
	}
	fresh := sqliteFixture(t, restored, "fresh")
	if _, _, err = restored.Prepare(t.Context(), restored.Namespace()+"/fresh-op", fresh.cap, fresh.key, fresh.mandate, fresh.request, fresh.now); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(t.TempDir(), "bad-restore")
	if _, err = RestoreSQLiteStore(t.Context(), path, broken, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong backup digest accepted")
	}
	if _, err = OpenSQLiteStore(t.Context(), broken); err == nil {
		t.Fatal("incomplete restore became executable")
	}
}

func TestSQLiteBeyondSnapshotCapacityAndRetainedIdentities(t *testing.T) {
	s := newSQLiteFixture(t)
	// Seed 10,001 retained identities in a single fixture transaction. Admission
	// through the real signed API must still work beyond the old store's cap.
	f := sqliteFixture(t, s, "seed")
	tx, err := s.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range 10001 {
		id := fmt.Sprintf("%s/old-%d", s.Namespace(), i)
		if _, err = tx.ExecContext(t.Context(), `INSERT INTO operations VALUES(?,?,?,?,?,?,?)`, id, f.mandate.ActionDigest, id, f.mandate.ActionDigest, f.now.UnixNano(), string(ExecutionSucceeded), f.mandate.ActionDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.ExecContext(t.Context(), `INSERT INTO uses VALUES(?,?,?)`, "asb.least-privilege/"+id, f.now.UnixNano(), id); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f = sqliteFixture(t, s, "new")
	if _, _, err = s.Prepare(t.Context(), s.Namespace()+"/new", f.cap, f.key, f.mandate, f.request, f.now); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(t.Context())
	if err != nil || status.Operations != 10002 {
		t.Fatalf("capacity: %+v %v", status, err)
	}
	if _, _, err = s.Prepare(t.Context(), s.Namespace()+"/old-0", f.cap, f.key, f.mandate, f.request, f.now); !errors.Is(err, ErrExecutionConflict) {
		t.Fatalf("old operation forgotten: %v", err)
	}
}

func TestSQLiteNoncePruningClockRollbackAndMissingState(t *testing.T) {
	s := newSQLiteFixture(t)
	now := time.Now().UTC()
	expiry := now.Add(time.Second)
	if err := s.Use(t.Context(), "old", expiry, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(t.Context(), "new", expiry.Add(time.Hour), expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(t.Context(), "old", expiry, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := OpenSQLiteStore(t.Context(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing state initialized")
	}
	if err := os.Chmod(filepath.Join(s.directory, "journal.sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSQLiteStore(t.Context(), s.directory); err == nil {
		t.Fatal("public database accepted")
	}
}

func TestSQLiteCrashNeverRedispatches(t *testing.T) {
	if path := os.Getenv("ASB_SQLITE_CRASH_FIXTURE"); path != "" {
		s, err := OpenSQLiteStore(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		f := sqliteFixture(t, s, "crash")
		_, _ = s.Run(t.Context(), s.Namespace()+"/crash", f.cap, f.key, f.mandate, f.request, f.now, func(context.Context, string, Request) (EffectResult, error) { os.Exit(73); return EffectResult{}, nil })
		t.Fatal("worker did not exit")
	}
	s := newSQLiteFixture(t)
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSQLiteCrashNeverRedispatches$")
	cmd.Env = append(os.Environ(), "ASB_SQLITE_CRASH_FIXTURE="+s.directory)
	var exit *exec.ExitError
	if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("worker exit: %v", err)
	}
	f := sqliteFixture(t, s, "crash")
	called := false
	r, err := s.Run(t.Context(), s.Namespace()+"/crash", f.cap, f.key, f.mandate, f.request, f.now, func(context.Context, string, Request) (EffectResult, error) {
		called = true
		return EffectResult{}, nil
	})
	if !errors.Is(err, ErrOutcomeUnknown) || r.State != ExecutionRunning || called {
		t.Fatalf("crash retry: %+v %v called=%v", r, err, called)
	}
}

func TestSQLiteMandateRevocationSurvivesRestartAndBundleRollback(t *testing.T) {
	s := newSQLiteFixture(t)
	f := sqliteFixture(t, s, "active")
	if err := s.SyncMandates(t.Context(), []Mandate{f.mandate}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncMandates(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSQLiteStore(t.Context(), s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err = reopened.SyncMandates(t.Context(), []Mandate{f.mandate}); !errors.Is(err, ErrInvalidMandate) {
		t.Fatalf("revoked mandate revived: %v", err)
	}
	fresh := sqliteFixture(t, s, "fresh")
	if err = reopened.SyncMandates(t.Context(), []Mandate{fresh.mandate}); err != nil {
		t.Fatal(err)
	}
	fresh.mandate.ExpiresAt = fresh.mandate.ExpiresAt.Add(time.Hour)
	if err = reopened.SyncMandates(t.Context(), []Mandate{fresh.mandate}); !errors.Is(err, ErrInvalidMandate) {
		t.Fatalf("existing authority altered: %v", err)
	}
}
