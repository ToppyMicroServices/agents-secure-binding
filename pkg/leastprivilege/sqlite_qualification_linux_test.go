// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Only an explicitly provisioned disposable, size-limited filesystem is used.
// The CI job owns that tmpfs; this test never fills the host's normal disk.
func TestSQLiteFilesystemFullRecovery(t *testing.T) {
	directory := os.Getenv("ASB_QA_FULL_DIRECTORY")
	if directory == "" {
		t.Skip("requires disposable 32 MiB tmpfs")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(directory, &fs); err != nil || fs.Type != unix.TMPFS_MAGIC || fs.Blocks*uint64(fs.Bsize) > 64<<20 {
		t.Fatal("refusing non-disposable capacity fixture")
	}
	s, err := CreateSQLiteStore(t.Context(), filepath.Join(directory, "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	f := sqliteFixture(t, s, "full")
	id := s.Namespace() + "/full"
	r, _, err := s.Prepare(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Start(t.Context(), id, r.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	filler := filepath.Join(directory, "capacity-fixture")
	file, err := os.OpenFile(filler, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1<<20)
	for err == nil {
		_, err = file.Write(buffer)
	}
	_ = file.Close()
	defer os.Remove(filler)
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatal("did not observe real ENOSPC", err)
	}
	if _, err = s.Complete(t.Context(), id, r.RequestDigest, ExecutionSucceeded, f.mandate.ActionDigest); err == nil {
		t.Fatal("completion unexpectedly persisted on full filesystem")
	}
	if err = os.Remove(filler); err != nil {
		t.Fatal(err)
	}
	assertUncertainAndFresh(t, s, f, id)
	t.Log("storage_fault=ENOSPC running_retained=true repeat_dispatches=0 fresh_request_succeeded=true")
}

func assertUncertainAndFresh(t *testing.T, s *SQLiteStore, f durableFixture, id string) {
	t.Helper()
	calls := 0
	effect := func(context.Context, string, Request) (EffectResult, error) {
		calls++
		return EffectResult{State: ExecutionSucceeded, EvidenceDigest: f.mandate.ActionDigest}, nil
	}
	_, err := s.Run(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now, effect)
	if !errors.Is(err, ErrOutcomeUnknown) || calls != 0 {
		t.Fatalf("uncertain effect replayed: %v calls=%d", err, calls)
	}
	fresh := sqliteFixture(t, s, "recovered")
	if r, err := s.Run(t.Context(), s.Namespace()+"/recovered", fresh.cap, fresh.key, fresh.mandate, fresh.request, fresh.now, effect); err != nil || r.State != ExecutionSucceeded || calls != 1 {
		t.Fatalf("fresh execution did not recover: %+v %v calls=%d", r, err, calls)
	}
}

func TestSQLiteKernelWriteFailureRecovery(t *testing.T) {
	// RLIMIT_FSIZE is process-wide, so exercise it in an isolated test child.
	if os.Getenv("ASB_QA_FSIZE_CHILD") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSQLiteKernelWriteFailureRecovery$", "-test.v")
		cmd.Env = append(os.Environ(), "ASB_QA_FSIZE_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("write fault child: %s %v", out, err)
		}
		t.Log(string(out))
		return
	}
	s := newSQLiteFixture(t)
	f := sqliteFixture(t, s, "io")
	id := s.Namespace() + "/io"
	r, _, err := s.Prepare(t.Context(), id, f.cap, f.key, f.mandate, f.request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Start(t.Context(), id, r.RequestDigest); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	var previous unix.Rlimit
	if err = unix.Getrlimit(unix.RLIMIT_FSIZE, &previous); err != nil {
		t.Fatal(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	if err = unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 1, Max: previous.Max}); err != nil {
		t.Fatal(err)
	}
	_, failed := s.Complete(t.Context(), id, r.RequestDigest, ExecutionSucceeded, f.mandate.ActionDigest)
	if err = unix.Setrlimit(unix.RLIMIT_FSIZE, &previous); err != nil {
		t.Fatal(err)
	}
	if failed == nil {
		t.Fatal("kernel write limit did not fail persistence")
	}
	assertUncertainAndFresh(t, s, f, id)
	t.Log("storage_fault=kernel_file_size_limit running_retained=true repeat_dispatches=0 fresh_request_succeeded=true")
}

func TestSQLiteHistoryMonitoringAndBackupQualification(t *testing.T) {
	if os.Getenv("ASB_QA_CAPACITY") != "1" {
		t.Skip("opt-in bounded history measurement")
	}
	s := newSQLiteFixture(t)
	f := sqliteFixture(t, s, "seed")
	err := s.write(t.Context(), func(conn *sql.Conn) error {
		for i := range 100000 {
			id := fmt.Sprintf("%s/history-%d", s.Namespace(), i)
			if _, err := conn.ExecContext(t.Context(), `INSERT INTO operations VALUES(?,?,?,?,?,?,?)`, id, f.mandate.ActionDigest, id, f.mandate.ActionDigest, f.now.UnixNano(), string(ExecutionSucceeded), f.mandate.ActionDigest); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, monitoring := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		var wg sync.WaitGroup
		var monitorErr error
		if monitoring {
			wg.Go(func() {
				for ctx.Err() == nil {
					if _, err := ReadSQLiteStatus(ctx, s.directory); err != nil && ctx.Err() == nil {
						monitorErr = err
						return
					}
				}
			})
		}
		latency := make([]int64, 0, 100)
		for i := range 100 {
			fresh := sqliteFixture(t, s, fmt.Sprintf("%t-%d", monitoring, i))
			start := time.Now()
			_, err = s.Run(t.Context(), s.Namespace()+fmt.Sprintf("/measure-%t-%d", monitoring, i), fresh.cap, fresh.key, fresh.mandate, fresh.request, fresh.now, func(context.Context, string, Request) (EffectResult, error) {
				return EffectResult{State: ExecutionSucceeded, EvidenceDigest: fresh.mandate.ActionDigest}, nil
			})
			latency = append(latency, time.Since(start).Microseconds())
			if err != nil {
				cancel()
				wg.Wait()
				t.Fatal(err)
			}
		}
		cancel()
		wg.Wait()
		if monitorErr != nil {
			t.Fatal(monitorErr)
		}
		slices.Sort(latency)
		if latency[98] > 1_000_000 || latency[99] > 5_000_000 {
			t.Fatal("p99 >1s or maximum >5s on the lab workload")
		}
		t.Logf("history=100000 monitoring=%t samples=100 p95_us=%d p99_us=%d max_us=%d", monitoring, latency[94], latency[98], latency[99])
	}
	start := time.Now()
	_, err = s.Backup(t.Context(), filepath.Join(t.TempDir(), "snapshot.sqlite"))
	if err != nil || time.Since(start) > time.Minute {
		t.Fatal("backup failed or exceeded lab 60s budget", err)
	}
	status, err := s.Status(t.Context())
	if err != nil || status.Operations != 100200 || status.Uncertain != 0 {
		t.Fatalf("retention/counts %+v %v", status, err)
	}
	var walBytes int64
	if info, err := os.Stat(filepath.Join(s.directory, "journal.sqlite-wal")); err == nil {
		walBytes = info.Size()
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(s.directory, &fs); err != nil {
		t.Fatal(err)
	}
	t.Logf("backup_ms=%d journal_bytes=%d wal_bytes=%d free_bytes=%d", time.Since(start).Milliseconds(), status.Bytes, walBytes, fs.Bavail*uint64(fs.Bsize))
}

func TestSQLiteReaderReleasesWALAndKeepsHistory(t *testing.T) {
	s := newSQLiteFixture(t)
	db, err := openSQLiteMode(filepath.Join(s.directory, "journal.sqlite"), "ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var namespace string
	if err = tx.QueryRowContext(t.Context(), `SELECT namespace FROM metadata`).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := range 200 {
		if err = s.Use(t.Context(), fmt.Sprintf("retained-%d", i), now.Add(time.Hour), now); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(filepath.Join(s.directory, "journal.sqlite-wal"))
	if err != nil || info.Size() == 0 {
		t.Fatal("WAL growth not observed")
	}
	peak := info.Size()
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(t.Context(), `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(s.directory, "journal.sqlite-wal"))
	if err != nil || info.Size() != 0 {
		t.Fatal("WAL reader was not released")
	}
	if err = s.Use(t.Context(), "retained-0", now.Add(time.Hour), now); !errors.Is(err, ErrReplay) {
		t.Fatal("checkpoint lost retained identity")
	}
	t.Logf("pinned_wal_bytes=%d released_wal_bytes=0 replay_history_retained=true", peak)
}
