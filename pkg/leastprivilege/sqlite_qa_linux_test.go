// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteMonitoringDoesNotWaitForWriter(t *testing.T) {
	s := newSQLiteFixture(t)
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(t.Context(), `ROLLBACK`) //nolint:errcheck // Fixture cleanup.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	start := time.Now()
	status, err := s.Status(ctx)
	if err != nil || status.Namespace != s.Namespace() {
		t.Fatalf("monitor blocked on writer: %+v %v", status, err)
	}
	if _, err = ReadSQLiteHealth(ctx, s.directory); err != nil {
		t.Fatal(err)
	}
	t.Logf("monitor_while_writer_locked_ms=%d", time.Since(start).Milliseconds())
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err = s.Status(canceled); err == nil {
		t.Fatal("canceled monitor accepted")
	}
}

func TestSQLiteMonitoringRejectsSealedAndChangedNamespace(t *testing.T) {
	s := newSQLiteFixture(t)
	if _, err := s.db.ExecContext(t.Context(), `UPDATE metadata SET backup=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Status(t.Context()); err == nil {
		t.Fatal("sealed journal monitored as active")
	}
	if _, err := s.db.ExecContext(t.Context(), `UPDATE metadata SET backup=0, namespace=?`, "00000000000000000000000000000000"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Status(t.Context()); err == nil {
		t.Fatal("namespace change accepted")
	}
}

func TestSQLiteLockCancellationRecovers(t *testing.T) {
	s := newSQLiteFixture(t)
	other, err := OpenSQLiteStore(t.Context(), s.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err = other.db.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	start := time.Now()
	err = s.Use(ctx, "blocked", time.Now().Add(time.Hour), time.Now())
	cancel()
	if err == nil {
		t.Fatal("writer lock did not prevent admission")
	}
	if _, err = other.db.ExecContext(t.Context(), `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if err = s.Use(t.Context(), "recovered", time.Now().Add(time.Hour), time.Now()); err != nil {
		t.Fatalf("connection did not recover: %v", err)
	}
	if time.Since(start) > 7*time.Second {
		t.Fatal("lock/cancel exceeded busy timeout plus cleanup allowance")
	}
	t.Logf("lock_cancel_and_recovery_ms=%d", time.Since(start).Milliseconds())
}

func privateBackupDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestSQLiteBackupRecoveryPreservesPublishedAndActiveFiles(t *testing.T) {
	s := newSQLiteFixture(t)
	directory := privateBackupDirectory(t)
	published := filepath.Join(directory, "snapshot.sqlite")
	manifest, err := s.Backup(t.Context(), published)
	if err != nil {
		t.Fatal(err)
	}
	alias, err := newBackupWorkspace(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(directory, ".asb-s3-backup-101")
	if err = os.Link(published, legacy); err != nil {
		t.Fatal(err)
	}
	if err = os.Link(published, alias); err != nil {
		t.Fatal(err)
	}
	partial, err := newBackupWorkspace(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(partial, bytes.Repeat([]byte{1}, 8192), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := backupLock(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RecoverSQLiteBackups(t.Context(), directory); err == nil {
		t.Fatal("active backup was not excluded")
	}
	if _, err = os.Stat(partial); err != nil {
		t.Fatal("active output removed")
	}
	_ = lock.Close()
	recovered, err := RecoverSQLiteBackups(t.Context(), directory)
	if err != nil || recovered.Removed != 2 || recovered.ReclaimedBytes < 8192 {
		t.Fatalf("recovery: %+v %v", recovered, err)
	}
	restored, err := RestoreSQLiteStore(t.Context(), published, filepath.Join(t.TempDir(), "restore"), manifest.SHA256)
	if err != nil {
		t.Fatal("published snapshot damaged", err)
	}
	_ = restored.Close()
	if _, err = os.Stat(legacy); err != nil {
		t.Fatal("legacy snapshot inferred to be garbage", err)
	}
	alias, err = newBackupWorkspace(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(published, alias); err != nil {
		t.Fatal(err)
	}
	if _, err = RecoverSQLiteBackups(t.Context(), directory); err == nil {
		t.Fatal("symlink accepted as owned temporary")
	}
	if _, err = os.Stat(published); err != nil {
		t.Fatal(err)
	}
}

type cancelingReader struct {
	cancel    context.CancelFunc
	remaining int64
}

func (r *cancelingReader) Read(b []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(b)), r.remaining)
	r.remaining -= n
	r.cancel()
	return int(n), nil
}

func TestSQLiteCopyCancellationDoesNotPublishOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	n, err := copySQLiteContext(ctx, &out, &cancelingReader{cancel: cancel, remaining: 1 << 30})
	if !errors.Is(err, context.Canceled) || n != 0 || out.Len() != 0 {
		t.Fatalf("copy ignored cancellation: %d %v", n, err)
	}
	t.Logf("copy_cancel_ms=%d", time.Since(start).Milliseconds())
	s := newSQLiteFixture(t)
	path := filepath.Join(privateBackupDirectory(t), "snapshot.sqlite")
	if _, err = s.Backup(ctx, path); err == nil {
		t.Fatal("canceled backup succeeded")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("canceled backup published")
	}
	directory := filepath.Join(t.TempDir(), "incomplete")
	source := filepath.Join(t.TempDir(), "source")
	if err = os.WriteFile(source, bytes.Repeat([]byte{1}, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreSQLiteStore(ctx, source, directory, fmt.Sprintf("%064d", 0)); err == nil {
		t.Fatal("canceled restore succeeded")
	}
	if _, err = OpenSQLiteStore(t.Context(), directory); err == nil {
		t.Fatal("incomplete restore became active")
	}
}

func TestSQLiteBackupCrashBoundaries(t *testing.T) {
	if stage := os.Getenv("ASB_QA_BACKUP_STAGE"); stage != "" {
		s, err := OpenSQLiteStore(t.Context(), os.Getenv("ASB_QA_STORE"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		_, err = s.backup(t.Context(), os.Getenv("ASB_QA_SNAPSHOT"), func(current string) {
			if current == stage {
				fmt.Println("backup-checkpoint")
				for {
					time.Sleep(time.Second)
				}
			}
		})
		t.Fatal("child failed to reach checkpoint", err)
	}
	for _, stage := range []string{"created", "snapshot", "sealed", "published"} {
		t.Run(stage, func(t *testing.T) {
			s := newSQLiteFixture(t)
			directory := privateBackupDirectory(t)
			good := filepath.Join(directory, "existing.sqlite")
			manifest, err := s.Backup(t.Context(), good)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(directory, "interrupted.sqlite")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteBackupCrashBoundaries$")
			cmd.Env = append(os.Environ(), "ASB_QA_BACKUP_STAGE="+stage, "ASB_QA_STORE="+s.directory, "ASB_QA_SNAPSHOT="+output)
			pipe, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(pipe)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == "backup-checkpoint" {
					reached = true
					break
				}
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if !reached {
				t.Fatal("checkpoint not observed")
			}
			recovery, err := RecoverSQLiteBackups(t.Context(), directory)
			if err != nil || recovery.Removed < 1 {
				t.Fatalf("no orphan recovered: %+v %v", recovery, err)
			}
			if stage == "published" && recovery.ReclaimedBytes != 0 {
				t.Fatal("published alias counted as a second data copy")
			}
			restored, err := RestoreSQLiteStore(t.Context(), good, filepath.Join(t.TempDir(), "verified"), manifest.SHA256)
			if err != nil {
				t.Fatal("existing snapshot damaged", err)
			}
			_ = restored.Close()
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if backupTemporaryName.MatchString(entry.Name()) {
					t.Fatal("temporary retained")
				}
			}
			t.Logf("stage=%s removed=%d reclaimed_bytes=%d existing_backup_readable=true", stage, recovery.Removed, recovery.ReclaimedBytes)
			if stage == "published" {
				raw, err := os.ReadFile(output)
				if err != nil || !strings.HasPrefix(string(raw), "SQLite format 3") {
					t.Fatal("published snapshot removed")
				}
			}
		})
	}
}
