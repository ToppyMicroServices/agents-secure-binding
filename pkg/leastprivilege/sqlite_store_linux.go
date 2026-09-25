// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteApplicationID = 0x41534c50

// SQLiteStore is a Linux, single-host execution journal. Indexed operation and
// mandate identities are retained indefinitely; only expired proof nonces are
// deleted. Storage exhaustion fails closed. It is not a replicated authority.
// Mandate and operation IDs must begin with Namespace()+"/". Restoring a backup
// changes that namespace, so authority issued before the restore cannot run.
type SQLiteStore struct {
	db        *sql.DB
	directory string
	namespace string
}

var _ ExecutionStore = (*SQLiteStore)(nil)

func newStoreNamespace() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func privateSQLitePath(directory string) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", ErrStoreUnavailable
	}
	if _, err := os.Lstat(filepath.Join(directory, "restore.pending")); !errors.Is(err, os.ErrNotExist) {
		return "", ErrStoreUnavailable
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", ErrStoreUnavailable
	}
	path := filepath.Join(directory, "journal.sqlite")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err = os.Lstat(path + suffix)
		if suffix != "" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return "", ErrStoreUnavailable
		}
	}
	return path, nil
}

func openSQLiteFile(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := u.Query()
	q.Set("mode", "rw")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, storeError(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// CreateSQLiteStore provisions a new owner-only directory. Failure never resets
// or removes a potentially committed journal. Use OpenSQLiteStore for recovery.
func CreateSQLiteStore(ctx context.Context, directory string) (*SQLiteStore, error) {
	if ctx == nil || !filepath.IsAbs(directory) {
		return nil, ErrStoreUnavailable
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, storeError(err)
	}
	path := filepath.Join(directory, "journal.sqlite")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, storeError(err)
	}
	if err = f.Close(); err != nil {
		return nil, storeError(err)
	}
	db, err := openSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	namespace, err := newStoreNamespace()
	if err != nil {
		return nil, storeError(err)
	}
	statements := []string{
		`BEGIN IMMEDIATE`,
		`CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), namespace TEXT NOT NULL, floor INTEGER NOT NULL, backup INTEGER NOT NULL CHECK(backup IN (0,1)))`,
		`CREATE TABLE operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, mandate TEXT NOT NULL UNIQUE, mandate_digest TEXT NOT NULL, expiry INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACCEPTED','RUNNING','UNKNOWN','SUCCEEDED','FAILED')), evidence TEXT NOT NULL)`,
		`CREATE TABLE uses (id TEXT PRIMARY KEY, expiry INTEGER NOT NULL, operation TEXT UNIQUE REFERENCES operations(id))`,
		`CREATE TABLE mandates (id TEXT PRIMARY KEY, digest TEXT NOT NULL, revoked INTEGER NOT NULL CHECK(revoked IN (0,1)))`,
		`CREATE INDEX expired_nonces ON uses(expiry) WHERE operation IS NULL`,
		`CREATE INDEX operation_states ON operations(state)`,
		fmt.Sprintf(`PRAGMA application_id=%d`, sqliteApplicationID),
		`PRAGMA user_version=1`,
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return nil, storeError(err)
		}
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO metadata VALUES(1,?,0,0)`, namespace); err != nil {
		return nil, storeError(err)
	}
	if _, err = db.ExecContext(ctx, `COMMIT`); err != nil {
		return nil, storeError(err)
	}
	if err = syncDirectory(directory); err != nil {
		return nil, storeError(err)
	}
	if err = syncDirectory(filepath.Dir(directory)); err != nil {
		return nil, storeError(err)
	}
	if err = db.Close(); err != nil {
		return nil, storeError(err)
	}
	return OpenSQLiteStore(ctx, directory)
}

func sqliteMetadata(ctx context.Context, db *sql.DB) (string, int, error) {
	var app, version, backup int
	var integrity, namespace string
	if err := db.QueryRowContext(ctx, `PRAGMA application_id`).Scan(&app); err != nil {
		return "", 0, storeError(err)
	}
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return "", 0, storeError(err)
	}
	if app != sqliteApplicationID || version != 1 {
		return "", 0, ErrStoreUnavailable
	}
	if err := db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return "", 0, ErrStoreUnavailable
	}
	if err := db.QueryRowContext(ctx, `SELECT namespace,backup FROM metadata WHERE id=1`).Scan(&namespace, &backup); err != nil {
		return "", 0, storeError(err)
	}
	raw, err := hex.DecodeString(namespace)
	if err != nil || len(raw) != 16 || namespace != hex.EncodeToString(raw) {
		return "", 0, ErrStoreUnavailable
	}
	return namespace, backup, nil
}

// OpenSQLiteStore never creates missing state, repairs corruption, or opens a
// backup for execution. The parent directory and storage must be operator-owned.
func OpenSQLiteStore(ctx context.Context, directory string) (*SQLiteStore, error) {
	if ctx == nil {
		return nil, ErrStoreUnavailable
	}
	path, err := privateSQLitePath(directory)
	if err != nil {
		return nil, err
	}
	db, err := openSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	namespace, backup, err := sqliteMetadata(ctx, db)
	if err != nil || backup != 0 {
		_ = db.Close()
		return nil, ErrStoreUnavailable
	}
	var mode string
	if err = db.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&mode); err != nil || mode != "wal" {
		_ = db.Close()
		return nil, ErrStoreUnavailable
	}
	return &SQLiteStore{db: db, directory: directory, namespace: namespace}, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	return s.db.Close()
}

func (s *SQLiteStore) Namespace() string {
	if s == nil {
		return ""
	}
	return s.namespace
}

func (s *SQLiteStore) write(ctx context.Context, fn func(*sql.Conn) error) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrStoreUnavailable
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return storeError(err)
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return storeError(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanup, `ROLLBACK`)
	}()
	var namespace string
	var backup int
	if err = conn.QueryRowContext(ctx, `SELECT namespace,backup FROM metadata WHERE id=1`).Scan(&namespace, &backup); err != nil {
		return storeError(err)
	}
	if namespace != s.namespace || backup != 0 {
		return ErrStoreUnavailable
	}
	if err = fn(conn); err != nil {
		return err
	}
	if _, err = conn.ExecContext(ctx, `COMMIT`); err != nil {
		return storeError(err)
	}
	return nil
}

func validSQLTime(t time.Time) bool {
	return !t.IsZero() && t.UnixNano() > 0 && time.Unix(0, t.UnixNano()).Equal(t)
}

func pruneSQLite(ctx context.Context, conn *sql.Conn, now, expiry time.Time) error {
	if !validSQLTime(now) || !validSQLTime(expiry) || !expiry.After(now) {
		return ErrExpired
	}
	var floor int64
	if err := conn.QueryRowContext(ctx, `SELECT floor FROM metadata WHERE id=1`).Scan(&floor); err != nil {
		return storeError(err)
	}
	if now.UnixNano() < floor {
		return ErrExpired
	}
	var expired sql.NullInt64
	if err := conn.QueryRowContext(ctx, `SELECT max(expiry) FROM uses WHERE operation IS NULL AND expiry<=?`, now.UnixNano()).Scan(&expired); err != nil {
		return storeError(err)
	}
	if expired.Valid && expired.Int64 > floor {
		if _, err := conn.ExecContext(ctx, `UPDATE metadata SET floor=? WHERE id=1`, expired.Int64); err != nil {
			return storeError(err)
		}
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM uses WHERE operation IS NULL AND expiry<=?`, now.UnixNano()); err != nil {
		return storeError(err)
	}
	return nil
}

func (s *SQLiteStore) Use(ctx context.Context, key string, expiry, now time.Time) error {
	if !boundedText(key, 512) {
		return ErrInvalidCapability
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		if err := pruneSQLite(ctx, conn, now, expiry); err != nil {
			return err
		}
		var found int
		if err := conn.QueryRowContext(ctx, `SELECT 1 FROM uses WHERE id=?`, key).Scan(&found); err == nil {
			return ErrReplay
		} else if !errors.Is(err, sql.ErrNoRows) {
			return storeError(err)
		}
		_, err := conn.ExecContext(ctx, `INSERT INTO uses(id,expiry) VALUES(?,?)`, key, expiry.UnixNano())
		return storeError(err)
	})
}

func querySQLiteExecution(ctx context.Context, conn *sql.Conn, id, digest string) (ExecutionRecord, error) {
	if !boundedText(id, 256) || !canonicalDigest(digest) {
		return ExecutionRecord{}, ErrBinding
	}
	var r ExecutionRecord
	var expiry int64
	err := conn.QueryRowContext(ctx, `SELECT id,digest,mandate,mandate_digest,expiry,state,evidence FROM operations WHERE id=?`, id).Scan(&r.OperationID, &r.RequestDigest, &r.MandateID, &r.MandateDigest, &expiry, &r.State, &r.EvidenceDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrExecutionNotFound
	}
	if err != nil {
		return r, storeError(err)
	}
	if r.RequestDigest != digest {
		return ExecutionRecord{}, ErrExecutionConflict
	}
	r.ExpiresAt = time.Unix(0, expiry).UTC()
	if !canonicalDigest(r.MandateDigest) || !boundedText(r.MandateID, 256) || !validSQLTime(r.ExpiresAt) {
		return ExecutionRecord{}, ErrStoreUnavailable
	}
	return r, nil
}

func (s *SQLiteStore) Prepare(ctx context.Context, id string, cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time) (ExecutionRecord, bool, error) {
	if s == nil || !strings.HasPrefix(id, s.namespace+"/") || !strings.HasPrefix(current.ID, s.namespace+"/") {
		return ExecutionRecord{}, false, ErrBinding
	}
	if err := CheckCapability(cap, key, current, request, now); err != nil {
		return ExecutionRecord{}, false, err
	}
	digest, err := DigestExecution(id, current, request)
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	md, err := DigestMandate(current)
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	var r ExecutionRecord
	created := false
	err = s.write(ctx, func(conn *sql.Conn) error {
		if err := pruneSQLite(ctx, conn, now, current.ExpiresAt); err != nil {
			return err
		}
		old, err := querySQLiteExecution(ctx, conn, id, digest)
		if err == nil {
			r = old
			return nil
		}
		if !errors.Is(err, ErrExecutionNotFound) {
			return err
		}
		useID := "asb.least-privilege/" + current.ID
		var found int
		if err := conn.QueryRowContext(ctx, `SELECT 1 FROM uses WHERE id=?`, useID).Scan(&found); err == nil {
			return ErrReplay
		} else if !errors.Is(err, sql.ErrNoRows) {
			return storeError(err)
		}
		r = ExecutionRecord{OperationID: id, RequestDigest: digest, MandateID: current.ID, MandateDigest: md, ExpiresAt: current.ExpiresAt.UTC(), State: ExecutionAccepted}
		if _, err := conn.ExecContext(ctx, `INSERT INTO operations VALUES(?,?,?,?,?,?,?)`, id, digest, current.ID, md, current.ExpiresAt.UnixNano(), string(ExecutionAccepted), ""); err != nil {
			return storeError(err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO uses VALUES(?,?,?)`, useID, current.ExpiresAt.UnixNano(), id); err != nil {
			return storeError(err)
		}
		created = true
		return nil
	})
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	return r, created, nil
}

func (s *SQLiteStore) Lookup(ctx context.Context, id, digest string) (ExecutionRecord, error) {
	var r ExecutionRecord
	err := s.write(ctx, func(conn *sql.Conn) error {
		var err error
		r, err = querySQLiteExecution(ctx, conn, id, digest)
		return err
	})
	return r, err
}

func (s *SQLiteStore) Start(ctx context.Context, id, digest string) (ExecutionRecord, bool, error) {
	var r ExecutionRecord
	started := false
	err := s.write(ctx, func(conn *sql.Conn) error {
		var err error
		r, err = querySQLiteExecution(ctx, conn, id, digest)
		if err != nil {
			return err
		}
		if r.State != ExecutionAccepted {
			return nil
		}
		if !strings.HasPrefix(r.MandateID, s.namespace+"/") || !strings.HasPrefix(id, s.namespace+"/") {
			return ErrBinding
		}
		_, err = conn.ExecContext(ctx, `UPDATE operations SET state=? WHERE id=?`, string(ExecutionRunning), id)
		if err != nil {
			return storeError(err)
		}
		r.State = ExecutionRunning
		started = true
		return nil
	})
	if err != nil {
		return ExecutionRecord{}, false, err
	}
	return r, started, nil
}

func (s *SQLiteStore) Complete(ctx context.Context, id, digest string, outcome ExecutionState, evidence string) (ExecutionRecord, error) {
	if outcome != ExecutionUnknown && outcome != ExecutionSucceeded && outcome != ExecutionFailed {
		return ExecutionRecord{}, ErrExecutionConflict
	}
	if (outcome != ExecutionUnknown && !canonicalDigest(evidence)) || (evidence != "" && !canonicalDigest(evidence)) {
		return ExecutionRecord{}, ErrBinding
	}
	var r ExecutionRecord
	err := s.write(ctx, func(conn *sql.Conn) error {
		var err error
		r, err = querySQLiteExecution(ctx, conn, id, digest)
		if err != nil {
			return err
		}
		if r.State == ExecutionAccepted {
			return ErrExecutionConflict
		}
		if r.Terminal() {
			if r.State != outcome || r.EvidenceDigest != evidence {
				return ErrExecutionConflict
			}
			return nil
		}
		if _, err = conn.ExecContext(ctx, `UPDATE operations SET state=?,evidence=? WHERE id=?`, string(outcome), evidence, id); err != nil {
			return storeError(err)
		}
		r.State = outcome
		r.EvidenceDigest = evidence
		return nil
	})
	return r, err
}

func (s *SQLiteStore) CancelAccepted(ctx context.Context, id, digest string) (ExecutionRecord, error) {
	evidence, err := digestValue("asb.least-privilege.canceled-before-dispatch/v1", struct{ OperationID, RequestDigest string }{id, digest})
	if err != nil {
		return ExecutionRecord{}, err
	}
	var r ExecutionRecord
	err = s.write(ctx, func(conn *sql.Conn) error {
		var err error
		r, err = querySQLiteExecution(ctx, conn, id, digest)
		if err != nil {
			return err
		}
		if r.State == ExecutionFailed && r.EvidenceDigest == evidence {
			return nil
		}
		if r.State != ExecutionAccepted {
			return ErrExecutionConflict
		}
		if _, err = conn.ExecContext(ctx, `UPDATE operations SET state=?,evidence=? WHERE id=?`, string(ExecutionFailed), evidence, id); err != nil {
			return storeError(err)
		}
		r.State = ExecutionFailed
		r.EvidenceDigest = evidence
		return nil
	})
	return r, err
}

func (s *SQLiteStore) Run(ctx context.Context, id string, cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time, effect Effect) (ExecutionRecord, error) {
	return runExecution(ctx, s, id, cap, key, current, request, now, effect)
}

// SQLiteStatus contains counts and storage sizes, never action arguments or keys.
type SQLiteStatus struct {
	Namespace     string `json:"namespace"`
	Operations    int64  `json:"operations"`
	Uncertain     int64  `json:"uncertain"`
	Accepted      int64  `json:"accepted"`
	ReplayRecords int64  `json:"replay_records"`
	Bytes         int64  `json:"bytes"`
}

func (s *SQLiteStore) Status(ctx context.Context) (SQLiteStatus, error) {
	result := SQLiteStatus{Namespace: s.Namespace()}
	err := s.write(ctx, func(conn *sql.Conn) error {
		for _, query := range []struct {
			sql string
			out *int64
		}{
			{`SELECT count(*) FROM operations`, &result.Operations},
			{`SELECT count(*) FROM operations WHERE state IN ('RUNNING','UNKNOWN')`, &result.Uncertain},
			{`SELECT count(*) FROM operations WHERE state='ACCEPTED'`, &result.Accepted},
			{`SELECT count(*) FROM uses`, &result.ReplayRecords},
		} {
			if err := conn.QueryRowContext(ctx, query.sql).Scan(query.out); err != nil {
				return storeError(err)
			}
		}
		return nil
	})
	if err != nil {
		return SQLiteStatus{}, err
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Lstat(filepath.Join(s.directory, "journal.sqlite") + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return SQLiteStatus{}, storeError(err)
		}
		result.Bytes += info.Size()
	}
	return result, nil
}
