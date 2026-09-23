// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package sqlitestore provides a single-host durable TaskCoord and Action
// transaction boundary. SQLite serializes independent processes. This adapter
// does not cover external effects, network filesystems, or database rollback.
package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
	_ "modernc.org/sqlite"
)

const (
	applicationID = 0x41534243
	maxStateBytes = 32 << 20
)

// Store persists the reference state machines and their immutable retry
// evidence. Every write obtains a SQLite write reservation BEFORE loading any
// state. Action validation receives Assignments from that same transaction;
// no independently persisted Assignment copy participates in authorization.
// State snapshots make this a bounded adapter, not a high-volume database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens a private local database. The containing directory must be owned
// by the deployment and must not be on a network filesystem. Existing database
// files must be regular files accessible only to their owner.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, unavailable(errors.New("database path required"))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, unavailable(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, unavailable(err)
	}
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = f.Close()
	} else if errors.Is(err, os.ErrExist) {
		err = nil
	}
	if err != nil {
		return nil, unavailable(err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, unavailable(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, unavailable(errors.New("database must be an owner-only regular file"))
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	q := u.Query()
	// DSN pragmas apply again if database/sql replaces a connection.
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(1)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, unavailable(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return unavailable(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return unavailable(err)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	var version, app int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return unavailable(err)
	}
	if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return unavailable(err)
	}
	if version == 0 && app == 0 {
		var count int
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
			return unavailable(err)
		}
		if count != 0 {
			return unavailable(errors.New("unrecognized database"))
		}
		for _, statement := range []string{
			`CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), tasks BLOB NOT NULL, actions BLOB NOT NULL)`,
			`INSERT INTO state VALUES (1, X'', X'')`,
			`CREATE TABLE replay (key TEXT PRIMARY KEY, expires INTEGER NOT NULL)`,
			`CREATE TABLE outcomes (id TEXT PRIMARY KEY, document BLOB NOT NULL)`,
			`CREATE TABLE outbox (id TEXT PRIMARY KEY, document BLOB NOT NULL, consumer TEXT NOT NULL DEFAULT '', lease TEXT NOT NULL DEFAULT '', expires INTEGER NOT NULL DEFAULT 0, acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)))`,
			`CREATE TABLE outbox_leases (id TEXT PRIMARY KEY)`,
			fmt.Sprintf("PRAGMA application_id = %d", applicationID),
			`PRAGMA user_version = 1`,
		} {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return unavailable(err)
			}
		}
	} else if version != 1 || app != applicationID {
		return unavailable(errors.New("unsupported database schema"))
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return unavailable(err)
	}
	var mode string
	if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
		return unavailable(err)
	}
	if mode != "wal" {
		return unavailable(errors.New("WAL mode unavailable"))
	}
	return nil
}

// Close releases this handle. Other processes and handles retain their state.
func (s *Store) Close() error { return s.db.Close() }

type transaction struct {
	*taskcoord.MemoryStore
	actions *actionbinding.MemoryStore
	conn    *sql.Conn
	ctx     context.Context
	now     func() time.Time
	failed  error
}

func unavailable(err error) error { return fmt.Errorf("%w: %v", taskcoord.ErrStoreUnavailable, err) }

func (s *Store) run(ctx context.Context, write bool, fn func(*transaction) error) error {
	if ctx == nil {
		return unavailable(errors.New("missing context"))
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return unavailable(err)
	}
	defer func() { _ = conn.Close() }()
	begin := "BEGIN"
	if write {
		begin = "BEGIN IMMEDIATE"
	}
	if _, err := conn.ExecContext(ctx, begin); err != nil {
		return unavailable(err)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	var tasks, actions []byte
	if err := conn.QueryRowContext(ctx, "SELECT tasks, actions FROM state WHERE id=1").Scan(&tasks, &actions); err != nil {
		return unavailable(err)
	}
	if len(tasks) > maxStateBytes || len(actions) > maxStateBytes {
		return taskcoord.ErrStoreLimit
	}
	taskState, err := taskcoord.RestoreMemoryStore(tasks)
	if err != nil {
		return unavailable(err)
	}
	actionState, err := actionbinding.RestoreMemoryStore(actions, taskState.Assignments(), s.now)
	if err != nil {
		return unavailable(err)
	}
	tx := &transaction{MemoryStore: taskState, actions: actionState, conn: conn, ctx: ctx, now: s.now}
	if err := fn(tx); err != nil {
		return err
	}
	if tx.failed != nil {
		return tx.failed
	}
	if write {
		tasks, err = tx.MemoryStore.ExportState()
		if err != nil {
			return unavailable(err)
		}
		actions, err = tx.actions.ExportState()
		if err != nil {
			return unavailable(err)
		}
		if len(tasks) > maxStateBytes || len(actions) > maxStateBytes {
			return taskcoord.ErrStoreLimit
		}
		if _, err := conn.ExecContext(ctx, "UPDATE state SET tasks=?, actions=? WHERE id=1", tasks, actions); err != nil {
			return unavailable(err)
		}
	}
	// A commit error is unknown to the caller. It must recover by stable
	// operation/event identity, never assume that repeating an effect is safe.
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return unavailable(err)
	}
	return nil
}

// RunHumanTransaction joins verifier replay, operation outcome, mutation and
// outbox in one transaction. The callback must not call Store methods, perform
// network I/O, or retain its transaction after returning. Any callback error
// rolls back every write. Callbacks receive trusted in-process APIs only.
func (s *Store) RunHumanTransaction(ctx context.Context, fn func(asbbinding.HumanTransaction) error) error {
	if fn == nil {
		return unavailable(errors.New("missing transaction callback"))
	}
	return s.run(ctx, true, func(tx *transaction) error { return fn(tx) })
}

var (
	_ taskcoord.Store                  = (*Store)(nil)
	_ taskcoord.OutboxStore            = (*Store)(nil)
	_ actionbinding.Store              = (*Store)(nil)
	_ asbbinding.HumanTransactionStore = (*Store)(nil)
)
