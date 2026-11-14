// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package protectedchange

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	_ "modernc.org/sqlite"
)

var ErrStoreUnavailable = errors.New("protected change: outcome store unavailable")

const (
	changeStoreApplicationID = 0x41534250 // ASBP, separate from TaskCoord's ASBC
	goosWindows              = "windows"
)

// SQLiteChangeStore commits a local configuration setting and its immutable
// receipt in the same transaction. It does not make remote effects atomic.
// Use a caller-owned private directory on a local filesystem, and retain both
// this database and the independent ASB replay store across service restarts.
type SQLiteChangeStore struct {
	db *sql.DB
}

// OpenSQLiteChangeStore opens a private, non-symlink database file. The immediate
// parent directory must already exist and remain trusted. Unix permissions must
// be owner-only; on Windows the caller must provide an owner-only directory ACL.
func OpenSQLiteChangeStore(ctx context.Context, path string) (*SQLiteChangeStore, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: require context and absolute clean path", ErrStoreUnavailable)
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || runtime.GOOS != goosWindows && parent.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: require a private parent directory", ErrStoreUnavailable)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		err = file.Close()
	} else if errors.Is(err, os.ErrExist) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || runtime.GOOS != goosWindows && info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: require private regular database file", ErrStoreUnavailable)
		}
		err = nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	dsn := sqliteChangeDSN(filepath.ToSlash(path), filepath.VolumeName(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteChangeStore{db: db}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func sqliteChangeDSN(databasePath, volume string) string {
	// A Windows drive must be a URL path, not the URI's authority component.
	if volume != "" && !strings.HasPrefix(databasePath, "/") {
		databasePath = "/" + databasePath
	}
	u := url.URL{Scheme: "file", Path: databasePath}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *SQLiteChangeStore) initialize(ctx context.Context) error {
	return s.write(ctx, func(conn *sql.Conn) error {
		var appID, version int
		if err := conn.QueryRowContext(ctx, "PRAGMA application_id").Scan(&appID); err != nil {
			return err
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
			return err
		}
		if appID == changeStoreApplicationID && version == 1 {
			return nil
		}
		var tables int
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return err
		}
		if appID != 0 || version != 0 || tables != 0 {
			return fmt.Errorf("%w: unsupported database", ErrStoreUnavailable)
		}
		for _, statement := range []string{
			`CREATE TABLE change_outcomes (change_id TEXT PRIMARY KEY, change_json TEXT NOT NULL, identity_json TEXT NOT NULL)`,
			`CREATE TABLE tenant_settings (tenant TEXT NOT NULL, setting TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), PRIMARY KEY(tenant,setting))`,
			fmt.Sprintf("PRAGMA application_id = %d", changeStoreApplicationID),
			"PRAGMA user_version = 1",
		} {
			if _, err := conn.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		return nil
	})
}

// Close releases this handle. Closing does not delete receipts or settings.
func (s *SQLiteChangeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Apply commits the local setting and receipt, or accepts an exact idempotent
// match. A renewed proof may change expiry times but not the recorded identity.
func (s *SQLiteChangeStore) Apply(ctx context.Context, change ChangeRequest, identity production.AcceptedIdentity) error {
	if err := validateChange(change); err != nil {
		return err
	}
	if identity.Issuer == "" || identity.Agent == "" || identity.TaskID != change.ChangeID {
		return ErrChangeConflict
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		existing, found, err := readOutcome(ctx, conn, change.ChangeID)
		if err != nil {
			return err
		}
		if found {
			if existing.Change == change && acceptedIdentityEqual(existing.Identity, identity) {
				return nil
			}
			return ErrChangeConflict
		}
		changeJSON, err := json.Marshal(change)
		if err != nil {
			return err
		}
		identityJSON, err := json.Marshal(identity)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO change_outcomes(change_id,change_json,identity_json) VALUES(?,?,?)`, change.ChangeID, string(changeJSON), string(identityJSON)); err != nil {
			return err
		}
		_, err = conn.ExecContext(ctx, `INSERT INTO tenant_settings(tenant,setting,enabled) VALUES(?,?,?) ON CONFLICT(tenant,setting) DO UPDATE SET enabled=excluded.enabled`, change.Tenant, change.Setting, change.Enabled)
		return err
	})
}

// Outcome reports the historical local commit for the full original change and
// its original issuer, Actor, task, and delegation. The endpoint separately
// verifies the lookup's read scope, capability, and exact request binding.
func (s *SQLiteChangeStore) Outcome(ctx context.Context, change ChangeRequest, viewer production.AcceptedIdentity) (bool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return false, ErrStoreUnavailable
	}
	if err := validateChange(change); err != nil {
		return false, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	record, found, err := readOutcome(ctx, conn, change.ChangeID)
	if err != nil || !found {
		return false, err
	}
	owner := record.Identity
	if record.Change != change || owner.Issuer != viewer.Issuer || owner.Agent != viewer.Agent || owner.TaskID != viewer.TaskID || owner.DelegationID != viewer.DelegationID {
		return false, ErrChangeConflict
	}
	return true, nil
}

func readOutcome(ctx context.Context, conn *sql.Conn, changeID string) (AppliedChange, bool, error) {
	var changeJSON, identityJSON string
	err := conn.QueryRowContext(ctx, "SELECT change_json,identity_json FROM change_outcomes WHERE change_id=?", changeID).Scan(&changeJSON, &identityJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return AppliedChange{}, false, nil
	}
	if err != nil {
		return AppliedChange{}, false, err
	}
	var result AppliedChange
	if err := json.Unmarshal([]byte(changeJSON), &result.Change); err != nil {
		return AppliedChange{}, false, err
	}
	if err := json.Unmarshal([]byte(identityJSON), &result.Identity); err != nil {
		return AppliedChange{}, false, err
	}
	if err := validateChange(result.Change); err != nil || result.Change.ChangeID != changeID || result.Identity.TaskID != changeID || result.Identity.Issuer == "" || result.Identity.Agent == "" {
		return AppliedChange{}, false, fmt.Errorf("%w: inconsistent receipt", ErrStoreUnavailable)
	}
	return result, true, nil
}

func (s *SQLiteChangeStore) write(ctx context.Context, action func(*sql.Conn) error) error {
	if s == nil || s.db == nil || ctx == nil {
		return ErrStoreUnavailable
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	if err := action(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}
