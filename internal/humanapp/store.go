// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	_ "modernc.org/sqlite"
)

const (
	storeSchemaVersion = 1
	storeApplicationID = 0x41534248
	maxMutationRecords = 10_000
	// Every admitted proposal reserves one receipt for its terminal decision.
	maxProposalRecords = maxMutationRecords / 2
	maxReplayRecords   = 100_000
	maxInboxOperations = 100
	maxSettingRevision = (1 << 53) - 1
)

// Store owns the local setting, approvals, replay records, and original
// mutation responses. It is application storage, not a generic TaskCoord or
// operationjournal adapter. Only effects inside this database are atomic.
type Store struct {
	db           *sql.DB
	now          func() time.Time
	beforeCommit func() error
}

// OpenStore opens an application database without replacing existing state.
// SQLite coordinates concurrent transactions; the process uses one connection
// so authentication and the resulting application write have one owner.
func OpenStore(path string) (*Store, error) {
	return OpenStoreContext(context.Background(), path)
}

// OpenStoreContext opens a database with bounded, cancelable initialization.
func OpenStoreContext(ctx context.Context, path string) (*Store, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, storeError(err)
	}
	if strings.TrimSpace(path) == "" {
		return nil, ErrInvalid
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, storeError(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, storeError(err)
	}
	file, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, storeError(err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, storeError(err)
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: database must be a regular file", ErrUnavailable)
	}
	databasePath := filepath.ToSlash(abs)
	if filepath.VolumeName(abs) != "" && !strings.HasPrefix(databasePath, "/") {
		databasePath = "/" + databasePath
	}
	dsn := (&url.URL{Scheme: "file", Path: databasePath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, storeError(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, now: time.Now}
	if err := store.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return storeError(err)
	}
	var version, applicationID int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return storeError(err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&applicationID); err != nil {
		return storeError(err)
	}
	if version != 0 && (version != storeSchemaVersion || applicationID != storeApplicationID) {
		return fmt.Errorf("%w: unsupported database schema", ErrUnavailable)
	}
	if version == 0 {
		var tables int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&tables); err != nil {
			return storeError(err)
		}
		if applicationID != 0 || tables != 0 {
			return fmt.Errorf("%w: unrecognized database", ErrUnavailable)
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return storeError(err)
		}
		defer func() { _ = tx.Rollback() }()
		statements := []string{
			`CREATE TABLE setting (id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), revision INTEGER NOT NULL CHECK (revision BETWEEN 0 AND 9007199254740991))`,
			`INSERT INTO setting (id, enabled, revision) VALUES (1, 0, 0)`,
			`CREATE TABLE operations (operation_id TEXT PRIMARY KEY, proposal_digest TEXT NOT NULL, proposal BLOB NOT NULL, document BLOB NOT NULL, created_at INTEGER NOT NULL)`,
			`CREATE TABLE commands (actor TEXT NOT NULL, command_id TEXT NOT NULL, request BLOB NOT NULL, response BLOB NOT NULL, identity BLOB NOT NULL, PRIMARY KEY (actor, command_id))`,
			`CREATE TABLE replay (replay_key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)`,
			`CREATE INDEX replay_expiry ON replay (expires_at)`,
			`CREATE INDEX operation_created ON operations (created_at DESC, operation_id)`,
			fmt.Sprintf("PRAGMA application_id = %d", storeApplicationID),
			fmt.Sprintf("PRAGMA user_version = %d", storeSchemaVersion),
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return storeError(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return storeError(err)
		}
	}
	for _, pragma := range []string{"PRAGMA journal_mode = WAL", "PRAGMA synchronous = FULL", "PRAGMA foreign_keys = ON"} {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return storeError(err)
		}
	}
	var check string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fmt.Errorf("%w: database integrity check failed", ErrUnavailable)
	}
	return nil
}

// Close releases the database. Committed operations remain available on reopen.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Execute authenticates before reading application state. The supplied
// authenticator must mark exactly one fresh replay key. Replay, any effect, and
// the original mutation response commit together before bytes are released.
// STATUS and INBOX are fresh reads; mutation retries retain their first result.
func (s *Store) Execute(ctx context.Context, command Command, authenticate Authenticator) ([]byte, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if authenticate == nil {
		return nil, ErrUnauthorized
	}
	if command.Change != nil {
		change := *command.Change
		command.Change = &change
	}
	if err := command.Validate(); err != nil {
		return nil, err
	}
	request, err := json.Marshal(command)
	if err != nil {
		return nil, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, storeError(err)
	}
	defer func() { _ = tx.Rollback() }()
	clock := s.now
	if clock == nil {
		clock = time.Now
	}
	replay := &transactionReplay{ctx: ctx, tx: tx, now: clock}
	identity, err := authenticate(replay)
	if err != nil {
		return nil, err
	}
	if replay.calls != 1 || !replay.marked || !ActorAllowed(identity.Agent, command.Kind) {
		return nil, ErrUnauthorized
	}
	var response []byte
	if command.Mutation() {
		var previousRequest []byte
		err := tx.QueryRowContext(ctx, "SELECT request, response FROM commands WHERE actor = ? AND command_id = ?", identity.Agent, command.CommandID).Scan(&previousRequest, &response)
		switch {
		case err == nil:
			if !bytes.Equal(previousRequest, request) {
				return nil, ErrConflict
			}
			if !json.Valid(response) {
				return nil, storeError(errors.New("invalid stored response"))
			}
		case errors.Is(err, sql.ErrNoRows):
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM commands").Scan(&count); err != nil {
				return nil, storeError(err)
			}
			if count >= maxMutationRecords {
				return nil, fmt.Errorf("%w: mutation record limit reached", ErrUnavailable)
			}
		default:
			return nil, storeError(err)
		}
	}
	if response == nil {
		result, err := executeCommand(ctx, tx, command, identity.Agent, request, clock().UTC())
		if err != nil {
			return nil, err
		}
		response, err = json.Marshal(result)
		if err != nil {
			return nil, storeError(err)
		}
		response = append(response, '\n')
		if command.Mutation() {
			accepted, err := json.Marshal(identity)
			if err != nil {
				return nil, storeError(err)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO commands (actor, command_id, request, response, identity) VALUES (?, ?, ?, ?, ?)", identity.Agent, command.CommandID, request, response, accepted); err != nil {
				return nil, storeError(err)
			}
		}
	}
	if s.beforeCommit != nil {
		if err := s.beforeCommit(); err != nil {
			return nil, storeError(err)
		}
	}
	if !clock().Before(replay.expiresAt) {
		return nil, ErrUnauthorized
	}
	if err := tx.Commit(); err != nil {
		return nil, storeError(err)
	}
	return response, nil
}

type transactionReplay struct {
	ctx       context.Context
	tx        *sql.Tx
	now       func() time.Time
	calls     int
	marked    bool
	expiresAt time.Time
}

func (r *transactionReplay) MarkUsed(key string, expiresAt time.Time) error {
	r.calls++
	if r.calls != 1 {
		return identitypolicy.ErrReplayDetected
	}
	now := r.now().UTC()
	if strings.TrimSpace(key) == "" || len(key) > MaxRequestBytes || expiresAt.IsZero() || !now.Before(expiresAt) {
		return identitypolicy.ErrReplayUnavailable
	}
	if _, err := r.tx.ExecContext(r.ctx, "DELETE FROM replay WHERE expires_at <= ?", now.UnixNano()); err != nil {
		return storeError(err)
	}
	digest := sha256.Sum256([]byte(key))
	replayKey := hex.EncodeToString(digest[:])
	var exists int
	err := r.tx.QueryRowContext(r.ctx, "SELECT 1 FROM replay WHERE replay_key = ?", replayKey).Scan(&exists)
	if err == nil {
		return identitypolicy.ErrReplayDetected
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return storeError(err)
	}
	var count int
	if err := r.tx.QueryRowContext(r.ctx, "SELECT count(*) FROM replay").Scan(&count); err != nil {
		return storeError(err)
	}
	if count >= maxReplayRecords {
		return fmt.Errorf("%w: replay record limit reached", ErrUnavailable)
	}
	if _, err := r.tx.ExecContext(r.ctx, "INSERT INTO replay (replay_key, expires_at) VALUES (?, ?)", replayKey, expiresAt.UTC().UnixNano()); err != nil {
		return storeError(err)
	}
	r.marked = true
	r.expiresAt = expiresAt
	return nil
}

func executeCommand(ctx context.Context, tx *sql.Tx, command Command, actor string, request []byte, now time.Time) (Response, error) {
	setting, err := loadSetting(ctx, tx)
	if err != nil {
		return Response{}, err
	}
	response := Response{CommandID: command.CommandID, Setting: &setting}
	switch command.Kind {
	case KindInbox:
		response.Operations, response.Inbox, err = loadInbox(ctx, tx)
		return response, err
	case KindPropose:
		if command.ExpectedRevision != setting.Revision {
			return Response{}, ErrConflict
		}
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM operations WHERE operation_id = ?", command.OperationID).Scan(&exists)
		if err == nil {
			return Response{}, ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Response{}, storeError(err)
		}
		var proposals int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations").Scan(&proposals); err != nil {
			return Response{}, storeError(err)
		}
		if proposals >= maxProposalRecords {
			return Response{}, fmt.Errorf("%w: proposal limit reached; existing proposals can still be decided", ErrUnavailable)
		}
		digest, err := CommandDigest(command)
		if err != nil {
			return Response{}, err
		}
		operation := Operation{OperationID: command.OperationID, ProposalDigest: digest, Change: *command.Change, Before: setting, State: StatePending, Proposer: actor, CreatedAt: now}
		document, err := json.Marshal(operation)
		if err != nil {
			return Response{}, storeError(err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO operations (operation_id, proposal_digest, proposal, document, created_at) VALUES (?, ?, ?, ?, ?)", operation.OperationID, digest, request, document, now.UnixNano()); err != nil {
			return Response{}, storeError(err)
		}
		response.Operation = &operation
		return response, nil
	}
	operation, err := loadOperation(ctx, tx, command.OperationID, command.ProposalDigest)
	if err != nil {
		return Response{}, err
	}
	response.Operation = &operation
	if command.Kind == KindStatus {
		return response, nil
	}
	if operation.State != StatePending || command.ExpectedRevision != operation.Before.Revision {
		return Response{}, ErrConflict
	}
	operation.Reviewer = actor
	operation.HumanParticipant = HumanParticipant
	operation.Assurance = Assurance
	operation.DecidedAt = &now
	switch command.Kind {
	case KindDecline:
		operation.State = StateDenied
	case KindApprove:
		if setting.Revision != operation.Before.Revision {
			operation.State = StateStale
		} else {
			if setting.Revision >= maxSettingRevision {
				return Response{}, fmt.Errorf("%w: setting revision limit reached", ErrUnavailable)
			}
			setting.Enabled = operation.Change.Enabled
			setting.Revision++
			if _, err := tx.ExecContext(ctx, "UPDATE setting SET enabled = ?, revision = ? WHERE id = 1", setting.Enabled, setting.Revision); err != nil {
				return Response{}, storeError(err)
			}
			operation.State = StateApplied
			operation.After = &setting
		}
	default:
		return Response{}, ErrInvalid
	}
	document, err := json.Marshal(operation)
	if err != nil {
		return Response{}, storeError(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET document = ? WHERE operation_id = ?", document, operation.OperationID); err != nil {
		return Response{}, storeError(err)
	}
	return response, nil
}

func loadSetting(ctx context.Context, tx *sql.Tx) (Setting, error) {
	setting := Setting{Tenant: Tenant, Name: SettingName}
	if err := tx.QueryRowContext(ctx, "SELECT enabled, revision FROM setting WHERE id = 1").Scan(&setting.Enabled, &setting.Revision); err != nil {
		return Setting{}, storeError(err)
	}
	return setting, nil
}

func loadOperation(ctx context.Context, tx *sql.Tx, operationID, digest string) (Operation, error) {
	var storedDigest string
	var proposal, document []byte
	err := tx.QueryRowContext(ctx, "SELECT proposal_digest, proposal, document FROM operations WHERE operation_id = ?", operationID).Scan(&storedDigest, &proposal, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, storeError(err)
	}
	if storedDigest != digest {
		return Operation{}, ErrConflict
	}
	return decodeStoredOperation(operationID, storedDigest, proposal, document)
}

func loadInbox(ctx context.Context, tx *sql.Tx) ([]Operation, *InboxSummary, error) {
	summary := &InboxSummary{Limit: maxInboxOperations}
	if err := tx.QueryRowContext(ctx, `SELECT count(*), coalesce(sum(json_extract(document, '$.state') = ?), 0) FROM operations`, StatePending).Scan(&summary.Total, &summary.Pending); err != nil {
		return nil, nil, storeError(err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT operation_id, proposal_digest, proposal, document FROM operations
		ORDER BY (json_extract(document, '$.state') = ?) DESC,
		CASE WHEN json_extract(document, '$.state') = ? THEN created_at END ASC,
		created_at DESC, operation_id LIMIT ?`, StatePending, StatePending, maxInboxOperations)
	if err != nil {
		return nil, nil, storeError(err)
	}
	defer func() { _ = rows.Close() }()
	operations := make([]Operation, 0)
	for rows.Next() {
		var operationID, digest string
		var proposal, document []byte
		if err := rows.Scan(&operationID, &digest, &proposal, &document); err != nil {
			return nil, nil, storeError(err)
		}
		operation, err := decodeStoredOperation(operationID, digest, proposal, document)
		if err != nil {
			return nil, nil, err
		}
		operations = append(operations, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, storeError(err)
	}
	return operations, summary, nil
}

func decodeStoredOperation(operationID, digest string, proposal, document []byte) (Operation, error) {
	var command Command
	var operation Operation
	if err := decodeJSON(bytes.NewReader(proposal), &command); err != nil || command.Kind != KindPropose || command.Validate() != nil {
		return Operation{}, storeError(errors.New("invalid stored proposal"))
	}
	actualDigest, err := CommandDigest(command)
	if err != nil || actualDigest != digest {
		return Operation{}, storeError(errors.New("stored proposal digest mismatch"))
	}
	if err := decodeJSON(bytes.NewReader(document), &operation); err != nil {
		return Operation{}, storeError(errors.New("invalid stored operation"))
	}
	if operation.OperationID != operationID || command.OperationID != operationID || operation.ProposalDigest != digest ||
		operation.Change != *command.Change || operation.Before.Tenant != Tenant || operation.Before.Name != SettingName ||
		operation.Before.Revision != command.ExpectedRevision || operation.Proposer != ActorAgent || operation.CreatedAt.IsZero() {
		return Operation{}, storeError(errors.New("stored operation binding mismatch"))
	}
	switch operation.State {
	case StatePending:
		if operation.DecidedAt != nil || operation.After != nil || operation.Reviewer != "" || operation.HumanParticipant != "" || operation.Assurance != "" {
			return Operation{}, storeError(errors.New("invalid pending operation"))
		}
	case StateApplied, StateDenied, StateStale:
		if operation.DecidedAt == nil || operation.Reviewer != ActorGateway || operation.HumanParticipant != HumanParticipant || operation.Assurance != Assurance {
			return Operation{}, storeError(errors.New("invalid decision provenance"))
		}
		if operation.State == StateApplied {
			if operation.After == nil || operation.After.Tenant != Tenant || operation.After.Name != SettingName || operation.After.Enabled != operation.Change.Enabled || operation.After.Revision != operation.Before.Revision+1 {
				return Operation{}, storeError(errors.New("invalid applied setting"))
			}
		} else if operation.After != nil {
			return Operation{}, storeError(errors.New("unexpected setting effect"))
		}
	default:
		return Operation{}, storeError(errors.New("invalid operation state"))
	}
	return operation, nil
}

func storeError(err error) error {
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
