// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
)

const maxJournalRecords = 100000

// Base64 encodes the original bytes; embedding RawMessage in JSON would
// compact whitespace and escape HTML, changing the retained response.
type storedHumanOutcome struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
	ParticipantID string `json:"participant_id"`
	ActorID       string `json:"actor_id"`
	Response      []byte `json:"response"`
}

func storedOutcome(o asbbinding.HumanOutcome) storedHumanOutcome {
	return storedHumanOutcome{o.OperationID, o.RequestDigest, o.ParticipantID, o.ActorID, []byte(o.Response)}
}

func (tx *transaction) MarkUsed(key string, expires time.Time) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	now := tx.now().UTC()
	if strings.TrimSpace(key) == "" || len(key) > 4096 || !now.Before(expires) {
		return identitypolicy.ErrReplayUnavailable
	}
	if _, err := tx.conn.ExecContext(tx.ctx, "DELETE FROM replay WHERE expires<=?", now.UnixNano()); err != nil {
		return identitypolicy.ErrReplayUnavailable
	}
	var count int
	if err := tx.conn.QueryRowContext(tx.ctx, "SELECT count(*) FROM replay").Scan(&count); err != nil || count >= maxJournalRecords {
		return identitypolicy.ErrReplayUnavailable
	}
	result, err := tx.conn.ExecContext(tx.ctx, "INSERT INTO replay(key,expires) VALUES (?,?) ON CONFLICT(key) DO NOTHING", key, expires.UnixNano())
	if err != nil {
		return identitypolicy.ErrReplayUnavailable
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return identitypolicy.ErrReplayUnavailable
	}
	if changed != 1 {
		return identitypolicy.ErrReplayDetected
	}
	return nil
}

func (tx *transaction) LookupHumanOutcome(ctx context.Context, id string) (asbbinding.HumanOutcome, error) {
	var value asbbinding.HumanOutcome
	var raw []byte
	err := tx.conn.QueryRowContext(ctx, "SELECT document FROM outcomes WHERE id=?", id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return value, asbbinding.ErrHumanOutcomeNotFound
	}
	if err != nil {
		return value, unavailable(err)
	}
	if len(raw) > 2*taskcoord.MaxDocumentBytes {
		return value, taskcoord.ErrStoreLimit
	}
	if err = strictjson.ValidateDocument(raw, int64(len(raw))); err != nil {
		return value, unavailable(err)
	}
	var stored storedHumanOutcome
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&stored); err != nil {
		return value, unavailable(err)
	}
	value = asbbinding.HumanOutcome{OperationID: stored.OperationID, RequestDigest: stored.RequestDigest, ParticipantID: stored.ParticipantID, ActorID: stored.ActorID, Response: stored.Response}
	if value.OperationID != id {
		return value, taskcoord.ErrStoreUnavailable
	}
	if err = value.Validate(); err != nil {
		return value, unavailable(err)
	}
	return value, nil
}

func (tx *transaction) PutHumanOutcome(ctx context.Context, value asbbinding.HumanOutcome) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	if err := value.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(storedOutcome(value))
	if err != nil {
		return err
	}
	if len(raw) > 2*taskcoord.MaxDocumentBytes {
		return taskcoord.ErrStoreLimit
	}
	old, err := tx.LookupHumanOutcome(ctx, value.OperationID)
	if err == nil {
		previous, err := json.Marshal(storedOutcome(old))
		if err != nil {
			return unavailable(err)
		}
		if bytes.Equal(raw, previous) {
			return nil
		}
		return asbbinding.ErrHumanOutcomeConflict
	}
	if !errors.Is(err, asbbinding.ErrHumanOutcomeNotFound) {
		return err
	}
	var count int
	if err := tx.conn.QueryRowContext(ctx, "SELECT count(*) FROM outcomes").Scan(&count); err != nil {
		return unavailable(err)
	}
	if count >= maxJournalRecords {
		return taskcoord.ErrStoreLimit
	}
	_, err = tx.conn.ExecContext(ctx, "INSERT INTO outcomes(id,document) VALUES (?,?)", value.OperationID, raw)
	if err != nil {
		return unavailable(err)
	}
	return nil
}
