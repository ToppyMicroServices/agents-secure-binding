// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// OutboxQuarantine is an operator-owned request, not a peer protocol. The hash
// identifies the exact corrupt bytes being removed from delivery selection;
// ReasonRef refers to private incident evidence, not free-form contact data.
type OutboxQuarantine struct {
	QuarantineID           string
	DeliveryID             string
	ExpectedDocumentDigest string
	ReasonRef              string
}

// QuarantineOutbox preserves a corrupt row and its hash in an immutable audit
// record. It does not acknowledge/delete the event or authorize redispatch.
// Only an unleased (or expired), unacknowledged and invalid row may be isolated.
// Valid rows and hash mismatches fail closed. Backend access is trusted only.
func (s *Store) QuarantineOutbox(ctx context.Context, request OutboxQuarantine) error {
	if !validRecoveryID(request.QuarantineID) || !validRecoveryID(request.DeliveryID) || !validRecoveryID(request.ReasonRef) || !validRecoveryDigest(request.ExpectedDocumentDigest) {
		return taskcoord.ErrOutboxConflict
	}
	return s.runOutboxWrite(ctx, func(conn *sql.Conn) error {
		var priorID, priorDigest, priorReason string
		err := conn.QueryRowContext(ctx, "SELECT delivery_id,document_digest,reason_ref FROM outbox_quarantine WHERE quarantine_id=?", request.QuarantineID).Scan(&priorID, &priorDigest, &priorReason)
		if err == nil {
			if priorID == request.DeliveryID && priorDigest == request.ExpectedDocumentDigest && priorReason == request.ReasonRef {
				return nil
			}
			return taskcoord.ErrOutboxConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return unavailable(err)
		}
		var raw []byte
		var acknowledged bool
		var expires int64
		err = conn.QueryRowContext(ctx, "SELECT document,acknowledged,expires FROM outbox WHERE id=?", request.DeliveryID).Scan(&raw, &acknowledged, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return taskcoord.ErrOutboxConflict
		}
		if err != nil {
			return unavailable(err)
		}
		if len(raw) > 2*taskcoord.MaxOutboxPayloadBytes {
			return taskcoord.ErrStoreLimit
		}
		now := s.now().UTC().UnixNano()
		if acknowledged || expires > now || recoveryDigest(raw) != request.ExpectedDocumentDigest {
			return taskcoord.ErrOutboxConflict
		}
		if _, err := decodeRecoveryOutbox(raw, request.DeliveryID); err == nil {
			return taskcoord.ErrOutboxConflict
		}
		var count int
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM outbox_quarantine").Scan(&count); err != nil {
			return unavailable(err)
		}
		if count >= maxJournalRecords {
			return taskcoord.ErrStoreLimit
		}
		if _, err := conn.ExecContext(ctx, "INSERT INTO outbox_quarantine(quarantine_id,delivery_id,document,document_digest,reason_ref,quarantined_at) VALUES (?,?,?,?,?,?)",
			request.QuarantineID, request.DeliveryID, raw, request.ExpectedDocumentDigest, request.ReasonRef, now); err != nil {
			return unavailable(err)
		}
		// Lease IDs remain reserved; old workers cannot acknowledge a restored row.
		_, err = conn.ExecContext(ctx, "UPDATE outbox SET consumer='',lease='',expires=0 WHERE id=?", request.DeliveryID)
		if err != nil {
			return unavailable(err)
		}
		return nil
	})
}

// RestoreQuarantinedOutbox repairs one row from a trusted backup. Valid JSON
// alone is insufficient: replaying its payload into authoritative TaskCoord
// history must change no state. Thus a repair cannot introduce a new authorized
// mutation. Original corrupt bytes and replacement hash stay in the audit log.
// Publication remains at-least-once; consumers must deduplicate the EventID.
func (s *Store) RestoreQuarantinedOutbox(ctx context.Context, quarantineID, expectedDigest string, replacement []byte) error {
	if !validRecoveryID(quarantineID) || !validRecoveryDigest(expectedDigest) || len(replacement) > 2*taskcoord.MaxOutboxPayloadBytes {
		return taskcoord.ErrOutboxConflict
	}
	return s.run(ctx, true, func(tx *transaction) error {
		var id, digest, replacementDigest string
		var original []byte
		var restoredAt int64
		err := tx.conn.QueryRowContext(ctx, "SELECT delivery_id,document,document_digest,restored_at,replacement_digest FROM outbox_quarantine WHERE quarantine_id=?", quarantineID).Scan(&id, &original, &digest, &restoredAt, &replacementDigest)
		if errors.Is(err, sql.ErrNoRows) {
			return taskcoord.ErrOutboxConflict
		}
		if err != nil {
			return unavailable(err)
		}
		if digest != expectedDigest || recoveryDigest(original) != digest {
			return taskcoord.ErrOutboxConflict
		}
		if restoredAt != 0 {
			if replacementDigest == recoveryDigest(replacement) {
				return nil
			}
			return taskcoord.ErrOutboxConflict
		}
		var current []byte
		var acknowledged bool
		if err := tx.conn.QueryRowContext(ctx, "SELECT document,acknowledged FROM outbox WHERE id=?", id).Scan(&current, &acknowledged); err != nil {
			return unavailable(err)
		}
		if acknowledged || !bytes.Equal(current, original) {
			return taskcoord.ErrOutboxConflict
		}
		event, err := decodeRecoveryOutbox(replacement, id)
		if err != nil {
			return err
		}
		if err := validateHistoricalOutbox(ctx, tx.MemoryStore, event); err != nil {
			return err
		}
		if _, err := tx.conn.ExecContext(ctx, "UPDATE outbox SET document=?,consumer='',lease='',expires=0 WHERE id=?", replacement, id); err != nil {
			return unavailable(err)
		}
		_, err = tx.conn.ExecContext(ctx, "UPDATE outbox_quarantine SET restored_at=?,replacement_digest=? WHERE quarantine_id=?", tx.now().UTC().UnixNano(), recoveryDigest(replacement), quarantineID)
		if err != nil {
			return unavailable(err)
		}
		return nil
	})
}

func decodeRecoveryOutbox(raw []byte, id string) (taskcoord.OutboxEvent, error) {
	var event taskcoord.OutboxEvent
	if strictjson.ValidateDocument(raw, 2*taskcoord.MaxOutboxPayloadBytes) != nil {
		return event, taskcoord.ErrStoreUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || event.EventID != id || event.Validate() != nil {
		return event, taskcoord.ErrStoreUnavailable
	}
	return event, nil
}

func validateHistoricalOutbox(ctx context.Context, store *taskcoord.MemoryStore, event taskcoord.OutboxEvent) error {
	before, err := store.ExportState()
	if err != nil {
		return unavailable(err)
	}
	copy, err := taskcoord.RestoreMemoryStore(before)
	if err != nil {
		return unavailable(err)
	}
	switch event.Kind {
	case taskcoord.OutboxAssignmentTransition:
		var value taskcoord.Transition
		if err := json.Unmarshal(event.Payload, &value); err != nil {
			return taskcoord.ErrOutboxConflict
		}
		err = copy.CommitAssignment(ctx, value.Assignment.Revision-1, value.Assignment, value.Record)
	case taskcoord.OutboxDelegationCommitted:
		var value taskcoord.DelegationTransition
		if err := json.Unmarshal(event.Payload, &value); err != nil {
			return taskcoord.ErrOutboxConflict
		}
		err = copy.CommitDelegation(ctx, value.Parent.Revision-1, value)
	case taskcoord.OutboxInteractionAppended:
		var value taskcoord.InteractionEvent
		if err := json.Unmarshal(event.Payload, &value); err != nil {
			return taskcoord.ErrOutboxConflict
		}
		err = copy.AppendInteractionEvent(ctx, value)
	default:
		return taskcoord.ErrOutboxConflict
	}
	if err != nil {
		return taskcoord.ErrOutboxConflict
	}
	after, err := copy.ExportState()
	if err != nil || !bytes.Equal(before, after) {
		return taskcoord.ErrOutboxConflict
	}
	return nil
}

func validRecoveryID(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validRecoveryDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == value
}

func recoveryDigest(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
