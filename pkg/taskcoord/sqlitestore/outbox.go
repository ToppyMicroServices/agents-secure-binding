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
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func (tx *transaction) CommitAssignment(ctx context.Context, expected uint64, next taskcoord.Assignment, record taskcoord.TransitionRecord) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	current, loadErr := tx.MemoryStore.LoadAssignment(ctx, next.AssignmentID)
	newMutation := (expected == 0 && errors.Is(loadErr, taskcoord.ErrNotFound)) ||
		(expected != 0 && loadErr == nil && current.Revision == expected)
	if err := tx.MemoryStore.CommitAssignment(ctx, expected, next, record); err != nil {
		return err
	}
	// A delegated child already has an OFFER event, but its publication is
	// contained in the parent delegation outbox event. Replaying that child
	// through CommitAssignment must not publish a new standalone offer.
	if !newMutation {
		return nil
	}
	return tx.enqueue(ctx, taskcoord.OutboxAssignmentTransition, record.EventID, next.TaskID, next.AssignmentID, next.ParticipantID, record.At, taskcoord.Transition{Assignment: next, Record: record})
}

func (tx *transaction) CommitDelegation(ctx context.Context, expected uint64, next taskcoord.DelegationTransition) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	current, loadErr := tx.MemoryStore.LoadAssignment(ctx, next.Parent.AssignmentID)
	newMutation := loadErr == nil && current.Revision == expected
	if err := tx.MemoryStore.CommitDelegation(ctx, expected, next); err != nil {
		return err
	}
	if !newMutation {
		return nil
	}
	return tx.enqueue(ctx, taskcoord.OutboxDelegationCommitted, next.Delegation.EventID, next.Child.TaskID, next.Child.AssignmentID, next.Child.ParticipantID, next.Delegation.At, next)
}

func (tx *transaction) AppendInteractionEvent(ctx context.Context, event taskcoord.InteractionEvent) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	_, loadErr := tx.MemoryStore.LoadInteractionEvent(ctx, event.EventID)
	if err := tx.MemoryStore.AppendInteractionEvent(ctx, event); err != nil {
		return err
	}
	if !errors.Is(loadErr, taskcoord.ErrNotFound) {
		return nil
	}
	return tx.enqueue(ctx, taskcoord.OutboxInteractionAppended, event.EventID, event.TaskID, event.AssignmentID, event.ParticipantID, event.At, event)
}

func (tx *transaction) enqueue(ctx context.Context, kind taskcoord.OutboxEventKind, id, task, assignment, participant string, at time.Time, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(payload)
	event := taskcoord.OutboxEvent{Schema: taskcoord.OutboxEventSchemaV1, EventID: id, Kind: kind, TaskID: task, AssignmentID: assignment, ParticipantID: participant, Payload: payload, PayloadDigest: hex.EncodeToString(hash[:]), OccurredAt: at}
	if err := event.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var old []byte
	err = tx.conn.QueryRowContext(ctx, "SELECT document FROM outbox WHERE id=?", id).Scan(&old)
	if err == nil {
		if bytes.Equal(old, raw) {
			return nil
		}
		return taskcoord.ErrEventConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return unavailable(err)
	}
	var count int
	if err := tx.conn.QueryRowContext(ctx, "SELECT count(*) FROM outbox").Scan(&count); err != nil {
		return unavailable(err)
	}
	if count >= maxJournalRecords {
		return taskcoord.ErrStoreLimit
	}
	_, err = tx.conn.ExecContext(ctx, "INSERT INTO outbox(id,document) VALUES (?,?)", id, raw)
	if err != nil {
		return unavailable(err)
	}
	return nil
}

// PollOutbox leases committed events. It retains lease identifiers and
// acknowledged rows to prevent stale-worker acknowledgements and duplicate
// enqueue after a retry. External delivery remains at-least-once.
func (s *Store) PollOutbox(ctx context.Context, request taskcoord.OutboxPoll) (deliveries []taskcoord.OutboxDelivery, err error) {
	if err = request.Validate(); err != nil {
		return nil, err
	}
	if request.Limit > 256 || request.LeaseDuration > time.Hour {
		return nil, taskcoord.ErrStoreLimit
	}
	now := s.now().UTC()
	var ready bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM outbox WHERE acknowledged=0 AND expires<=?)", now.UnixNano()).Scan(&ready); err != nil {
		return nil, unavailable(err)
	}
	if !ready {
		return nil, nil
	}
	err = s.runOutboxWrite(ctx, func(conn *sql.Conn) error {
		now = s.now().UTC()
		rows, err := conn.QueryContext(ctx, "SELECT id,document FROM outbox WHERE acknowledged=0 AND expires<=? ORDER BY rowid LIMIT ?", now.UnixNano(), request.Limit)
		if err != nil {
			return unavailable(err)
		}
		for rows.Next() {
			var id string
			var raw []byte
			var event taskcoord.OutboxEvent
			if err := rows.Scan(&id, &raw); err != nil {
				_ = rows.Close()
				return unavailable(err)
			}
			if len(raw) > 2*taskcoord.MaxOutboxPayloadBytes || json.Unmarshal(raw, &event) != nil || event.EventID != id || event.Validate() != nil {
				_ = rows.Close()
				return taskcoord.ErrStoreUnavailable
			}
			deliveries = append(deliveries, taskcoord.OutboxDelivery{DeliveryID: id, LeaseID: request.LeaseID, Event: event})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return unavailable(err)
		}
		if err := rows.Close(); err != nil {
			return unavailable(err)
		}
		// An empty poll grants no acknowledgement capability, so retaining its
		// lease identifier cannot fence a stale worker. Reserving it would only
		// consume the store's finite lifetime budget during normal idle polling.
		if len(deliveries) == 0 {
			return nil
		}
		var count int
		if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM outbox_leases").Scan(&count); err != nil {
			return unavailable(err)
		}
		if count >= maxJournalRecords {
			return taskcoord.ErrStoreLimit
		}
		result, err := conn.ExecContext(ctx, "INSERT INTO outbox_leases(id) VALUES (?) ON CONFLICT(id) DO NOTHING", request.LeaseID)
		if err != nil {
			return unavailable(err)
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return unavailable(err)
		}
		if changed != 1 {
			return taskcoord.ErrOutboxConflict
		}
		for _, delivery := range deliveries {
			if _, err := conn.ExecContext(ctx, "UPDATE outbox SET consumer=?,lease=?,expires=? WHERE id=?", request.ConsumerID, request.LeaseID, now.Add(request.LeaseDuration).UnixNano(), delivery.DeliveryID); err != nil {
				return unavailable(err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return deliveries, nil
}

func (s *Store) runOutboxWrite(ctx context.Context, fn func(*sql.Conn) error) error {
	if ctx == nil {
		return unavailable(errors.New("missing context"))
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return unavailable(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return unavailable(err)
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()
	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return unavailable(err)
	}
	return nil
}

func (s *Store) AcknowledgeOutbox(ctx context.Context, request taskcoord.OutboxAcknowledgement) error {
	if err := request.Validate(); err != nil {
		return err
	}
	return s.run(ctx, true, func(tx *transaction) error {
		var consumer, lease string
		var expires int64
		var acknowledged bool
		err := tx.conn.QueryRowContext(ctx, "SELECT consumer,lease,expires,acknowledged FROM outbox WHERE id=?", request.DeliveryID).Scan(&consumer, &lease, &expires, &acknowledged)
		if errors.Is(err, sql.ErrNoRows) {
			return taskcoord.ErrOutboxConflict
		}
		if err != nil {
			return unavailable(err)
		}
		if consumer != request.ConsumerID || lease != request.LeaseID || acknowledged {
			return taskcoord.ErrOutboxConflict
		}
		if tx.now().UTC().UnixNano() >= expires {
			return taskcoord.ErrOutboxLeaseExpired
		}
		if _, err := tx.conn.ExecContext(ctx, "UPDATE outbox SET acknowledged=1 WHERE id=?", request.DeliveryID); err != nil {
			return unavailable(err)
		}
		return nil
	})
}
