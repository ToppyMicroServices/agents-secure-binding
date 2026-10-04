// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestOutboxQuarantinePreservesEvidenceAndRestoresOnlyAuthorizedHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(time.Second))
	participant, offered := offerFixture(t)
	if err := s.RegisterParticipant(ctx, participant); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if err := s.db.QueryRowContext(ctx, "SELECT document FROM outbox WHERE id=?", offered.Record.EventID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(`{"bad":true,`), original[1:]...)
	if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET document=? WHERE id=?", corrupt, offered.Record.EventID); err != nil {
		t.Fatal(err)
	}
	request := OutboxQuarantine{QuarantineID: "quarantine:one", DeliveryID: offered.Record.EventID,
		ExpectedDocumentDigest: recoveryDigest(corrupt), ReasonRef: "incident:one"}
	if err := s.QuarantineOutbox(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := s.QuarantineOutbox(ctx, request); err != nil {
		t.Fatalf("exact quarantine retry: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path, base.Add(2*time.Second))
	deliveries, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker", LeaseID: "lease:one", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 0 {
		t.Fatalf("poison row was not isolated: %+v %v", deliveries, err)
	}
	var event taskcoord.OutboxEvent
	if err := json.Unmarshal(original, &event); err != nil {
		t.Fatal(err)
	}
	var transition taskcoord.Transition
	if err := json.Unmarshal(event.Payload, &transition); err != nil {
		t.Fatal(err)
	}
	transition.Record.ProofID = "proof:forged"
	transition.Assignment.LastTransition = transition.Record
	payload, err := json.Marshal(transition)
	if err != nil {
		t.Fatal(err)
	}
	event.Payload, event.PayloadDigest = payload, recoveryDigest(payload)
	forged, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("forged fixture must be syntactically valid: %v", err)
	}
	if err := s.RestoreQuarantinedOutbox(ctx, request.QuarantineID, request.ExpectedDocumentDigest, forged); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("uncommitted proof accepted: %v", err)
	}
	if err := s.RestoreQuarantinedOutbox(ctx, request.QuarantineID, request.ExpectedDocumentDigest, original); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreQuarantinedOutbox(ctx, request.QuarantineID, request.ExpectedDocumentDigest, original); err != nil {
		t.Fatalf("exact restoration retry: %v", err)
	}
	deliveries, err = s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker", LeaseID: "lease:two", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 || deliveries[0].Event.EventID != offered.Record.EventID {
		t.Fatalf("restored event: %+v %v", deliveries, err)
	}
	var saved []byte
	var restoredAt int64
	var replacementHash string
	if err := s.db.QueryRowContext(ctx, "SELECT document,restored_at,replacement_digest FROM outbox_quarantine WHERE quarantine_id=?", request.QuarantineID).Scan(&saved, &restoredAt, &replacementHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved, corrupt) || restoredAt == 0 || replacementHash != recoveryDigest(original) {
		t.Fatal("recovery destroyed evidence")
	}
	var acknowledged bool
	if err := s.db.QueryRowContext(ctx, "SELECT acknowledged FROM outbox WHERE id=?", request.DeliveryID).Scan(&acknowledged); err != nil || acknowledged {
		t.Fatalf("recovery acknowledged an external delivery: %v", err)
	}
}

func TestOutboxQuarantineRejectsValidLeasedAndChangedRows(t *testing.T) {
	for _, mode := range []string{"valid", "leased", "acknowledged", "digest mismatch"} {
		t.Run(mode, func(t *testing.T) {
			s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(time.Second))
			participant, offered := offerFixture(t)
			if err := s.RegisterParticipant(ctx, participant); err != nil {
				t.Fatal(err)
			}
			if err := s.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
				t.Fatal(err)
			}
			var raw []byte
			if err := s.db.QueryRowContext(ctx, "SELECT document FROM outbox WHERE id=?", offered.Record.EventID).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if mode != "valid" {
				raw = []byte(`{"corrupt":true}`)
			}
			if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET document=? WHERE id=?", raw, offered.Record.EventID); err != nil {
				t.Fatal(err)
			}
			if mode == "leased" {
				if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET expires=? WHERE id=?", s.now().Add(time.Minute).UnixNano(), offered.Record.EventID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "acknowledged" {
				if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET acknowledged=1 WHERE id=?", offered.Record.EventID); err != nil {
					t.Fatal(err)
				}
			}
			digest := recoveryDigest(raw)
			if mode == "digest mismatch" {
				digest = recoveryDigest([]byte("other"))
			}
			err := s.QuarantineOutbox(ctx, OutboxQuarantine{"quarantine:rejected", offered.Record.EventID, digest, "incident:test"})
			if !errors.Is(err, taskcoord.ErrOutboxConflict) {
				t.Fatalf("unsafe quarantine: %v", err)
			}
			var count int
			if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_quarantine").Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejected quarantine mutated audit: %d %v", count, err)
			}
		})
	}
}

func TestOutboxQuarantineFencesExpiredWorkerAndUnblocksOtherEvents(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(time.Second))
	participant, offered := offerFixture(t)
	if err := s.RegisterParticipant(ctx, participant); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 0, offered.Assignment, offered.Record); err != nil {
		t.Fatal(err)
	}
	deliveries, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "old", LeaseID: "lease:old", Limit: 1, LeaseDuration: time.Second})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("initial poll: %+v %v", deliveries, err)
	}
	var original []byte
	if err := s.db.QueryRowContext(ctx, "SELECT document FROM outbox WHERE id=?", offered.Record.EventID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte(`{"bad":true}`)
	if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET document=? WHERE id=?", corrupt, offered.Record.EventID); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return base.Add(3 * time.Second) }
	request := OutboxQuarantine{"quarantine:expired", offered.Record.EventID, recoveryDigest(corrupt), "incident:expired"}
	if err := s.QuarantineOutbox(ctx, request); err != nil {
		t.Fatal(err)
	}
	next, err := taskcoord.Apply(offered.Assignment, taskEvent(offered.Assignment, taskcoord.OperationAccept, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 1, next.Assignment, next.Record); err != nil {
		t.Fatal(err)
	}
	deliveries, err = s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "other", LeaseID: "lease:other", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(deliveries) != 1 || deliveries[0].Event.EventID != next.Record.EventID {
		t.Fatalf("unrelated delivery blocked: %+v %v", deliveries, err)
	}
	if err := s.RestoreQuarantinedOutbox(ctx, request.QuarantineID, request.ExpectedDocumentDigest, original); err != nil {
		t.Fatal(err)
	}
	if err := s.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{DeliveryID: offered.Record.EventID, ConsumerID: "old", LeaseID: "lease:old"}); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("stale worker acknowledged repaired row: %v", err)
	}
	if _, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "old", LeaseID: "lease:old", Limit: 10, LeaseDuration: time.Minute}); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("reused lease after repair: %v", err)
	}
}
