// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestOutboxRejectsAmbiguousStoredEnvelopeWithoutLeasing(t *testing.T) {
	for name, prefix := range map[string]string{
		"duplicate member": `{"schema":"unexpected",`,
		"unknown member":   `{"unexpected":true,`,
	} {
		t.Run(name, func(t *testing.T) {
			s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(time.Second))
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
			if !bytes.HasPrefix(original, []byte("{")) {
				t.Fatal("fixture is not an outbox object")
			}
			malformed := append([]byte(prefix), original[1:]...)
			if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET document=? WHERE id=?", malformed, offered.Record.EventID); err != nil {
				t.Fatal(err)
			}
			poll := taskcoord.OutboxPoll{ConsumerID: "worker:strict", LeaseID: "lease:strict", Limit: 1, LeaseDuration: time.Minute}
			deliveries, err := s.PollOutbox(ctx, poll)
			if !errors.Is(err, taskcoord.ErrStoreUnavailable) || len(deliveries) != 0 {
				t.Fatalf("invalid persisted envelope returned %d deliveries: %v", len(deliveries), err)
			}
			var leases int
			if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM outbox_leases").Scan(&leases); err != nil || leases != 0 {
				t.Fatalf("rejected poll reserved a lease: %d, %v", leases, err)
			}
			// Restore the fixture to show that a rejected poll granted no lease
			// capability and did not prevent subsequent valid delivery.
			if _, err := s.db.ExecContext(ctx, "UPDATE outbox SET document=? WHERE id=?", original, offered.Record.EventID); err != nil {
				t.Fatal(err)
			}
			deliveries, err = s.PollOutbox(ctx, poll)
			if err != nil || len(deliveries) != 1 {
				t.Fatalf("valid event after rejection: %d deliveries, %v", len(deliveries), err)
			}
		})
	}
}
