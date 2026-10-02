// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestStoreConnectionReplacementPreservesSettingsAndOutcome(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	proposal := testProposal("connection-recovery", true, 0)
	original, proposed := executeStore(t, store, proposal, ActorAgent, "initial-proposal")
	for replacement := range 3 {
		conn, err := store.db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		// Force the same pool replacement database/sql performs for an
		// unusable connection, without depending on cancellation timing.
		err = conn.Raw(func(any) error { return driver.ErrBadConn })
		_ = conn.Close()
		if !errors.Is(err, driver.ErrBadConn) {
			t.Fatalf("discard connection: %v", err)
		}
		for pragma, expected := range map[string]int{
			"busy_timeout": 5000, "synchronous": 2, "foreign_keys": 1,
		} {
			var actual int
			if err := store.db.QueryRowContext(t.Context(), "PRAGMA "+pragma).Scan(&actual); err != nil {
				t.Fatal(err)
			}
			if actual != expected {
				t.Fatalf("replacement %d: %s = %d, want %d", replacement, pragma, actual, expected)
			}
		}
		recovered, _ := executeStore(t, store, proposal, ActorAgent, fmt.Sprintf("recovery-%d", replacement))
		if !bytes.Equal(recovered, original) {
			t.Fatal("connection replacement changed the original proposal response")
		}
	}
	_, approved := executeStore(t, store, testDecision("approve-recovered", KindApprove, *proposed.Operation), ActorGateway, "approve-recovered")
	requireSetting(t, approved, true, 1)
}
