// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// SyncMandates installs an operator's complete active mandate set. Removed IDs
// are durably revoked; previously revoked or changed IDs cannot be reintroduced.
// A single policy authority must stop admission while replacing its in-memory
// policy view. The Linux product does this at startup under its authority lock.
func (s *SQLiteStore) SyncMandates(ctx context.Context, mandates []Mandate) error {
	if s == nil || len(mandates) > 4096 {
		return ErrInvalidMandate
	}
	digests := make(map[string]string, len(mandates))
	for _, mandate := range mandates {
		if !strings.HasPrefix(mandate.ID, s.namespace+"/") {
			return ErrBinding
		}
		digest, err := DigestMandate(mandate)
		if err != nil {
			return err
		}
		if _, duplicate := digests[mandate.ID]; duplicate {
			return ErrInvalidMandate
		}
		digests[mandate.ID] = digest
	}
	return s.write(ctx, func(conn *sql.Conn) error {
		for id, digest := range digests {
			var old string
			var revoked int
			err := conn.QueryRowContext(ctx, `SELECT digest,revoked FROM mandates WHERE id=?`, id).Scan(&old, &revoked)
			if err == nil && (revoked != 0 || old != digest) {
				return ErrInvalidMandate
			}
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return storeError(err)
			}
		}
		if _, err := conn.ExecContext(ctx, `UPDATE mandates SET revoked=1 WHERE id LIKE ?`, s.namespace+"/%"); err != nil {
			return storeError(err)
		}
		for id, digest := range digests {
			if _, err := conn.ExecContext(ctx, `INSERT INTO mandates VALUES(?,?,0) ON CONFLICT(id) DO UPDATE SET revoked=0`, id, digest); err != nil {
				return storeError(err)
			}
		}
		return nil
	})
}
