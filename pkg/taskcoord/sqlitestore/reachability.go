// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"errors"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

var (
	_ taskcoord.HumanReachabilityDirectory           = (*Store)(nil)
	_ taskcoord.HumanReachabilityRelayTransaction    = (*Store)(nil)
	_ taskcoord.HumanReachabilityDispatchTransaction = (*Store)(nil)
)

func (s *Store) runReachability(ctx context.Context, write bool, fn func(*taskcoord.MemoryReachabilityDirectory) error) error {
	if !durableReachabilitySupported {
		return unavailable(errors.New("durable reachability requires Linux local storage"))
	}
	return s.run(ctx, write, func(tx *transaction) error {
		var size int
		if err := tx.conn.QueryRowContext(ctx, "SELECT length(state) FROM reachability WHERE id=1").Scan(&size); err != nil {
			return unavailable(err)
		}
		if size > maxStateBytes {
			return taskcoord.ErrStoreLimit
		}
		var raw []byte
		if err := tx.conn.QueryRowContext(ctx, "SELECT state FROM reachability WHERE id=1").Scan(&raw); err != nil {
			return unavailable(err)
		}
		directory, err := taskcoord.RestoreMemoryReachabilityDirectory(raw, tx.MemoryStore, s.now)
		if err != nil {
			return unavailable(err)
		}
		if err := fn(directory); err != nil {
			return err
		}
		if write {
			raw, err = directory.ExportState()
			if err != nil {
				return err
			}
			if _, err := tx.conn.ExecContext(ctx, "UPDATE reachability SET state=? WHERE id=1", raw); err != nil {
				return unavailable(err)
			}
		}
		return nil
	})
}

// RegisterHumanMatchConsent persists a trusted, requester-scoped opt-in. Raw
// network input must pass the deployment's authorization verifier first.
func (s *Store) RegisterHumanMatchConsent(ctx context.Context, consent taskcoord.HumanMatchConsent) error {
	return s.runReachability(ctx, true, func(d *taskcoord.MemoryReachabilityDirectory) error {
		return d.RegisterHumanMatchConsent(ctx, consent)
	})
}

// RevokeHumanMatchConsent orders the permanent withdrawal with relay dispatch.
func (s *Store) RevokeHumanMatchConsent(ctx context.Context, revocation taskcoord.HumanMatchConsentRevocation) error {
	return s.runReachability(ctx, true, func(d *taskcoord.MemoryReachabilityDirectory) error {
		return d.RevokeHumanMatchConsent(ctx, revocation)
	})
}

// MatchHumans returns only the existing privacy-minimized matching projection.
func (s *Store) MatchHumans(ctx context.Context, request taskcoord.AuthenticatedHumanMatchQuery) (result []taskcoord.HumanMatchCandidate, err error) {
	err = s.runReachability(ctx, false, func(d *taskcoord.MemoryReachabilityDirectory) error {
		result, err = d.MatchHumans(ctx, request)
		return err
	})
	return result, err
}

// IssueHumanReachabilityGrant commits the Human-approved grant and its history.
func (s *Store) IssueHumanReachabilityGrant(ctx context.Context, definition taskcoord.HumanReachabilityGrantDefinition) (result taskcoord.HumanReachabilityGrant, err error) {
	err = s.runReachability(ctx, true, func(d *taskcoord.MemoryReachabilityDirectory) error {
		result, err = d.IssueHumanReachabilityGrant(ctx, definition)
		return err
	})
	return result, err
}

// LoadActiveHumanReachabilityGrant rechecks expiry, exact scope and revocation.
func (s *Store) LoadActiveHumanReachabilityGrant(ctx context.Context, access taskcoord.AuthenticatedReachabilityAccess) (result taskcoord.HumanReachabilityGrant, err error) {
	err = s.runReachability(ctx, false, func(d *taskcoord.MemoryReachabilityDirectory) error {
		result, err = d.LoadActiveHumanReachabilityGrant(ctx, access)
		return err
	})
	return result, err
}

// RevokeHumanReachabilityGrant retains revocation permanently. An external
// dispatch that already holds the guard may finish before this method returns.
func (s *Store) RevokeHumanReachabilityGrant(ctx context.Context, revocation taskcoord.HumanReachabilityRevocation) error {
	return s.runReachability(ctx, true, func(d *taskcoord.MemoryReachabilityDirectory) error {
		return d.RevokeHumanReachabilityGrant(ctx, revocation)
	})
}

func (s *Store) withRelayGuard(ctx context.Context, fn func(*taskcoord.MemoryReachabilityDirectory) error) error {
	if !durableReachabilitySupported || ctx == nil {
		return unavailable(errors.New("relay authorization requires Linux and a bounded context"))
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 30*time.Second {
		return unavailable(errors.New("relay callback needs a deadline of at most 30 seconds"))
	}
	release, err := s.acquireGrantGuard(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	var directory *taskcoord.MemoryReachabilityDirectory
	if err := s.runReachability(ctx, false, func(d *taskcoord.MemoryReachabilityDirectory) error {
		directory = d
		return nil
	}); err != nil {
		return err
	}
	// The SQLite read transaction is closed before the callback. All grant,
	// consent and Participant writes in this adapter use the same OS guard.
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(directory)
}

// CommitWithActiveHumanReachabilityGrant keeps authorization stable until a
// trusted relay callback durably commits its exact intent. It must use this
// directory as its only grant authority, honor ctx, and never re-enter Store.
// A crash after its own durable commit is recovered by intent identity.
func (s *Store) CommitWithActiveHumanReachabilityGrant(ctx context.Context, access taskcoord.AuthenticatedReachabilityAccess, commit func(taskcoord.HumanReachabilityGrant) error) error {
	return s.withRelayGuard(ctx, func(d *taskcoord.MemoryReachabilityDirectory) error {
		return d.CommitWithActiveHumanReachabilityGrant(ctx, access, commit)
	})
}

// CommitWithActiveHumanReachabilityGrantForDispatch serializes dispatch with
// revocation across processes on one Linux host. The callback must honor ctx,
// persist DISPATCHING before contacting a provider, and never blindly retry an
// uncertain effect. It must not re-enter Store. This is not a distributed lock.
func (s *Store) CommitWithActiveHumanReachabilityGrantForDispatch(ctx context.Context, access taskcoord.HumanReachabilityDispatchAccess, dispatch func(taskcoord.HumanReachabilityGrant) error) error {
	return s.withRelayGuard(ctx, func(d *taskcoord.MemoryReachabilityDirectory) error {
		return d.CommitWithActiveHumanReachabilityGrantForDispatch(ctx, access, dispatch)
	})
}
