// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"errors"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
)

func (s *Store) LoadParticipant(ctx context.Context, id string) (value taskcoord.Participant, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.LoadParticipant(ctx, id)
		return e
	})
	return
}

func (s *Store) LoadAssignment(ctx context.Context, id string) (value taskcoord.Assignment, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.LoadAssignment(ctx, id)
		return e
	})
	if errors.Is(err, taskcoord.ErrNotFound) {
		err = errors.Join(err, actionbinding.ErrNotFound)
	}
	return
}

func (s *Store) LoadDelegation(ctx context.Context, id string) (value taskcoord.DelegationRecord, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.LoadDelegation(ctx, id)
		return e
	})
	return
}

func (s *Store) LoadInteractionEvent(ctx context.Context, id string) (value taskcoord.InteractionEvent, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.LoadInteractionEvent(ctx, id)
		return e
	})
	return
}

func (s *Store) ListInteractionEvents(ctx context.Context, id string) (value []taskcoord.InteractionEvent, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.ListInteractionEvents(ctx, id)
		return e
	})
	return
}

func (s *Store) RegisterParticipant(ctx context.Context, participant taskcoord.Participant) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.RegisterParticipant(ctx, participant) })
}

func (s *Store) CommitAssignment(ctx context.Context, expected uint64, next taskcoord.Assignment, record taskcoord.TransitionRecord) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.CommitAssignment(ctx, expected, next, record) })
}

func (s *Store) CommitDelegation(ctx context.Context, expected uint64, next taskcoord.DelegationTransition) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.CommitDelegation(ctx, expected, next) })
}

func (s *Store) AppendInteractionEvent(ctx context.Context, event taskcoord.InteractionEvent) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.AppendInteractionEvent(ctx, event) })
}

// A failed write poisons the transaction even if a callback ignores its error.
func (tx *transaction) RegisterParticipant(ctx context.Context, participant taskcoord.Participant) (failure error) {
	defer func() {
		if failure != nil {
			tx.failed = failure
		}
	}()
	return tx.MemoryStore.RegisterParticipant(ctx, participant)
}
