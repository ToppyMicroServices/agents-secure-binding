// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
)

func (s *Store) Load(ctx context.Context, id string) (value actionlifecycle.Snapshot, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.actions.Load(ctx, id)
		return e
	})
	return
}

func (s *Store) ListDependencies(ctx context.Context, id string) (value []taskcoord.Dependency, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.actions.ListDependencies(ctx, id)
		return e
	})
	return
}

func (s *Store) LoadBinding(ctx context.Context, id string) (value actionbinding.Binding, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.actions.LoadBinding(ctx, id)
		return e
	})
	return
}

func (s *Store) LoadDependencyWait(ctx context.Context, id string, revision uint64) (value actionbinding.DependencyWait, err error) {
	err = s.run(ctx, false, func(tx *transaction) error {
		var e error
		value, e = tx.actions.LoadDependencyWait(ctx, id, revision)
		return e
	})
	return
}

func (s *Store) CommitAcceptance(ctx context.Context, expected uint64, assignment taskcoord.Assignment, request actionbinding.AcceptRequest) (value actionbinding.View, err error) {
	err = s.run(ctx, true, func(tx *transaction) error {
		var e error
		value, e = tx.actions.CommitAcceptance(ctx, expected, assignment, request)
		return e
	})
	return
}

func (s *Store) CommitAuthorizedTransition(ctx context.Context, expected uint64, current actionlifecycle.Snapshot, event actionlifecycle.Event, transition actionlifecycle.Transition) error {
	return s.run(ctx, true, func(tx *transaction) error {
		return tx.actions.CommitAuthorizedTransition(ctx, expected, current, event, transition)
	})
}

func (s *Store) CommitExecutionTransition(ctx context.Context, expectedAssignment uint64, assignment taskcoord.Assignment, expected uint64, current actionlifecycle.Snapshot, event actionlifecycle.Event, transition actionlifecycle.Transition, binding actionbinding.Binding) error {
	return s.run(ctx, true, func(tx *transaction) error {
		return tx.actions.CommitExecutionTransition(ctx, expectedAssignment, assignment, expected, current, event, transition, binding)
	})
}

func (s *Store) CommitDependencyWait(ctx context.Context, expectedAssignment uint64, assignment taskcoord.Assignment, expected uint64, current actionlifecycle.Snapshot, dependencies []taskcoord.Dependency, event actionlifecycle.Event, transition actionlifecycle.Transition, binding actionbinding.Binding, wait actionbinding.DependencyWait) error {
	return s.run(ctx, true, func(tx *transaction) error {
		return tx.actions.CommitDependencyWait(ctx, expectedAssignment, assignment, expected, current, dependencies, event, transition, binding, wait)
	})
}

func (s *Store) CommitDependencyResume(ctx context.Context, expectedAssignment uint64, assignment taskcoord.Assignment, expected uint64, current actionlifecycle.Snapshot, dependencies []taskcoord.Dependency, event actionlifecycle.Event, transition actionlifecycle.Transition, binding actionbinding.Binding, wait actionbinding.DependencyWait) error {
	return s.run(ctx, true, func(tx *transaction) error {
		return tx.actions.CommitDependencyResume(ctx, expectedAssignment, assignment, expected, current, dependencies, event, transition, binding, wait)
	})
}

func (s *Store) CommitTrustedLeaseExpiry(ctx context.Context, expected uint64, current actionlifecycle.Snapshot, event actionlifecycle.Event, transition actionlifecycle.Transition) error {
	return s.run(ctx, true, func(tx *transaction) error {
		return tx.actions.CommitTrustedLeaseExpiry(ctx, expected, current, event, transition)
	})
}

// SetDependencies is a trusted application API; callers must authorize dependency updates before calling it.
func (s *Store) SetDependencies(ctx context.Context, dependencies []taskcoord.Dependency) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.actions.SetDependencies(ctx, dependencies) })
}

// SetDependencySatisfied is a trusted application API; callers must authorize dependency updates before calling it.
func (s *Store) SetDependencySatisfied(ctx context.Context, id string, satisfied bool) error {
	return s.run(ctx, true, func(tx *transaction) error { return tx.actions.SetDependencySatisfied(ctx, id, satisfied) })
}
