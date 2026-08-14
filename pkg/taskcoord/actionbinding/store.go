// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

// Store is the application transaction boundary joining TaskCoord and Action
// lifecycle persistence. Implementations must use one atomic database
// transaction (or an equivalent primitive) for each Commit method, with
// isolation that prevents the checked revisions or dependency rows from
// changing before commit.
//
// CommitBinding compares the supplied Assignment revision and ACCEPTED state,
// commits the revision-one Action snapshot and transition with expected Action
// revision zero, and inserts the immutable Binding.
//
// CommitDependencyWait compares both current revisions and the current
// dependency rows, then commits the WAITING Action transition and immutable
// DependencyWait together. CommitDependencyResume repeats those checks,
// requires the same topology to be satisfied, and commits RESUME. An adapter
// must deduplicate every Action transition by Record.EventID.
//
// Load methods return an error wrapping ErrNotFound when no record exists.
// Service treats every other load error as fail-closed storage failure.
type Store interface {
	actionlifecycle.Store
	LoadAssignment(context.Context, string) (taskcoord.Assignment, error)
	ListDependencies(context.Context, string) ([]taskcoord.Dependency, error)
	LoadBinding(context.Context, string) (Binding, error)
	LoadDependencyWait(context.Context, string, uint64) (DependencyWait, error)
	CommitBinding(context.Context, uint64, taskcoord.Assignment, actionlifecycle.Transition, Binding) error
	CommitDependencyWait(context.Context, uint64, taskcoord.Assignment, uint64, actionlifecycle.Snapshot, []taskcoord.Dependency, actionlifecycle.Transition, Binding, DependencyWait) error
	CommitDependencyResume(context.Context, uint64, taskcoord.Assignment, uint64, actionlifecycle.Snapshot, []taskcoord.Dependency, actionlifecycle.Transition, Binding, DependencyWait) error
}
