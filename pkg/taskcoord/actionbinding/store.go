// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// Store is the application transaction boundary joining TaskCoord and Action
// lifecycle persistence. Implementations must use one atomic database
// transaction (or an equivalent primitive) for each Commit method, with
// isolation that prevents the checked revisions or dependency rows from
// changing before commit.
//
// CommitAcceptance compares the supplied Assignment revision and ACCEPTED
// state, derives accepted_at from the transaction clock, rederives the initial
// Action, commits it with expected revision zero, and inserts the immutable
// Binding. It returns the canonical committed View rather than a caller-side
// reconstruction.
//
// A conforming v1 Store persists three distinct identities: the
// AcceptanceRequestDigest business identity, the complete
// AcceptanceAttemptFingerprint, and the first canonical result. The exact same
// business request and attempt returns that result even after the proof window
// expires. An expired proof must never create new state. A different proof for
// the same business request returns ErrAcceptanceReconciliationRequired and
// must not rewrite the first audit provenance. A distinct Action for an already
// bound Assignment fails with ErrAlreadyExists.
//
// CommitExecutionTransition is required for START, RESUME, TAKEOVER, and lease
// renewal. It atomically compares the complete ACCEPTED Assignment, immutable
// Binding, and current Action before committing the next Action revision. This
// prevents responsibility release or revocation from racing execution start.
//
// CommitDependencyWait compares both current revisions and the current
// dependency rows, then commits the WAITING Action transition and immutable
// DependencyWait together. CommitDependencyResume repeats those checks,
// requires the same topology to be satisfied, and commits RESUME. An adapter
// must deduplicate every Action transition by Record.EventID.
//
// Every mutation commit receives the original Event. After locking the
// compared rows, an adapter must apply that Event to the stored current
// Snapshot and require the derived Transition to match the supplied Transition
// exactly. Authenticated commits must also compare authorization and current
// executor-lease deadlines with the transaction clock immediately before
// commit. CommitTrustedLeaseExpiry is the only unauthenticated mutation path;
// it must use the same transaction clock to prove that the stored lease has
// expired.
//
// Load methods return an error wrapping ErrNotFound when no record exists.
// Service treats every other load error as fail-closed storage failure.
type Store interface {
	Load(context.Context, string) (actionlifecycle.Snapshot, error)
	LoadAssignment(context.Context, string) (taskcoord.Assignment, error)
	ListDependencies(context.Context, string) ([]taskcoord.Dependency, error)
	LoadBinding(context.Context, string) (Binding, error)
	LoadDependencyWait(context.Context, string, uint64) (DependencyWait, error)
	CommitAcceptance(context.Context, uint64, taskcoord.Assignment, AcceptRequest) (View, error)
	CommitAuthorizedTransition(context.Context, uint64, actionlifecycle.Snapshot, actionlifecycle.Event, actionlifecycle.Transition) error
	CommitExecutionTransition(context.Context, uint64, taskcoord.Assignment, uint64, actionlifecycle.Snapshot, actionlifecycle.Event, actionlifecycle.Transition, Binding) error
	CommitDependencyWait(context.Context, uint64, taskcoord.Assignment, uint64, actionlifecycle.Snapshot, []taskcoord.Dependency, actionlifecycle.Event, actionlifecycle.Transition, Binding, DependencyWait) error
	CommitDependencyResume(context.Context, uint64, taskcoord.Assignment, uint64, actionlifecycle.Snapshot, []taskcoord.Dependency, actionlifecycle.Event, actionlifecycle.Transition, Binding, DependencyWait) error
	CommitTrustedLeaseExpiry(context.Context, uint64, actionlifecycle.Snapshot, actionlifecycle.Event, actionlifecycle.Transition) error
}
