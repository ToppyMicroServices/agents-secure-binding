// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import "context"

// Store is a low-level durability boundary, not network ingress. Commit must
// reject an invalid Snapshot or a Record that differs from LastTransition,
// atomically compare Revision, persist the complete next Snapshot, and
// append/deduplicate Record.EventID before acknowledging success. Revision-one
// ACCEPT validation recomputes its durable definition/context digest. An
// application that binds TaskCoord responsibility must expose actionbinding.Store
// instead so the complete authorization window and locked Assignment can also
// be rechecked.
type Store interface {
	Load(context.Context, string) (Snapshot, error)
	Commit(context.Context, uint64, Snapshot, TransitionRecord) error
}
