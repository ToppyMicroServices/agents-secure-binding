// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import "context"

// Store is the durability boundary. Commit must atomically compare Revision,
// persist the complete next Snapshot, and append/deduplicate Record.EventID
// before acknowledging success. Implementations must not acknowledge a partial
// snapshot or an event that cannot be recovered after restart.
type Store interface {
	Load(context.Context, string) (Snapshot, error)
	Commit(context.Context, uint64, Snapshot, TransitionRecord) error
}
