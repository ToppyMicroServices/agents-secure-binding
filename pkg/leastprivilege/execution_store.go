// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/ed25519"
	"time"
)

// ExecutionStore owns durable admission, replay history and effect outcomes.
// Implementations must retain operation identities and never redispatch an
// uncertain effect. This is trusted storage, not an authorization API.
type ExecutionStore interface {
	UseStore
	Run(context.Context, string, Capability, ed25519.PublicKey, Mandate, Request, time.Time, Effect) (ExecutionRecord, error)
	Lookup(context.Context, string, string) (ExecutionRecord, error)
	Complete(context.Context, string, string, ExecutionState, string) (ExecutionRecord, error)
}

type executionRunner interface {
	Prepare(context.Context, string, Capability, ed25519.PublicKey, Mandate, Request, time.Time) (ExecutionRecord, bool, error)
	Start(context.Context, string, string) (ExecutionRecord, bool, error)
	Complete(context.Context, string, string, ExecutionState, string) (ExecutionRecord, error)
}
