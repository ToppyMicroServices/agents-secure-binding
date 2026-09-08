// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// GrantTransaction is the TaskCoord authorization transaction needed by the
// reference MemoryStore. It must serialize queue and dispatch authorization
// with grant/consent revocation and Participant status.
type GrantTransaction interface {
	taskcoord.HumanReachabilityRelayTransaction
	taskcoord.HumanReachabilityDispatchTransaction
}

// Store is the combined reachability-authorization, relay-intent, and outbox
// boundary. CommitAuthorizedIntent must recheck the authoritative Participant,
// consent, grant, exact scope, revocation, and expiry state in the same durable
// transaction that inserts the immutable intent, its QUEUED event, and a
// pending dispatch record. A lookup followed by an unrelated write does not
// satisfy this interface.
//
// GrantID is unique: one active reachability grant authorizes one intent. A
// retry with the same RequestDigest, routing, and content but fresh verifier
// proof identifiers must return the original Receipt without replacing its
// first-commit audit fields. A changed business request must conflict.
//
// CommitAuthorizedDispatch must recheck reachability under the same
// grant-scoped ordering boundary used by revocation. It commits DISPATCHING
// before at most one provider callback and commits a valid acknowledgement
// before releasing that boundary. If reachability is already unavailable, it
// records CANCELED without calling the provider. An implementation must not
// expose this trusted worker operation as an Agent-facing route.
type Store interface {
	CommitAuthorizedIntent(context.Context, QueueCommit) (Receipt, error)
	LoadIntent(context.Context, string) (Intent, Receipt, error)
	CommitAuthorizedDispatch(context.Context, string, SessionDispatcher, func() time.Time) (Receipt, error)
}

// SessionDispatcher sends an opaque relay-session request to a configured
// Human gateway. It is consumed only by the trusted Worker, never by an
// Agent-facing route. Implementations must deduplicate by
// DispatchRequest.IntentID. The callback runs under the reference store's
// grant-scoped dispatch guard and must not re-enter the Store or reachability
// directory. Errors may contain provider-private routing data and must remain
// worker-private.
type SessionDispatcher interface {
	Dispatch(context.Context, DispatchRequest) (ProviderAck, error)
}
