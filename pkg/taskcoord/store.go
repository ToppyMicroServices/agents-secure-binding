// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import "context"

// Store is the Task Participant durability boundary.
//
// CommitAssignment must atomically compare the complete current Assignment,
// validate the consecutive transition, persist the complete next Assignment,
// and append/deduplicate Record.EventID before it acknowledges success.
// Deduplication is exact over the durable record; a fresh verifier proof is a
// distinct audit record and needs application-level outcome reconciliation
// after an unknown commit result.
//
// CommitDelegation must atomically compare the complete current parent and
// persist the parent transition, child offer, and delegation record. A
// production adapter is expected to implement this with one database
// transaction and publish notifications through an outbox written in that
// same transaction.
//
// AppendInteractionEvent must append or exactly deduplicate an immutable event
// without changing the related Assignment revision or lifecycle state.
type Store interface {
	RegisterParticipant(context.Context, Participant) error
	LoadParticipant(context.Context, string) (Participant, error)
	LoadAssignment(context.Context, string) (Assignment, error)
	LoadDelegation(context.Context, string) (DelegationRecord, error)
	LoadInteractionEvent(context.Context, string) (InteractionEvent, error)
	ListInteractionEvents(context.Context, string) ([]InteractionEvent, error)
	CommitAssignment(context.Context, uint64, Assignment, TransitionRecord) error
	CommitDelegation(context.Context, uint64, DelegationTransition) error
	AppendInteractionEvent(context.Context, InteractionEvent) error
}
