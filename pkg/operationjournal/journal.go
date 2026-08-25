// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package operationjournal

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound indicates that no operation is reserved under the supplied ID.
	ErrNotFound = errors.New("operationjournal: operation not found")
	// ErrConflict indicates reuse of an operation ID with different bound data,
	// or an attempt to replace a terminal decision with a different decision.
	ErrConflict = errors.New("operationjournal: operation conflict")
	// ErrInvalidTransition indicates that the requested state change is not
	// permitted by the journal state machine.
	ErrInvalidTransition = errors.New("operationjournal: invalid state transition")
	// ErrInvalidRecord indicates malformed operation input or persisted state.
	ErrInvalidRecord = errors.New("operationjournal: invalid record")
	// ErrUnavailable indicates that durable journal state cannot be read or
	// committed. Callers must not proceed with an operation after this error.
	ErrUnavailable = errors.New("operationjournal: journal unavailable")
	// ErrReplay indicates that the accepted verifier nonce was already
	// reserved and cannot authorize another operation attempt.
	ErrReplay = errors.New("operationjournal: replay detected")
)

// State is the durable execution state of one operation.
type State string

const (
	// StateAccepted means the exact request has been reserved but execution has
	// not started.
	StateAccepted State = "ACCEPTED"
	// StateRunning means execution may have reached an external model, tool, or
	// physical adapter.
	StateRunning State = "RUNNING"
	// StateIndeterminate means execution may have had an effect, but no terminal
	// result is known. It must not be treated as permission for a blind retry.
	StateIndeterminate State = "INDETERMINATE"
	// StateSucceeded, StateFailed, and StateCanceled are terminal.
	StateSucceeded State = "SUCCEEDED"
	StateFailed    State = "FAILED"
	StateCanceled  State = "CANCELED"
)

// Terminal reports whether no further execution transition is permitted.
func (s State) Terminal() bool {
	switch s {
	case StateSucceeded, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

// Reservation identifies the exact application request to reserve. The digest
// must be a lowercase, canonical "sha256:" value. Request bytes are not stored.
type Reservation struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
}

// AcceptanceReservation commits replay protection and an operation
// reservation in one store transaction. ReplayKey is already a
// domain-separated digest; raw verifier nonces are not accepted here.
type AcceptanceReservation struct {
	ReplayKey         string
	ReplayRetainUntil time.Time
	Operation         Reservation
}

// Finalization records one terminal decision. OutcomeDigest is optional, but
// when present it must use the same canonical SHA-256 form as RequestDigest.
// The journal deliberately stores no raw model output or application payload.
type Finalization struct {
	OperationID   string
	RequestDigest string
	State         State
	OutcomeDigest string
}

// SealedResult is an opaque, authenticated-encryption envelope stored beside
// an operation record. The journal never receives the plaintext application
// result or the key needed to open it.
//
// OperationID, RequestDigest, OutcomeDigest, and MediaType are authenticated
// encryption inputs. Implementations must keep the envelope bound to that
// exact tuple and must bound the nonce and ciphertext before persistence.
type SealedResult struct {
	OperationID    string `json:"operation_id"`
	RequestDigest  string `json:"request_digest"`
	OutcomeDigest  string `json:"outcome_digest"`
	MediaType      string `json:"media_type"`
	Envelope       string `json:"envelope"`
	PlaintextBytes uint32 `json:"plaintext_bytes"`
	Nonce          []byte `json:"nonce"`
	Ciphertext     []byte `json:"ciphertext"`
}

// Record is the durable projection returned by the journal.
type Record struct {
	OperationID   string    `json:"operation_id"`
	RequestDigest string    `json:"request_digest"`
	State         State     `json:"state"`
	OutcomeDigest string    `json:"outcome_digest,omitempty"`
	Revision      uint64    `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

// Store is the application-facing durable operation journal contract.
//
// Reserve is exactly idempotent for the same operation ID and request digest.
// Its created result is false for an existing exact reservation. Lookup also
// requires both values so an ID alone cannot select an unrelated result.
type Store interface {
	Reserve(ctx context.Context, request Reservation) (record Record, created bool, err error)
	Lookup(ctx context.Context, operationID, requestDigest string) (Record, error)
	MarkRunning(ctx context.Context, operationID, requestDigest string) (record Record, started bool, err error)
	MarkIndeterminate(ctx context.Context, operationID, requestDigest string) (Record, error)
	Finalize(ctx context.Context, final Finalization) (Record, error)
}

// AcceptanceStore adds an atomic replay-plus-operation reservation. An exact
// operation retry can return an existing Record, but only with a fresh replay
// key. A repeated replay key always fails.
type AcceptanceStore interface {
	Store
	ReserveAcceptance(ctx context.Context, request AcceptanceReservation) (record Record, operationCreated bool, err error)
}

// ResultStore adds atomic terminal-result persistence. FinalizeWithResult must
// commit the payload-free SUCCEEDED Record and opaque SealedResult in one
// transaction. LookupResult requires the exact operation ID and request digest;
// callers still authenticate and open the envelope outside the journal.
//
// This interface is optional because stores used only for state tracking need
// not retain recoverable application results.
type ResultStore interface {
	AcceptanceStore
	FinalizeWithResult(ctx context.Context, final Finalization, result SealedResult) (Record, error)
	LookupResult(ctx context.Context, operationID, requestDigest string) (Record, SealedResult, error)
}
