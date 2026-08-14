// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import "time"

const (
	// SchemaV1 is the durable JSON snapshot profile implemented by this package.
	SchemaV1 = "asb.action-lifecycle/v1"
	// MaxSnapshotBytes bounds strict JSON decoding.
	MaxSnapshotBytes = 1 << 20
)

// State is the authoritative state of one accepted Action.
type State string

const (
	StateAccepted      State = "ACCEPTED"
	StateRunning       State = "RUNNING"
	StateWaiting       State = "WAITING"
	StatePaused        State = "PAUSED"
	StateOrphaned      State = "ORPHANED"
	StateCanceling     State = "CANCELING"
	StateIndeterminate State = "INDETERMINATE"
	StateSucceeded     State = "SUCCEEDED"
	StateFailed        State = "FAILED"
	StateCanceled      State = "CANCELED"
)

// Terminal reports whether no further state transition is allowed.
func (s State) Terminal() bool {
	return s == StateSucceeded || s == StateFailed || s == StateCanceled
}

// RequiresExecutorLease reports whether an executor may currently effect the
// Action. WAITING and PAUSED deliberately do not retain an executor lease.
func (s State) RequiresExecutorLease() bool {
	return s == StateRunning || s == StateCanceling
}

// EventKind identifies an authenticated mutation or trusted lease-expiry
// observation. It is also bound into AuthenticatedOperation.
type EventKind string

const (
	EventAccept                EventKind = "ACCEPT"
	EventStart                 EventKind = "START"
	EventWait                  EventKind = "WAIT"
	EventPause                 EventKind = "PAUSE"
	EventResume                EventKind = "RESUME"
	EventRequestCancel         EventKind = "REQUEST_CANCEL"
	EventComplete              EventKind = "COMPLETE"
	EventFail                  EventKind = "FAIL"
	EventConfirmCanceled       EventKind = "CONFIRM_CANCELED"
	EventMarkIndeterminate     EventKind = "MARK_INDETERMINATE"
	EventLeaseExpired          EventKind = "LEASE_EXPIRED"
	EventTakeover              EventKind = "TAKEOVER"
	EventBeginReconciliation   EventKind = "BEGIN_RECONCILIATION"
	EventResolveReconciliation EventKind = "RESOLVE_RECONCILIATION"
	EventRenewLease            EventKind = "RENEW_LEASE"
)

// ReasonCode is a structured, non-terminal explanation for a transition.
type ReasonCode string

const (
	ReasonAccepted               ReasonCode = "ACCEPTED"
	ReasonStarted                ReasonCode = "STARTED"
	ReasonScheduled              ReasonCode = "SCHEDULED"
	ReasonTargetBusy             ReasonCode = "TARGET_BUSY"
	ReasonServerUnavailable      ReasonCode = "SERVER_UNAVAILABLE"
	ReasonDependencyPending      ReasonCode = "DEPENDENCY_PENDING"
	ReasonOperatorPause          ReasonCode = "OPERATOR_PAUSE"
	ReasonResumed                ReasonCode = "RESUMED"
	ReasonCancelRequested        ReasonCode = "CANCEL_REQUESTED"
	ReasonCompleted              ReasonCode = "COMPLETED"
	ReasonExecutionFailed        ReasonCode = "EXECUTION_FAILED"
	ReasonCanceled               ReasonCode = "CANCELED"
	ReasonOutcomeUnknown         ReasonCode = "OUTCOME_UNKNOWN"
	ReasonTimeout                ReasonCode = "TIMEOUT"
	ReasonTransportTimeout       ReasonCode = "TRANSPORT_TIMEOUT"
	ReasonLeaseExpired           ReasonCode = "LEASE_EXPIRED"
	ReasonTakenOver              ReasonCode = "TAKEN_OVER"
	ReasonReconciliationRequired ReasonCode = "RECONCILIATION_REQUIRED"
	ReasonReconciliationResolved ReasonCode = "RECONCILIATION_RESOLVED"
	ReasonLeaseRenewed           ReasonCode = "LEASE_RENEWED"
)

// Reason records a machine-readable code and an optional bounded diagnostic.
type Reason struct {
	Code   ReasonCode `json:"code"`
	Detail string     `json:"detail,omitempty"`
}

// ResumeKind identifies the durable condition that must be satisfied before a
// WAITING Action can resume.
type ResumeKind string

const (
	ResumeAtTime          ResumeKind = "TIME"
	ResumeTargetAvailable ResumeKind = "TARGET_AVAILABLE"
	ResumeServerAvailable ResumeKind = "SERVER_AVAILABLE"
	ResumeDependency      ResumeKind = "DEPENDENCY"
	ResumeManual          ResumeKind = "MANUAL"
	ResumeSignal          ResumeKind = "SIGNAL"
)

// ResumeCondition is stored with WAITING. Absolute timestamps avoid relying on
// an in-process timer surviving a restart.
type ResumeCondition struct {
	Type               ResumeKind `json:"type"`
	NotBefore          *time.Time `json:"not_before,omitempty"`
	ProbeAfter         *time.Time `json:"probe_after,omitempty"`
	Target             string     `json:"target,omitempty"`
	DependencyActionID string     `json:"dependency_action_id,omitempty"`
	Signal             string     `json:"signal,omitempty"`
}

// ExecutorLease is an exclusive, finite execution claim. Generation is a
// monotonically increasing fencing token and never decreases or repeats.
type ExecutorLease struct {
	LeaseID    string    `json:"lease_id"`
	ExecutorID string    `json:"executor_id"`
	Generation uint64    `json:"generation"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// LeaseFence is presented by the current executor for a state mutation.
type LeaseFence struct {
	LeaseID    string `json:"lease_id"`
	ExecutorID string `json:"executor_id"`
	Generation uint64 `json:"generation"`
}

// Checkpoint binds recoverable state to immutable external storage.
type Checkpoint struct {
	Sequence      uint64    `json:"sequence"`
	PayloadDigest string    `json:"payload_digest"`
	StorageRef    string    `json:"storage_ref"`
	CreatedAt     time.Time `json:"created_at"`
}

// RecoveryMode fixes what may happen after executor loss.
type RecoveryMode string

const (
	RecoveryResumeFromCheckpoint  RecoveryMode = "RESUME_FROM_CHECKPOINT"
	RecoveryRestartIdempotent     RecoveryMode = "RESTART_IDEMPOTENT"
	RecoveryReconcileBeforeResume RecoveryMode = "RECONCILE_BEFORE_RESUME"
	RecoveryManual                RecoveryMode = "MANUAL"
)

// RecoveryPolicy is immutable for the lifetime of an Action.
type RecoveryPolicy struct {
	Mode           RecoveryMode `json:"mode"`
	MaxAttempts    uint32       `json:"max_attempts"`
	IdempotencyKey string       `json:"idempotency_key,omitempty"`
}

// ReconciliationStatus records progress without treating an unknown effect as
// a failure.
type ReconciliationStatus string

const (
	ReconciliationRequired ReconciliationStatus = "REQUIRED"
	ReconciliationRunning  ReconciliationStatus = "RUNNING"
	ReconciliationResolved ReconciliationStatus = "RESOLVED"
)

// ReconciliationResult is the effect proven by authenticated reconciliation.
type ReconciliationResult string

const (
	ReconciliationNoEffect  ReconciliationResult = "NO_EFFECT"
	ReconciliationSucceeded ReconciliationResult = "SUCCEEDED"
	ReconciliationFailed    ReconciliationResult = "FAILED"
	ReconciliationCanceled  ReconciliationResult = "CANCELED"
)

// Reconciliation persists the required lookup and its authenticated evidence.
type Reconciliation struct {
	Status      ReconciliationStatus `json:"status"`
	Attempt     uint32               `json:"attempt"`
	EvidenceRef string               `json:"evidence_ref,omitempty"`
	Result      ReconciliationResult `json:"result,omitempty"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

// OutcomeStatus is a known terminal result. INDETERMINATE is deliberately not
// an OutcomeStatus because it requires reconciliation.
type OutcomeStatus string

const (
	OutcomeSucceeded OutcomeStatus = "SUCCEEDED"
	OutcomeFailed    OutcomeStatus = "FAILED"
	OutcomeCanceled  OutcomeStatus = "CANCELED"
)

// Outcome is populated only after a terminal result is known.
type Outcome struct {
	Status     OutcomeStatus `json:"status"`
	ResultRef  string        `json:"result_ref,omitempty"`
	ErrorCode  string        `json:"error_code,omitempty"`
	RecordedAt time.Time     `json:"recorded_at"`
}

// AuthenticatedOperation is the minimal projection of a freshly verified ASB
// follow-up authorization. It binds one mutation, not a reusable session.
type AuthenticatedOperation struct {
	ActorID         string    `json:"actor_id"`
	AuthorizationID string    `json:"authorization_id"`
	ProofID         string    `json:"proof_id"`
	Operation       EventKind `json:"operation"`
	ActionID        string    `json:"action_id"`
	ActionDigest    string    `json:"action_digest"`
	VerifierNonce   string    `json:"verifier_nonce"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// TransitionRecord is appended atomically with the next Snapshot.
type TransitionRecord struct {
	EventID         string    `json:"event_id"`
	Kind            EventKind `json:"kind"`
	From            State     `json:"from"`
	To              State     `json:"to"`
	Reason          Reason    `json:"reason"`
	At              time.Time `json:"at"`
	ActorID         string    `json:"actor_id,omitempty"`
	AuthorizationID string    `json:"authorization_id,omitempty"`
	ProofID         string    `json:"proof_id,omitempty"`
	EvidenceRef     string    `json:"evidence_ref,omitempty"`
	LeaseGeneration uint64    `json:"lease_generation,omitempty"`
}

// Snapshot is the complete durable state needed to recover one Action.
type Snapshot struct {
	Schema           string           `json:"schema"`
	ActionID         string           `json:"action_id"`
	ActionDigest     string           `json:"action_digest"`
	OwnerID          string           `json:"owner_id"`
	Revision         uint64           `json:"revision"`
	State            State            `json:"state"`
	Reason           Reason           `json:"reason"`
	LeaseGeneration  uint64           `json:"lease_generation"`
	ExecutorLease    *ExecutorLease   `json:"executor_lease,omitempty"`
	ResumeCondition  *ResumeCondition `json:"resume_condition,omitempty"`
	Checkpoint       *Checkpoint      `json:"checkpoint,omitempty"`
	RecoveryPolicy   RecoveryPolicy   `json:"recovery_policy"`
	RecoveryAttempts uint32           `json:"recovery_attempts"`
	Reconciliation   *Reconciliation  `json:"reconciliation,omitempty"`
	Outcome          *Outcome         `json:"outcome,omitempty"`
	LastTransition   TransitionRecord `json:"last_transition"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// Definition contains immutable fields for a newly accepted Action.
type Definition struct {
	EventID        string
	ActionID       string
	ActionDigest   string
	OwnerID        string
	RecoveryPolicy RecoveryPolicy
	AcceptedAt     time.Time
}

// Event is an attempted compare-and-swap mutation of a Snapshot.
type Event struct {
	ID                   string
	Kind                 EventKind
	ExpectedRevision     uint64
	At                   time.Time
	Reason               Reason
	Auth                 *AuthenticatedOperation
	Fence                *LeaseFence
	Lease                *ExecutorLease
	ResumeCondition      *ResumeCondition
	Checkpoint           *Checkpoint
	EvidenceRef          string
	ReconciliationResult ReconciliationResult
	ResultRef            string
	ErrorCode            string
}

// Transition is committed atomically by a Store.
type Transition struct {
	Snapshot Snapshot
	Record   TransitionRecord
}
