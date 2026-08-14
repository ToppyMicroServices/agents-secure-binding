// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidSnapshot        = errors.New("action lifecycle: invalid snapshot")
	ErrInvalidEvent           = errors.New("action lifecycle: invalid event")
	ErrInvalidTransition      = errors.New("action lifecycle: invalid transition")
	ErrRevisionConflict       = errors.New("action lifecycle: revision conflict")
	ErrLeaseRequired          = errors.New("action lifecycle: active executor lease required")
	ErrLeaseExpired           = errors.New("action lifecycle: executor lease expired")
	ErrLeaseFenceMismatch     = errors.New("action lifecycle: lease fence mismatch")
	ErrAuthenticationRequired = errors.New("action lifecycle: authenticated operation required")
	ErrReconciliationRequired = errors.New("action lifecycle: reconciliation required")
	ErrRecoveryExhausted      = errors.New("action lifecycle: recovery attempts exhausted")
)

const (
	maxIDLength        = 256
	maxDetailLength    = 1024
	maxReferenceLength = 2048
)

// Validate checks every cross-field invariant in a durable Snapshot.
func (s Snapshot) Validate() error {
	if s.Schema != SchemaV1 {
		return invalidSnapshot("unsupported schema")
	}
	if err := validateID("action_id", s.ActionID); err != nil {
		return invalidSnapshotError(err)
	}
	if err := validateDigest("action_digest", s.ActionDigest); err != nil {
		return invalidSnapshotError(err)
	}
	if err := validateID("owner_id", s.OwnerID); err != nil {
		return invalidSnapshotError(err)
	}
	if s.Revision == 0 {
		return invalidSnapshot("revision must be positive")
	}
	if !validState(s.State) {
		return invalidSnapshot("unsupported state")
	}
	if err := validateReason(s.Reason); err != nil {
		return invalidSnapshotError(err)
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() || s.UpdatedAt.Before(s.CreatedAt) {
		return invalidSnapshot("invalid snapshot timestamps")
	}
	if err := s.RecoveryPolicy.Validate(); err != nil {
		return invalidSnapshotError(err)
	}
	if s.RecoveryAttempts > s.RecoveryPolicy.MaxAttempts {
		return invalidSnapshot("recovery attempts exceed policy")
	}

	if s.State.RequiresExecutorLease() {
		if s.ExecutorLease == nil {
			return invalidSnapshotError(ErrLeaseRequired)
		}
	} else if s.ExecutorLease != nil {
		return invalidSnapshot("state must not retain an executor lease")
	}
	if s.ExecutorLease != nil {
		if err := validateLease(*s.ExecutorLease); err != nil {
			return invalidSnapshotError(err)
		}
		if s.ExecutorLease.Generation != s.LeaseGeneration {
			return invalidSnapshot("lease generation does not match fencing generation")
		}
		if s.ExecutorLease.IssuedAt.Before(s.CreatedAt) {
			return invalidSnapshot("executor lease predates Action acceptance")
		}
	}
	if s.State == StateWaiting {
		if s.ResumeCondition == nil {
			return invalidSnapshot("WAITING requires a resume condition")
		}
		if err := s.ResumeCondition.Validate(); err != nil {
			return invalidSnapshotError(err)
		}
	} else if s.ResumeCondition != nil {
		return invalidSnapshot("resume condition is only valid in WAITING")
	}
	if s.Checkpoint != nil {
		if err := s.Checkpoint.Validate(); err != nil {
			return invalidSnapshotError(err)
		}
		if s.Checkpoint.CreatedAt.After(s.UpdatedAt) {
			return invalidSnapshot("checkpoint is newer than snapshot")
		}
	}

	if s.State == StateIndeterminate {
		if s.Reconciliation == nil || s.Reconciliation.Status == ReconciliationResolved {
			return invalidSnapshot("INDETERMINATE requires unresolved reconciliation")
		}
	} else if s.Reconciliation != nil && s.Reconciliation.Status != ReconciliationResolved {
		return invalidSnapshot("unresolved reconciliation requires INDETERMINATE")
	}
	if s.Reconciliation != nil {
		if err := s.Reconciliation.Validate(); err != nil {
			return invalidSnapshotError(err)
		}
		if s.Reconciliation.UpdatedAt.After(s.UpdatedAt) {
			return invalidSnapshot("reconciliation is newer than snapshot")
		}
	}

	if s.State.Terminal() {
		if s.Outcome == nil || State(s.Outcome.Status) != s.State {
			return invalidSnapshot("terminal state requires matching known outcome")
		}
		if err := s.Outcome.Validate(); err != nil {
			return invalidSnapshotError(err)
		}
		if s.Outcome.RecordedAt.After(s.UpdatedAt) {
			return invalidSnapshot("outcome is newer than snapshot")
		}
	} else if s.Outcome != nil {
		return invalidSnapshot("non-terminal state must not contain an outcome")
	}

	if err := s.LastTransition.Validate(); err != nil {
		return invalidSnapshotError(err)
	}
	if s.LastTransition.To != s.State || s.LastTransition.Reason != s.Reason ||
		s.LastTransition.LeaseGeneration != s.LeaseGeneration || !s.LastTransition.At.Equal(s.UpdatedAt) {
		return invalidSnapshot("last transition does not match snapshot")
	}
	if s.LastTransition.Kind == EventAccept {
		if s.LastTransition.From != "" || s.LastTransition.To != StateAccepted || s.LastTransition.Reason.Code != ReasonAccepted {
			return invalidSnapshot("invalid acceptance transition")
		}
	} else if !reasonAllowed(s.LastTransition.Kind, s.LastTransition.Reason.Code) {
		return invalidSnapshot("last transition reason does not match event kind")
	}
	return nil
}

// Validate checks an immutable recovery policy.
func (p RecoveryPolicy) Validate() error {
	if p.MaxAttempts == 0 {
		return fmt.Errorf("recovery_policy.max_attempts must be positive")
	}
	switch p.Mode {
	case RecoveryResumeFromCheckpoint, RecoveryReconcileBeforeResume, RecoveryManual:
		if p.IdempotencyKey != "" {
			return fmt.Errorf("recovery_policy.idempotency_key is only valid for RESTART_IDEMPOTENT")
		}
	case RecoveryRestartIdempotent:
		if err := validateReference("recovery_policy.idempotency_key", p.IdempotencyKey); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported recovery_policy.mode")
	}
	return nil
}

// Validate checks a resume condition and rejects ambiguous mixed forms.
func (c ResumeCondition) Validate() error {
	switch c.Type {
	case ResumeAtTime:
		if c.NotBefore == nil || c.NotBefore.IsZero() || c.ProbeAfter != nil || c.Target != "" || c.DependencyActionID != "" || c.Signal != "" {
			return fmt.Errorf("TIME requires only not_before")
		}
	case ResumeTargetAvailable, ResumeServerAvailable:
		if err := validateReference("resume_condition.target", c.Target); err != nil {
			return err
		}
		if c.ProbeAfter == nil || c.ProbeAfter.IsZero() || c.NotBefore != nil || c.DependencyActionID != "" || c.Signal != "" {
			return fmt.Errorf("availability condition requires only target and probe_after")
		}
	case ResumeDependency:
		if err := validateID("resume_condition.dependency_action_id", c.DependencyActionID); err != nil {
			return err
		}
		if c.NotBefore != nil || c.ProbeAfter != nil || c.Target != "" || c.Signal != "" {
			return fmt.Errorf("DEPENDENCY requires only dependency_action_id")
		}
	case ResumeManual:
		if c.NotBefore != nil || c.ProbeAfter != nil || c.Target != "" || c.DependencyActionID != "" || c.Signal != "" {
			return fmt.Errorf("MANUAL does not accept condition fields")
		}
	case ResumeSignal:
		if err := validateID("resume_condition.signal", c.Signal); err != nil {
			return err
		}
		if c.NotBefore != nil || c.ProbeAfter != nil || c.Target != "" || c.DependencyActionID != "" {
			return fmt.Errorf("SIGNAL requires only signal")
		}
	default:
		return fmt.Errorf("unsupported resume_condition.type")
	}
	return nil
}

// Validate checks a checkpoint reference and content digest.
func (c Checkpoint) Validate() error {
	if c.Sequence == 0 {
		return fmt.Errorf("checkpoint.sequence must be positive")
	}
	if err := validateDigest("checkpoint.payload_digest", c.PayloadDigest); err != nil {
		return err
	}
	if err := validateReference("checkpoint.storage_ref", c.StorageRef); err != nil {
		return err
	}
	if c.CreatedAt.IsZero() {
		return fmt.Errorf("checkpoint.created_at is required")
	}
	return nil
}

// Validate checks a reconciliation record.
func (r Reconciliation) Validate() error {
	if r.UpdatedAt.IsZero() {
		return fmt.Errorf("reconciliation.updated_at is required")
	}
	switch r.Status {
	case ReconciliationRequired:
		if r.Attempt != 0 || r.Result != "" || r.EvidenceRef != "" {
			return fmt.Errorf("required reconciliation must not claim an attempt or result")
		}
	case ReconciliationRunning:
		if r.Attempt == 0 {
			return fmt.Errorf("running reconciliation requires an attempt")
		}
		if r.Result != "" || r.EvidenceRef != "" {
			return fmt.Errorf("unresolved reconciliation must not claim a result")
		}
	case ReconciliationResolved:
		if r.Attempt == 0 {
			return fmt.Errorf("resolved reconciliation requires an attempt")
		}
		if !validReconciliationResult(r.Result) {
			return fmt.Errorf("resolved reconciliation requires a known result")
		}
		if err := validateReference("reconciliation.evidence_ref", r.EvidenceRef); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported reconciliation.status")
	}
	return nil
}

// Validate checks a known terminal outcome.
func (o Outcome) Validate() error {
	if o.Status != OutcomeSucceeded && o.Status != OutcomeFailed && o.Status != OutcomeCanceled {
		return fmt.Errorf("unsupported outcome.status")
	}
	if o.RecordedAt.IsZero() {
		return fmt.Errorf("outcome.recorded_at is required")
	}
	if o.ResultRef != "" {
		if err := validateReference("outcome.result_ref", o.ResultRef); err != nil {
			return err
		}
	}
	if o.ErrorCode != "" {
		if err := validateID("outcome.error_code", o.ErrorCode); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks an append-only transition record.
func (r TransitionRecord) Validate() error {
	if err := validateID("last_transition.event_id", r.EventID); err != nil {
		return err
	}
	if !validEventKind(r.Kind) || !validState(r.To) || (r.From != "" && !validState(r.From)) {
		return fmt.Errorf("last_transition contains unsupported enum")
	}
	if err := validateReason(r.Reason); err != nil {
		return err
	}
	if r.At.IsZero() {
		return fmt.Errorf("last_transition.at is required")
	}
	for name, value := range map[string]string{
		"last_transition.actor_id":         r.ActorID,
		"last_transition.authorization_id": r.AuthorizationID,
		"last_transition.proof_id":         r.ProofID,
	} {
		if value != "" {
			if err := validateID(name, value); err != nil {
				return err
			}
		}
	}
	if r.EvidenceRef != "" {
		return validateReference("last_transition.evidence_ref", r.EvidenceRef)
	}
	return nil
}

func validateLease(l ExecutorLease) error {
	if err := validateID("executor_lease.lease_id", l.LeaseID); err != nil {
		return err
	}
	if err := validateID("executor_lease.executor_id", l.ExecutorID); err != nil {
		return err
	}
	if l.Generation == 0 || l.IssuedAt.IsZero() || l.ExpiresAt.IsZero() || !l.ExpiresAt.After(l.IssuedAt) {
		return fmt.Errorf("invalid executor lease generation or timestamps")
	}
	return nil
}

func validateReason(r Reason) error {
	if !validReason(r.Code) {
		return fmt.Errorf("unsupported reason.code")
	}
	if len(r.Detail) > maxDetailLength || !safeText(r.Detail) {
		return fmt.Errorf("reason.detail is unsafe or too long")
	}
	return nil
}

func validateID(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxIDLength || !safeText(value) {
		return fmt.Errorf("%s is missing, unsafe, or too long", name)
	}
	return nil
}

func validateReference(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxReferenceLength || !safeText(value) {
		return fmt.Errorf("%s is missing, unsafe, or too long", name)
	}
	return nil
}

func validateDigest(name, value string) error {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be canonical sha256 lowercase hex", name)
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil {
		return fmt.Errorf("%s must be canonical sha256 lowercase hex", name)
	}
	return nil
}

func safeText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || strings.ContainsRune(`<>&"'`, r) {
			return false
		}
	}
	return true
}

func validState(state State) bool {
	switch state {
	case StateAccepted, StateRunning, StateWaiting, StatePaused, StateOrphaned,
		StateCanceling, StateIndeterminate, StateSucceeded, StateFailed, StateCanceled:
		return true
	default:
		return false
	}
}

func validEventKind(kind EventKind) bool {
	switch kind {
	case EventAccept, EventStart, EventWait, EventPause, EventResume, EventRequestCancel,
		EventComplete, EventFail, EventConfirmCanceled, EventMarkIndeterminate,
		EventLeaseExpired, EventTakeover, EventBeginReconciliation,
		EventResolveReconciliation, EventRenewLease:
		return true
	default:
		return false
	}
}

func validReason(reason ReasonCode) bool {
	switch reason {
	case ReasonAccepted, ReasonStarted, ReasonScheduled, ReasonTargetBusy,
		ReasonServerUnavailable, ReasonDependencyPending, ReasonOperatorPause,
		ReasonResumed, ReasonCancelRequested, ReasonCompleted, ReasonExecutionFailed,
		ReasonCanceled, ReasonOutcomeUnknown, ReasonTimeout, ReasonTransportTimeout,
		ReasonLeaseExpired, ReasonTakenOver, ReasonReconciliationRequired,
		ReasonReconciliationResolved, ReasonLeaseRenewed:
		return true
	default:
		return false
	}
}

func validReconciliationResult(result ReconciliationResult) bool {
	return result == ReconciliationNoEffect || result == ReconciliationSucceeded ||
		result == ReconciliationFailed || result == ReconciliationCanceled
}

func invalidSnapshot(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidSnapshot, detail)
}

func invalidSnapshotError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidSnapshot, err)
}
