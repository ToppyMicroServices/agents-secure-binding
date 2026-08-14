// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"fmt"
	"time"
)

// NewSnapshot returns the first durable ACCEPTED snapshot. The caller commits
// it with expected revision zero before acknowledging Action acceptance.
func NewSnapshot(def Definition) (Transition, error) {
	at := def.AcceptedAt.UTC()
	if def.AcceptedAt.IsZero() {
		return Transition{}, fmt.Errorf("%w: accepted_at is required", ErrInvalidEvent)
	}
	if err := validateID("event_id", def.EventID); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("action_id", def.ActionID); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateDigest("action_digest", def.ActionDigest); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("owner_id", def.OwnerID); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := def.RecoveryPolicy.Validate(); err != nil {
		return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	reason := Reason{Code: ReasonAccepted}
	record := TransitionRecord{
		EventID: def.EventID,
		Kind:    EventAccept,
		To:      StateAccepted,
		Reason:  reason,
		At:      at,
	}
	snapshot := Snapshot{
		Schema:         SchemaV1,
		ActionID:       def.ActionID,
		ActionDigest:   def.ActionDigest,
		OwnerID:        def.OwnerID,
		Revision:       1,
		State:          StateAccepted,
		Reason:         reason,
		RecoveryPolicy: def.RecoveryPolicy,
		LastTransition: record,
		CreatedAt:      at,
		UpdatedAt:      at,
	}
	if err := snapshot.Validate(); err != nil {
		return Transition{}, err
	}
	return Transition{Snapshot: snapshot, Record: record}, nil
}

// Apply validates and applies one event without performing I/O. The returned
// Snapshot and Record must be committed atomically through Store.
func Apply(current Snapshot, event Event) (Transition, error) {
	if err := current.Validate(); err != nil {
		return Transition{}, err
	}
	if event.ExpectedRevision != current.Revision {
		return Transition{}, fmt.Errorf("%w: have %d, expected %d", ErrRevisionConflict, current.Revision, event.ExpectedRevision)
	}
	if current.State.Terminal() {
		return Transition{}, fmt.Errorf("%w: %s is terminal", ErrInvalidTransition, current.State)
	}
	if err := validateEvent(current, event); err != nil {
		return Transition{}, err
	}

	next := cloneSnapshot(current)
	at := event.At.UTC()

	switch event.Kind {
	case EventStart:
		if current.State != StateAccepted {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := acquireLease(&next, event, current.LeaseGeneration+1); err != nil {
			return Transition{}, err
		}
		next.State = StateRunning

	case EventWait:
		if current.State != StateRunning {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := requireCurrentExecutor(current, event); err != nil {
			return Transition{}, err
		}
		if event.ResumeCondition == nil {
			return Transition{}, fmt.Errorf("%w: WAIT requires resume_condition", ErrInvalidEvent)
		}
		condition := *event.ResumeCondition
		if err := condition.Validate(); err != nil {
			return Transition{}, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
		if err := updateCheckpoint(&next, event.Checkpoint); err != nil {
			return Transition{}, err
		}
		next.State = StateWaiting
		next.ExecutorLease = nil
		next.ResumeCondition = &condition

	case EventPause:
		if current.State != StateRunning && current.State != StateWaiting {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if current.State == StateRunning {
			if err := requireCurrentExecutor(current, event); err != nil {
				return Transition{}, err
			}
		}
		if err := updateCheckpoint(&next, event.Checkpoint); err != nil {
			return Transition{}, err
		}
		next.State = StatePaused
		next.ExecutorLease = nil
		next.ResumeCondition = nil

	case EventResume:
		if current.State != StateWaiting && current.State != StatePaused {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if current.State == StateWaiting {
			if err := resumeSatisfied(*current.ResumeCondition, at, event.EvidenceRef); err != nil {
				return Transition{}, err
			}
		}
		if err := acquireLease(&next, event, current.LeaseGeneration+1); err != nil {
			return Transition{}, err
		}
		next.State = StateRunning
		next.ResumeCondition = nil

	case EventRequestCancel:
		switch current.State {
		case StateRunning:
			next.State = StateCanceling
		case StateAccepted, StateWaiting, StatePaused:
			next.State = StateCanceled
			next.ExecutorLease = nil
			next.ResumeCondition = nil
			next.Outcome = terminalOutcome(OutcomeCanceled, event, at)
		case StateOrphaned:
			next.State = StateIndeterminate
			next.Reconciliation = requiredReconciliation(at)
		default:
			return Transition{}, transitionError(current.State, event.Kind)
		}

	case EventComplete:
		if current.State != StateRunning && current.State != StateCanceling {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := requireCurrentExecutor(current, event); err != nil {
			return Transition{}, err
		}
		next.State = StateSucceeded
		next.ExecutorLease = nil
		next.Outcome = terminalOutcome(OutcomeSucceeded, event, at)

	case EventFail:
		if current.State != StateRunning && current.State != StateCanceling {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := requireCurrentExecutor(current, event); err != nil {
			return Transition{}, err
		}
		if err := validateID("error_code", event.ErrorCode); err != nil {
			return Transition{}, fmt.Errorf("%w: known failure requires error_code", ErrInvalidEvent)
		}
		next.State = StateFailed
		next.ExecutorLease = nil
		next.Outcome = terminalOutcome(OutcomeFailed, event, at)

	case EventConfirmCanceled:
		if current.State != StateCanceling {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := requireCurrentExecutor(current, event); err != nil {
			return Transition{}, err
		}
		next.State = StateCanceled
		next.ExecutorLease = nil
		next.Outcome = terminalOutcome(OutcomeCanceled, event, at)

	case EventMarkIndeterminate:
		if current.State != StateRunning && current.State != StateCanceling && current.State != StateOrphaned {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if current.State.RequiresExecutorLease() {
			if err := requireCurrentExecutor(current, event); err != nil {
				return Transition{}, err
			}
		}
		next.State = StateIndeterminate
		next.ExecutorLease = nil
		next.ResumeCondition = nil
		next.Reconciliation = requiredReconciliation(at)

	case EventLeaseExpired:
		if !current.State.RequiresExecutorLease() || current.ExecutorLease == nil {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if at.Before(current.ExecutorLease.ExpiresAt) {
			return Transition{}, fmt.Errorf("%w: lease remains active", ErrInvalidEvent)
		}
		next.State = StateOrphaned
		next.ExecutorLease = nil

	case EventTakeover:
		if current.State != StateOrphaned {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if current.RecoveryAttempts >= current.RecoveryPolicy.MaxAttempts {
			return Transition{}, ErrRecoveryExhausted
		}
		switch current.RecoveryPolicy.Mode {
		case RecoveryResumeFromCheckpoint:
			if current.Checkpoint == nil {
				return Transition{}, fmt.Errorf("%w: checkpoint required by recovery policy", ErrInvalidTransition)
			}
		case RecoveryRestartIdempotent:
			// RecoveryPolicy.Validate requires the bound idempotency key.
		case RecoveryReconcileBeforeResume:
			return Transition{}, ErrReconciliationRequired
		case RecoveryManual:
			if event.EvidenceRef == "" {
				return Transition{}, fmt.Errorf("%w: manual takeover requires evidence_ref", ErrInvalidEvent)
			}
		}
		if err := acquireLease(&next, event, current.LeaseGeneration+1); err != nil {
			return Transition{}, err
		}
		next.State = StateRunning
		next.RecoveryAttempts++

	case EventBeginReconciliation:
		if current.State != StateIndeterminate && current.State != StateOrphaned {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		attempt := uint32(1)
		if current.Reconciliation != nil {
			attempt = current.Reconciliation.Attempt + 1
		}
		next.State = StateIndeterminate
		next.ExecutorLease = nil
		next.Reconciliation = &Reconciliation{
			Status:    ReconciliationRunning,
			Attempt:   attempt,
			UpdatedAt: at,
		}

	case EventResolveReconciliation:
		if current.State != StateIndeterminate || current.Reconciliation == nil ||
			current.Reconciliation.Status != ReconciliationRunning {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if !validReconciliationResult(event.ReconciliationResult) || event.EvidenceRef == "" {
			return Transition{}, fmt.Errorf("%w: reconciliation result and evidence_ref are required", ErrInvalidEvent)
		}
		next.Reconciliation = &Reconciliation{
			Status:      ReconciliationResolved,
			Attempt:     current.Reconciliation.Attempt,
			EvidenceRef: event.EvidenceRef,
			Result:      event.ReconciliationResult,
			UpdatedAt:   at,
		}
		switch event.ReconciliationResult {
		case ReconciliationNoEffect:
			next.State = StatePaused
		case ReconciliationSucceeded:
			next.State = StateSucceeded
			next.Outcome = terminalOutcome(OutcomeSucceeded, event, at)
		case ReconciliationFailed:
			next.State = StateFailed
			next.Outcome = terminalOutcome(OutcomeFailed, event, at)
		case ReconciliationCanceled:
			next.State = StateCanceled
			next.Outcome = terminalOutcome(OutcomeCanceled, event, at)
		}

	case EventRenewLease:
		if !current.State.RequiresExecutorLease() {
			return Transition{}, transitionError(current.State, event.Kind)
		}
		if err := requireCurrentExecutor(current, event); err != nil {
			return Transition{}, err
		}
		if event.Lease == nil || event.Lease.LeaseID != current.ExecutorLease.LeaseID ||
			event.Lease.ExecutorID != current.ExecutorLease.ExecutorID ||
			event.Lease.Generation != current.ExecutorLease.Generation ||
			!event.Lease.IssuedAt.Equal(current.ExecutorLease.IssuedAt) ||
			!event.Lease.ExpiresAt.After(current.ExecutorLease.ExpiresAt) {
			return Transition{}, fmt.Errorf("%w: renewal must extend the current fenced lease", ErrInvalidEvent)
		}
		lease := *event.Lease
		next.ExecutorLease = &lease

	default:
		return Transition{}, fmt.Errorf("%w: unsupported event kind", ErrInvalidEvent)
	}

	next.Revision++
	next.Reason = event.Reason
	next.UpdatedAt = at
	record := transitionRecord(current, next, event)
	next.LastTransition = record
	if err := next.Validate(); err != nil {
		return Transition{}, err
	}
	return Transition{Snapshot: next, Record: record}, nil
}

func validateEvent(current Snapshot, event Event) error {
	if err := validateID("event_id", event.ID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if !validEventKind(event.Kind) || event.Kind == EventAccept {
		return fmt.Errorf("%w: unsupported mutation kind", ErrInvalidEvent)
	}
	if event.At.IsZero() || event.At.Before(current.UpdatedAt) {
		return fmt.Errorf("%w: event time precedes the durable snapshot", ErrInvalidEvent)
	}
	if err := validateReason(event.Reason); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if !reasonAllowed(event.Kind, event.Reason.Code) {
		return fmt.Errorf("%w: reason %s is not valid for %s", ErrInvalidEvent, event.Reason.Code, event.Kind)
	}
	if event.EvidenceRef != "" {
		if err := validateReference("evidence_ref", event.EvidenceRef); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	if event.ResultRef != "" {
		if err := validateReference("result_ref", event.ResultRef); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	if event.Kind == EventLeaseExpired {
		if event.Auth != nil {
			return fmt.Errorf("%w: LEASE_EXPIRED is a trusted store observation", ErrInvalidEvent)
		}
		return nil
	}
	if event.Auth == nil {
		return ErrAuthenticationRequired
	}
	return validateAuthenticatedOperation(current, event, *event.Auth)
}

func validateAuthenticatedOperation(current Snapshot, event Event, auth AuthenticatedOperation) error {
	for name, value := range map[string]string{
		"auth.actor_id":         auth.ActorID,
		"auth.authorization_id": auth.AuthorizationID,
		"auth.proof_id":         auth.ProofID,
		"auth.verifier_nonce":   auth.VerifierNonce,
	} {
		if err := validateID(name, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	if auth.Operation != event.Kind || auth.ActionID != current.ActionID || auth.ActionDigest != current.ActionDigest {
		return fmt.Errorf("%w: authenticated operation binding mismatch", ErrInvalidEvent)
	}
	if auth.IssuedAt.IsZero() || auth.ExpiresAt.IsZero() || auth.IssuedAt.After(event.At) || !auth.ExpiresAt.After(event.At) {
		return fmt.Errorf("%w: authenticated operation is not current", ErrInvalidEvent)
	}
	return nil
}

func acquireLease(next *Snapshot, event Event, generation uint64) error {
	if event.Lease == nil {
		return ErrLeaseRequired
	}
	if err := validateLease(*event.Lease); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if event.Lease.Generation != generation || !event.Lease.IssuedAt.Equal(event.At) || !event.Lease.ExpiresAt.After(event.At) {
		return fmt.Errorf("%w: new lease requires the next generation and current issue time", ErrInvalidEvent)
	}
	if event.Auth == nil || event.Auth.ActorID != event.Lease.ExecutorID {
		return fmt.Errorf("%w: authenticated actor must be the new executor", ErrInvalidEvent)
	}
	lease := *event.Lease
	next.ExecutorLease = &lease
	next.LeaseGeneration = generation
	return nil
}

func requireCurrentExecutor(current Snapshot, event Event) error {
	if current.ExecutorLease == nil || event.Fence == nil {
		return ErrLeaseRequired
	}
	if !event.At.Before(current.ExecutorLease.ExpiresAt) {
		return ErrLeaseExpired
	}
	if event.Fence.LeaseID != current.ExecutorLease.LeaseID ||
		event.Fence.ExecutorID != current.ExecutorLease.ExecutorID ||
		event.Fence.Generation != current.ExecutorLease.Generation {
		return ErrLeaseFenceMismatch
	}
	if event.Auth == nil || event.Auth.ActorID != current.ExecutorLease.ExecutorID {
		return fmt.Errorf("%w: actor is not the current executor", ErrInvalidEvent)
	}
	return nil
}

func updateCheckpoint(next *Snapshot, checkpoint *Checkpoint) error {
	if checkpoint == nil {
		return nil
	}
	if err := checkpoint.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if next.Checkpoint != nil && checkpoint.Sequence <= next.Checkpoint.Sequence {
		return fmt.Errorf("%w: checkpoint sequence must increase", ErrInvalidEvent)
	}
	checkpointCopy := *checkpoint
	next.Checkpoint = &checkpointCopy
	return nil
}

func resumeSatisfied(condition ResumeCondition, at time.Time, evidenceRef string) error {
	if condition.Type == ResumeAtTime {
		if condition.NotBefore == nil || at.Before(*condition.NotBefore) {
			return fmt.Errorf("%w: time resume condition is not satisfied", ErrInvalidTransition)
		}
		return nil
	}
	if evidenceRef == "" {
		return fmt.Errorf("%w: resume condition requires evidence_ref", ErrInvalidTransition)
	}
	return nil
}

func requiredReconciliation(at time.Time) *Reconciliation {
	return &Reconciliation{Status: ReconciliationRequired, UpdatedAt: at}
}

func terminalOutcome(status OutcomeStatus, event Event, at time.Time) *Outcome {
	return &Outcome{Status: status, ResultRef: event.ResultRef, ErrorCode: event.ErrorCode, RecordedAt: at}
}

func transitionRecord(current, next Snapshot, event Event) TransitionRecord {
	record := TransitionRecord{
		EventID:         event.ID,
		Kind:            event.Kind,
		From:            current.State,
		To:              next.State,
		Reason:          event.Reason,
		At:              event.At.UTC(),
		EvidenceRef:     event.EvidenceRef,
		LeaseGeneration: next.LeaseGeneration,
	}
	if event.Auth != nil {
		record.ActorID = event.Auth.ActorID
		record.AuthorizationID = event.Auth.AuthorizationID
		record.ProofID = event.Auth.ProofID
	}
	return record
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	if in.ExecutorLease != nil {
		value := *in.ExecutorLease
		out.ExecutorLease = &value
	}
	if in.ResumeCondition != nil {
		value := *in.ResumeCondition
		out.ResumeCondition = &value
	}
	if in.Checkpoint != nil {
		value := *in.Checkpoint
		out.Checkpoint = &value
	}
	if in.Reconciliation != nil {
		value := *in.Reconciliation
		out.Reconciliation = &value
	}
	if in.Outcome != nil {
		value := *in.Outcome
		out.Outcome = &value
	}
	return out
}

func transitionError(state State, kind EventKind) error {
	return fmt.Errorf("%w: %s cannot apply %s", ErrInvalidTransition, state, kind)
}

func reasonAllowed(kind EventKind, reason ReasonCode) bool {
	switch kind {
	case EventStart:
		return reason == ReasonStarted
	case EventWait:
		return reason == ReasonScheduled || reason == ReasonTargetBusy || reason == ReasonServerUnavailable ||
			reason == ReasonDependencyPending || reason == ReasonTimeout
	case EventPause:
		return reason == ReasonOperatorPause || reason == ReasonTimeout
	case EventResume:
		return reason == ReasonResumed
	case EventRequestCancel:
		return reason == ReasonCancelRequested
	case EventComplete:
		return reason == ReasonCompleted
	case EventFail:
		return reason == ReasonExecutionFailed
	case EventConfirmCanceled:
		return reason == ReasonCanceled
	case EventMarkIndeterminate:
		return reason == ReasonOutcomeUnknown || reason == ReasonTimeout || reason == ReasonTransportTimeout
	case EventLeaseExpired:
		return reason == ReasonLeaseExpired
	case EventTakeover:
		return reason == ReasonTakenOver
	case EventBeginReconciliation:
		return reason == ReasonReconciliationRequired
	case EventResolveReconciliation:
		return reason == ReasonReconciliationResolved
	case EventRenewLease:
		return reason == ReasonLeaseRenewed
	default:
		return false
	}
}
