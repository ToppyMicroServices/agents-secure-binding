// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var testStart = time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)

func TestWaitingTimeConditionSurvivesWithoutExecutorLease(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryRestartIdempotent, MaxAttempts: 3, IdempotencyKey: "action-001"})
	snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))

	notBefore := testStart.Add(24 * time.Hour)
	waitAt := testStart.Add(2 * time.Minute)
	wait := executorEvent(snapshot, EventWait, waitAt)
	wait.Reason = Reason{Code: ReasonScheduled}
	wait.ResumeCondition = &ResumeCondition{Type: ResumeAtTime, NotBefore: &notBefore}
	snapshot = applyTestEvent(t, snapshot, wait)
	if snapshot.State != StateWaiting || snapshot.ExecutorLease != nil || snapshot.ResumeCondition == nil {
		t.Fatalf("WAITING snapshot = %+v", snapshot)
	}

	expiry := Event{
		ID:               "event-wait-expiry",
		Kind:             EventLeaseExpired,
		ExpectedRevision: snapshot.Revision,
		At:               notBefore,
		Reason:           Reason{Code: ReasonLeaseExpired},
	}
	if _, err := Apply(snapshot, expiry); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("WAITING lease expiry error = %v, want %v", err, ErrInvalidTransition)
	}

	early := resumeEvent(snapshot, notBefore.Add(-time.Second), "executor-b", "")
	if _, err := Apply(snapshot, early); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early resume error = %v, want %v", err, ErrInvalidTransition)
	}

	snapshot = applyTestEvent(t, snapshot, resumeEvent(snapshot, notBefore, "executor-b", ""))
	if snapshot.State != StateRunning || snapshot.ExecutorLease == nil || snapshot.ExecutorLease.Generation != 2 {
		t.Fatalf("resumed snapshot = %+v", snapshot)
	}
}

func TestAvailabilityWaitRequiresEvidenceToResume(t *testing.T) {
	for _, kind := range []ResumeKind{ResumeTargetAvailable, ResumeServerAvailable} {
		t.Run(string(kind), func(t *testing.T) {
			snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryRestartIdempotent, MaxAttempts: 2, IdempotencyKey: "action-001"})
			snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))
			probeAt := testStart.Add(10 * time.Minute)
			wait := executorEvent(snapshot, EventWait, testStart.Add(2*time.Minute))
			wait.Reason = Reason{Code: ReasonTargetBusy}
			if kind == ResumeServerAvailable {
				wait.Reason.Code = ReasonServerUnavailable
			}
			wait.ResumeCondition = &ResumeCondition{Type: kind, Target: "service:target-a", ProbeAfter: &probeAt}
			snapshot = applyTestEvent(t, snapshot, wait)

			if _, err := Apply(snapshot, resumeEvent(snapshot, probeAt, "executor-b", "")); !errors.Is(err, ErrInvalidTransition) {
				t.Fatalf("resume without evidence error = %v, want %v", err, ErrInvalidTransition)
			}
			snapshot = applyTestEvent(t, snapshot, resumeEvent(snapshot, probeAt, "executor-b", "status:available:42"))
			if snapshot.State != StateRunning {
				t.Fatalf("state = %s, want %s", snapshot.State, StateRunning)
			}
		})
	}
}

func TestTimeoutCannotBecomeFailedWithoutKnownFailure(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryReconcileBeforeResume, MaxAttempts: 2})
	snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))

	fail := executorEvent(snapshot, EventFail, testStart.Add(2*time.Minute))
	fail.Reason = Reason{Code: ReasonTimeout}
	fail.ErrorCode = "timeout"
	if _, err := Apply(snapshot, fail); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("timeout failure error = %v, want %v", err, ErrInvalidEvent)
	}

	unknown := executorEvent(snapshot, EventMarkIndeterminate, testStart.Add(2*time.Minute))
	unknown.Reason = Reason{Code: ReasonTransportTimeout}
	snapshot = applyTestEvent(t, snapshot, unknown)
	if snapshot.State != StateIndeterminate || snapshot.Outcome != nil || snapshot.Reconciliation == nil {
		t.Fatalf("indeterminate snapshot = %+v", snapshot)
	}

	begin := authenticatedEvent(snapshot, EventBeginReconciliation, testStart.Add(3*time.Minute), "reconciler-a")
	begin.Reason = Reason{Code: ReasonReconciliationRequired}
	snapshot = applyTestEvent(t, snapshot, begin)
	resolve := authenticatedEvent(snapshot, EventResolveReconciliation, testStart.Add(4*time.Minute), "reconciler-a")
	resolve.Reason = Reason{Code: ReasonReconciliationResolved}
	resolve.ReconciliationResult = ReconciliationSucceeded
	resolve.EvidenceRef = "outcome:lookup:42"
	snapshot = applyTestEvent(t, snapshot, resolve)
	if snapshot.State != StateSucceeded || snapshot.Outcome == nil || snapshot.Outcome.Status != OutcomeSucceeded {
		t.Fatalf("reconciled snapshot = %+v", snapshot)
	}
}

func TestLeaseExpiryOrphansAndAuthenticatedTakeoverFencesOldExecutor(t *testing.T) {
	policy := RecoveryPolicy{Mode: RecoveryResumeFromCheckpoint, MaxAttempts: 2}
	snapshot := newTestSnapshot(t, policy)
	snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))

	checkpointAt := testStart.Add(2 * time.Minute)
	wait := executorEvent(snapshot, EventWait, checkpointAt)
	wait.Reason = Reason{Code: ReasonTargetBusy}
	probeAt := testStart.Add(3 * time.Minute)
	wait.ResumeCondition = &ResumeCondition{Type: ResumeTargetAvailable, Target: "target:a", ProbeAfter: &probeAt}
	wait.Checkpoint = &Checkpoint{
		Sequence:      1,
		PayloadDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		StorageRef:    "checkpoint:action-001:1",
		CreatedAt:     checkpointAt,
	}
	snapshot = applyTestEvent(t, snapshot, wait)
	snapshot = applyTestEvent(t, snapshot, resumeEvent(snapshot, probeAt, "executor-a", "target:available:1"))
	oldFence := fenceFor(snapshot)
	leaseExpiry := snapshot.ExecutorLease.ExpiresAt

	expired := Event{
		ID:               "event-lease-expired",
		Kind:             EventLeaseExpired,
		ExpectedRevision: snapshot.Revision,
		At:               leaseExpiry,
		Reason:           Reason{Code: ReasonLeaseExpired},
	}
	snapshot = applyTestEvent(t, snapshot, expired)
	if snapshot.State != StateOrphaned || snapshot.Outcome != nil || snapshot.ExecutorLease != nil {
		t.Fatalf("orphaned snapshot = %+v", snapshot)
	}

	takeoverAt := leaseExpiry.Add(time.Minute)
	bad := takeoverEvent(snapshot, takeoverAt, "executor-b")
	bad.Auth.ActionDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := Apply(snapshot, bad); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("unbound takeover error = %v, want %v", err, ErrInvalidEvent)
	}

	snapshot = applyTestEvent(t, snapshot, takeoverEvent(snapshot, takeoverAt, "executor-b"))
	if snapshot.State != StateRunning || snapshot.ExecutorLease.ExecutorID != "executor-b" || snapshot.RecoveryAttempts != 1 {
		t.Fatalf("takeover snapshot = %+v", snapshot)
	}

	stale := authenticatedEvent(snapshot, EventComplete, takeoverAt.Add(time.Minute), "executor-a")
	stale.Reason = Reason{Code: ReasonCompleted}
	stale.Fence = &oldFence
	if _, err := Apply(snapshot, stale); !errors.Is(err, ErrLeaseFenceMismatch) {
		t.Fatalf("stale executor error = %v, want %v", err, ErrLeaseFenceMismatch)
	}
}

func TestReconcileBeforeResumePolicyBlocksDirectTakeover(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryReconcileBeforeResume, MaxAttempts: 2})
	snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))
	expiry := snapshot.ExecutorLease.ExpiresAt
	snapshot = applyTestEvent(t, snapshot, Event{
		ID: "event-expire", Kind: EventLeaseExpired, ExpectedRevision: snapshot.Revision,
		At: expiry, Reason: Reason{Code: ReasonLeaseExpired},
	})
	if _, err := Apply(snapshot, takeoverEvent(snapshot, expiry.Add(time.Minute), "executor-b")); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("takeover error = %v, want %v", err, ErrReconciliationRequired)
	}

	begin := authenticatedEvent(snapshot, EventBeginReconciliation, expiry.Add(time.Minute), "reconciler-a")
	begin.Reason = Reason{Code: ReasonReconciliationRequired}
	snapshot = applyTestEvent(t, snapshot, begin)
	resolve := authenticatedEvent(snapshot, EventResolveReconciliation, expiry.Add(2*time.Minute), "reconciler-a")
	resolve.Reason = Reason{Code: ReasonReconciliationResolved}
	resolve.ReconciliationResult = ReconciliationNoEffect
	resolve.EvidenceRef = "target:lookup:no-effect"
	snapshot = applyTestEvent(t, snapshot, resolve)
	if snapshot.State != StatePaused || snapshot.Outcome != nil || snapshot.Reconciliation.Status != ReconciliationResolved {
		t.Fatalf("no-effect reconciliation snapshot = %+v", snapshot)
	}
}

func TestCancelRaceAllowsDurablyKnownCompletionToWin(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryRestartIdempotent, MaxAttempts: 2, IdempotencyKey: "action-001"})
	snapshot = applyTestEvent(t, snapshot, startEvent(snapshot, testStart.Add(time.Minute), "executor-a"))
	cancel := authenticatedEvent(snapshot, EventRequestCancel, testStart.Add(2*time.Minute), "owner-a")
	cancel.Reason = Reason{Code: ReasonCancelRequested}
	snapshot = applyTestEvent(t, snapshot, cancel)
	if snapshot.State != StateCanceling {
		t.Fatalf("state = %s, want %s", snapshot.State, StateCanceling)
	}
	complete := executorEvent(snapshot, EventComplete, testStart.Add(3*time.Minute))
	complete.Reason = Reason{Code: ReasonCompleted}
	snapshot = applyTestEvent(t, snapshot, complete)
	if snapshot.State != StateSucceeded {
		t.Fatalf("state = %s, want %s", snapshot.State, StateSucceeded)
	}
}

func TestRevisionAndStrictJSONValidation(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1})
	event := startEvent(snapshot, testStart.Add(time.Minute), "executor-a")
	event.ExpectedRevision--
	if _, err := Apply(snapshot, event); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("revision error = %v, want %v", err, ErrRevisionConflict)
	}

	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DecodeSnapshot() error = %v", err)
	}
	unknown := bytes.Replace(raw, []byte(`"owner_id"`), []byte(`"unknown":true,"owner_id"`), 1)
	if _, err := DecodeSnapshot(bytes.NewReader(unknown)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("unknown field error = %v, want %v", err, ErrInvalidSnapshot)
	}
	invalidUTF8 := append([]byte(nil), raw...)
	invalidUTF8[len(invalidUTF8)-2] = 0xff
	if _, err := DecodeSnapshot(bytes.NewReader(invalidUTF8)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("invalid UTF-8 error = %v, want %v", err, ErrInvalidSnapshot)
	}
}

func TestJSONSchemaIncludesAllLifecycleStates(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/action-lifecycle-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("schema JSON: %v", err)
	}
	text := string(raw)
	for _, state := range []State{
		StateAccepted, StateRunning, StateWaiting, StatePaused, StateOrphaned,
		StateCanceling, StateIndeterminate, StateSucceeded, StateFailed, StateCanceled,
	} {
		if !strings.Contains(text, `"`+string(state)+`"`) {
			t.Fatalf("schema does not contain state %s", state)
		}
	}
}

func newTestSnapshot(t *testing.T, policy RecoveryPolicy) Snapshot {
	t.Helper()
	transition, err := NewSnapshot(Definition{
		EventID: "event-accept", ActionID: "action-001", ActionDigest: testDigest,
		OwnerID: "owner-a", RecoveryPolicy: policy, AcceptedAt: testStart,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transition.Snapshot
}

func applyTestEvent(t *testing.T, snapshot Snapshot, event Event) Snapshot {
	t.Helper()
	transition, err := Apply(snapshot, event)
	if err != nil {
		t.Fatalf("Apply(%s): %v", event.Kind, err)
	}
	return transition.Snapshot
}

func startEvent(snapshot Snapshot, at time.Time, executor string) Event {
	event := authenticatedEvent(snapshot, EventStart, at, executor)
	event.Reason = Reason{Code: ReasonStarted}
	event.Lease = newLease(snapshot.LeaseGeneration+1, executor, at)
	return event
}

func resumeEvent(snapshot Snapshot, at time.Time, executor, evidence string) Event {
	event := authenticatedEvent(snapshot, EventResume, at, executor)
	event.Reason = Reason{Code: ReasonResumed}
	event.Lease = newLease(snapshot.LeaseGeneration+1, executor, at)
	event.EvidenceRef = evidence
	return event
}

func takeoverEvent(snapshot Snapshot, at time.Time, executor string) Event {
	event := authenticatedEvent(snapshot, EventTakeover, at, executor)
	event.Reason = Reason{Code: ReasonTakenOver}
	event.Lease = newLease(snapshot.LeaseGeneration+1, executor, at)
	return event
}

func executorEvent(snapshot Snapshot, kind EventKind, at time.Time) Event {
	event := authenticatedEvent(snapshot, kind, at, snapshot.ExecutorLease.ExecutorID)
	fence := fenceFor(snapshot)
	event.Fence = &fence
	return event
}

func authenticatedEvent(snapshot Snapshot, kind EventKind, at time.Time, actor string) Event {
	return Event{
		ID:               "event-" + strings.ToLower(string(kind)) + "-" + at.Format("150405"),
		Kind:             kind,
		ExpectedRevision: snapshot.Revision,
		At:               at,
		Auth: &AuthenticatedOperation{
			ActorID: actor, AuthorizationID: "authorization-001", ProofID: "proof-" + at.Format("150405"),
			Operation: kind, ActionID: snapshot.ActionID, ActionDigest: snapshot.ActionDigest,
			VerifierNonce: "nonce-" + at.Format("150405"), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
		},
	}
}

func newLease(generation uint64, executor string, at time.Time) *ExecutorLease {
	return &ExecutorLease{
		LeaseID: "lease-" + executor + "-" + at.Format("150405"), ExecutorID: executor,
		Generation: generation, IssuedAt: at, ExpiresAt: at.Add(10 * time.Minute),
	}
}

func fenceFor(snapshot Snapshot) LeaseFence {
	return LeaseFence{
		LeaseID: snapshot.ExecutorLease.LeaseID, ExecutorID: snapshot.ExecutorLease.ExecutorID,
		Generation: snapshot.ExecutorLease.Generation,
	}
}
