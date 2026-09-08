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
const testAcceptanceContextDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

var testStart = time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)

func TestNewSnapshotRequiresBoundAcceptanceAuthentication(t *testing.T) {
	t.Parallel()
	definition := Definition{
		EventID: "event-accept-auth", ActionID: "action-accept-auth", ActionDigest: testDigest,
		OwnerID: "owner-a", RecoveryPolicy: RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1},
		AcceptanceContextDigest: testAcceptanceContextDigest, AcceptedAt: testStart,
	}
	if _, err := NewSnapshot(definition); !errors.Is(err, ErrAuthenticationRequired) {
		t.Fatalf("missing acceptance authentication error = %v", err)
	}
	definition.Auth = &AuthenticatedOperation{
		ActorID: "owner-a", AuthorizationID: "authorization-accept", ProofID: "proof-accept",
		Operation: EventAccept, ActionID: definition.ActionID, ActionDigest: definition.ActionDigest,
		VerifierNonce: "nonce-accept", IssuedAt: testStart.Add(-time.Second), ExpiresAt: testStart.Add(time.Minute),
	}
	digest, err := AcceptanceRequestDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Auth.MutationDigest = digest
	transition, err := NewSnapshot(definition)
	if err != nil {
		t.Fatalf("authenticated acceptance: %v", err)
	}
	if transition.Auth == nil || transition.Record.ActorID != definition.Auth.ActorID ||
		transition.Record.MutationDigest != definition.Auth.MutationDigest {
		t.Fatalf("acceptance provenance was not retained: %+v", transition)
	}
	forged := transition.Snapshot
	forged.RecoveryPolicy.MaxAttempts++
	if err := forged.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("durable acceptance digest did not reject recovery tampering: %v", err)
	}
	tests := map[string]func(*Definition){
		"event":    func(candidate *Definition) { candidate.EventID += "-substituted" },
		"action":   func(candidate *Definition) { candidate.ActionID += "-substituted" },
		"owner":    func(candidate *Definition) { candidate.OwnerID += "-substituted" },
		"recovery": func(candidate *Definition) { candidate.RecoveryPolicy.MaxAttempts++ },
		"context": func(candidate *Definition) {
			candidate.AcceptanceContextDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := definition
			auth := *definition.Auth
			candidate.Auth = &auth
			mutate(&candidate)
			if _, err := NewSnapshot(candidate); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("mismatched acceptance authentication error = %v", err)
			}
		})
	}
}

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
	bindTestEvent(t, &early)
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

			withoutEvidence := resumeEvent(snapshot, probeAt, "executor-b", "")
			bindTestEvent(t, &withoutEvidence)
			if _, err := Apply(snapshot, withoutEvidence); !errors.Is(err, ErrInvalidTransition) {
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
	bindTestEvent(t, &fail)
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
	bindTestEvent(t, &bad)
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
	bindTestEvent(t, &stale)
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
	directTakeover := takeoverEvent(snapshot, expiry.Add(time.Minute), "executor-b")
	bindTestEvent(t, &directTakeover)
	if _, err := Apply(snapshot, directTakeover); !errors.Is(err, ErrReconciliationRequired) {
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

func TestAuthenticatedOperationBindsEntireMutation(t *testing.T) {
	snapshot := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryRestartIdempotent, MaxAttempts: 1, IdempotencyKey: "action-001"})
	at := testStart.Add(time.Minute)
	start := startEvent(snapshot, at, "executor-a")
	bindTestEvent(t, &start)

	mutated := start
	lease := *start.Lease
	lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
	mutated.Lease = &lease
	if _, err := Apply(snapshot, mutated); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("mutated lease error = %v, want %v", err, ErrInvalidEvent)
	}

	mutated = start
	mutated.ID = "event-start-substituted"
	if _, err := Apply(snapshot, mutated); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("mutated event identifier error = %v, want %v", err, ErrInvalidEvent)
	}

	tooLong := startEvent(snapshot, at, "executor-a")
	tooLong.Auth.ExpiresAt = at.Add(5 * time.Minute)
	bindTestEvent(t, &tooLong)
	if _, err := Apply(snapshot, tooLong); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("lease beyond authorization error = %v, want %v", err, ErrInvalidEvent)
	}
}

func TestTransitionRecordRequiresAuthenticatedProvenance(t *testing.T) {
	t.Parallel()
	accepted := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1})
	for name, clear := range map[string]func(*TransitionRecord){
		"accept actor":         func(record *TransitionRecord) { record.ActorID = "" },
		"accept authorization": func(record *TransitionRecord) { record.AuthorizationID = "" },
		"accept proof":         func(record *TransitionRecord) { record.ProofID = "" },
		"accept digest":        func(record *TransitionRecord) { record.MutationDigest = "" },
		"accept context":       func(record *TransitionRecord) { record.AcceptanceContextDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := accepted
			clear(&invalid.LastTransition)
			if err := invalid.Validate(); err == nil {
				t.Fatal("authenticated ACCEPT transition with missing provenance accepted")
			}
		})
	}

	running := applyTestEvent(t, accepted, startEvent(accepted, testStart.Add(time.Minute), "executor-a"))
	for name, clear := range map[string]func(*TransitionRecord){
		"actor":         func(record *TransitionRecord) { record.ActorID = "" },
		"authorization": func(record *TransitionRecord) { record.AuthorizationID = "" },
		"proof":         func(record *TransitionRecord) { record.ProofID = "" },
		"digest":        func(record *TransitionRecord) { record.MutationDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := running
			clear(&invalid.LastTransition)
			if err := invalid.Validate(); err == nil {
				t.Fatal("authenticated transition with missing provenance accepted")
			}
		})
	}
}

func TestSnapshotValidationRejectsImpossibleDurableHistory(t *testing.T) {
	t.Parallel()
	accepted := newTestSnapshot(t, RecoveryPolicy{Mode: RecoveryManual, MaxAttempts: 1})

	tests := map[string]func(Snapshot) Snapshot{
		"accept at revision two": func(snapshot Snapshot) Snapshot {
			snapshot.Revision = 2
			return snapshot
		},
		"accept with recovery state": func(snapshot Snapshot) Snapshot {
			snapshot.RecoveryAttempts = 1
			return snapshot
		},
		"accept with later updated time": func(snapshot Snapshot) Snapshot {
			snapshot.UpdatedAt = snapshot.UpdatedAt.Add(time.Second)
			snapshot.LastTransition.At = snapshot.UpdatedAt
			return snapshot
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := mutate(accepted).Validate(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSnapshot)
			}
		})
	}

	running := applyTestEvent(t, accepted, startEvent(accepted, testStart.Add(time.Minute), "executor-a"))
	running.Revision = 1
	if err := running.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("revision-one mutation error = %v, want %v", err, ErrInvalidSnapshot)
	}

	running = applyTestEvent(t, accepted, startEvent(accepted, testStart.Add(time.Minute), "executor-a"))
	running.LastTransition.From = StateFailed
	if err := running.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("impossible transition edge error = %v, want %v", err, ErrInvalidSnapshot)
	}
	raw, err := json.Marshal(running)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("DecodeSnapshot() impossible edge error = %v, want %v", err, ErrInvalidSnapshot)
	}

	causalAccepted := newTestSnapshot(t, RecoveryPolicy{
		Mode: RecoveryRestartIdempotent, MaxAttempts: 2, IdempotencyKey: "action-001",
	})
	causalRunning := applyTestEvent(t, causalAccepted, startEvent(causalAccepted, testStart.Add(time.Minute), "executor-a"))

	complete := executorEvent(causalRunning, EventComplete, testStart.Add(2*time.Minute))
	complete.Reason = Reason{Code: ReasonCompleted}
	completed := applyTestEvent(t, causalRunning, complete)

	fail := executorEvent(causalRunning, EventFail, testStart.Add(2*time.Minute))
	fail.Reason = Reason{Code: ReasonExecutionFailed}
	fail.ErrorCode = "execution-failed"
	failed := applyTestEvent(t, causalRunning, fail)

	expiry := Event{
		ID:               "event-minimum-revision-expiry",
		Kind:             EventLeaseExpired,
		ExpectedRevision: causalRunning.Revision,
		At:               causalRunning.ExecutorLease.ExpiresAt,
		Reason:           Reason{Code: ReasonLeaseExpired},
	}
	orphaned := applyTestEvent(t, causalRunning, expiry)
	takenOver := applyTestEvent(t, orphaned, takeoverEvent(
		orphaned,
		orphaned.UpdatedAt.Add(time.Minute),
		"executor-b",
	))

	tooEarly := map[string]Snapshot{
		"revision-two COMPLETE":      completed,
		"revision-two FAIL":          failed,
		"revision-two LEASE_EXPIRED": orphaned,
		"revision-two TAKEOVER":      takenOver,
	}
	for name, snapshot := range tooEarly {
		name, snapshot := name, snapshot
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot.Revision = 2
			if err := snapshot.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Validate() error = %v, want %v", err, ErrInvalidSnapshot)
			}
		})
	}
	takenOver.Revision = 3
	if err := takenOver.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("revision-three TAKEOVER error = %v, want %v", err, ErrInvalidSnapshot)
	}
	raw, err = json.Marshal(takenOver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSnapshot(bytes.NewReader(raw)); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("DecodeSnapshot() early TAKEOVER error = %v, want %v", err, ErrInvalidSnapshot)
	}
}

func TestMinimumTransitionRevision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind EventKind
		from State
		want uint64
	}{
		{name: "start", kind: EventStart, from: StateAccepted, want: 2},
		{name: "complete", kind: EventComplete, from: StateRunning, want: 3},
		{name: "resume", kind: EventResume, from: StateWaiting, want: 4},
		{name: "takeover", kind: EventTakeover, from: StateOrphaned, want: 4},
		{name: "canceling expiry", kind: EventLeaseExpired, from: StateCanceling, want: 4},
		{name: "begin reconciliation", kind: EventBeginReconciliation, from: StateIndeterminate, want: 4},
		{name: "resolve reconciliation", kind: EventResolveReconciliation, from: StateIndeterminate, want: 5},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := minimumTransitionRevision(test.kind, test.from); got != test.want {
				t.Fatalf("minimumTransitionRevision(%s, %s) = %d, want %d", test.kind, test.from, got, test.want)
			}
		})
	}
}

func TestTransitionAllowedMatchesLifecycleGraph(t *testing.T) {
	t.Parallel()
	type edge struct {
		kind     EventKind
		from, to State
	}
	allowed := map[edge]bool{
		{EventStart, StateAccepted, StateRunning}:                          true,
		{EventWait, StateRunning, StateWaiting}:                            true,
		{EventPause, StateRunning, StatePaused}:                            true,
		{EventPause, StateWaiting, StatePaused}:                            true,
		{EventResume, StateWaiting, StateRunning}:                          true,
		{EventResume, StatePaused, StateRunning}:                           true,
		{EventRequestCancel, StateRunning, StateCanceling}:                 true,
		{EventRequestCancel, StateAccepted, StateCanceled}:                 true,
		{EventRequestCancel, StateWaiting, StateCanceled}:                  true,
		{EventRequestCancel, StatePaused, StateCanceled}:                   true,
		{EventRequestCancel, StateOrphaned, StateIndeterminate}:            true,
		{EventComplete, StateRunning, StateSucceeded}:                      true,
		{EventComplete, StateCanceling, StateSucceeded}:                    true,
		{EventFail, StateRunning, StateFailed}:                             true,
		{EventFail, StateCanceling, StateFailed}:                           true,
		{EventConfirmCanceled, StateCanceling, StateCanceled}:              true,
		{EventMarkIndeterminate, StateRunning, StateIndeterminate}:         true,
		{EventMarkIndeterminate, StateCanceling, StateIndeterminate}:       true,
		{EventMarkIndeterminate, StateOrphaned, StateIndeterminate}:        true,
		{EventLeaseExpired, StateRunning, StateOrphaned}:                   true,
		{EventLeaseExpired, StateCanceling, StateOrphaned}:                 true,
		{EventTakeover, StateOrphaned, StateRunning}:                       true,
		{EventBeginReconciliation, StateIndeterminate, StateIndeterminate}: true,
		{EventBeginReconciliation, StateOrphaned, StateIndeterminate}:      true,
		{EventResolveReconciliation, StateIndeterminate, StatePaused}:      true,
		{EventResolveReconciliation, StateIndeterminate, StateSucceeded}:   true,
		{EventResolveReconciliation, StateIndeterminate, StateFailed}:      true,
		{EventResolveReconciliation, StateIndeterminate, StateCanceled}:    true,
		{EventRenewLease, StateRunning, StateRunning}:                      true,
		{EventRenewLease, StateCanceling, StateCanceling}:                  true,
	}
	kinds := []EventKind{
		EventStart, EventWait, EventPause, EventResume, EventRequestCancel,
		EventComplete, EventFail, EventConfirmCanceled, EventMarkIndeterminate,
		EventLeaseExpired, EventTakeover, EventBeginReconciliation,
		EventResolveReconciliation, EventRenewLease,
	}
	states := []State{
		StateAccepted, StateRunning, StateWaiting, StatePaused, StateOrphaned,
		StateCanceling, StateIndeterminate, StateSucceeded, StateFailed, StateCanceled,
	}
	for _, kind := range kinds {
		for _, from := range states {
			for _, to := range states {
				candidate := edge{kind: kind, from: from, to: to}
				if got := transitionAllowed(kind, from, to); got != allowed[candidate] {
					t.Fatalf("transitionAllowed(%s, %s, %s) = %t, want %t", kind, from, to, got, allowed[candidate])
				}
			}
		}
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
	definition := Definition{
		EventID: "event-accept", ActionID: "action-001", ActionDigest: testDigest,
		OwnerID: "owner-a", RecoveryPolicy: policy,
		AcceptanceContextDigest: testAcceptanceContextDigest, AcceptedAt: testStart,
		Auth: &AuthenticatedOperation{
			ActorID: "owner-a", AuthorizationID: "authorization-accept", ProofID: "proof-accept",
			Operation: EventAccept, ActionID: "action-001", ActionDigest: testDigest,
			VerifierNonce: "nonce-accept", IssuedAt: testStart.Add(-time.Second), ExpiresAt: testStart.Add(time.Minute),
		},
	}
	digest, err := AcceptanceRequestDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Auth.MutationDigest = digest
	transition, err := NewSnapshot(definition)
	if err != nil {
		t.Fatal(err)
	}
	return transition.Snapshot
}

func applyTestEvent(t *testing.T, snapshot Snapshot, event Event) Snapshot {
	t.Helper()
	if event.Auth != nil {
		bindTestEvent(t, &event)
	}
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
			VerifierNonce: "nonce-" + at.Format("150405"), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(15 * time.Minute),
		},
	}
}

func bindTestEvent(t *testing.T, event *Event) {
	t.Helper()
	digest, err := MutationRequestDigest(*event)
	if err != nil {
		t.Fatal(err)
	}
	event.Auth.MutationDigest = digest
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
