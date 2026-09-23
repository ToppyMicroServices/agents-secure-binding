// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
)

var (
	ctx  = context.Background()
	base = time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
)

func openTest(t *testing.T, path string, at time.Time) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return at }
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func offerFixture(t *testing.T) (taskcoord.Participant, taskcoord.Transition) {
	t.Helper()
	p := taskcoord.Participant{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:owner", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:owner", Status: taskcoord.ParticipantActive, RegisteredAt: base.Add(-time.Hour)}
	auth := taskcoord.AuthenticatedOperation{ActorID: "agent:requester", ParticipantID: p.ParticipantID, AuthorizationID: "authorization:offer", ProofID: "proof:offer", Operation: taskcoord.OperationOffer, TaskID: "task:1", AssignmentID: "assignment:1", TargetParticipantID: p.ParticipantID, VerifierNonce: "nonce:offer", IssuedAt: base.Add(-time.Minute), ExpiresAt: base.Add(time.Minute), Assurance: taskcoord.GatewayAssertedForHumanProvenance()}
	offer, err := taskcoord.Offer(taskcoord.AssignmentDefinition{EventID: "event:offer", AssignmentID: "assignment:1", TaskID: "task:1", ParticipantID: p.ParticipantID, Role: taskcoord.RoleAssignee, AuthorityDigest: strings.Repeat("a", 64), OfferedAt: base}, p, auth)
	if err != nil {
		t.Fatal(err)
	}
	return p, offer
}

func taskEvent(a taskcoord.Assignment, kind taskcoord.OperationKind, at time.Time) taskcoord.Event {
	return taskcoord.Event{ID: "event:" + string(kind), Kind: kind, ExpectedRevision: a.Revision, At: at, Auth: taskcoord.AuthenticatedOperation{ActorID: a.ParticipantID, ParticipantID: a.ParticipantID, AuthorizationID: "authorization:" + string(kind), ProofID: "proof:" + string(kind), Operation: kind, TaskID: a.TaskID, AssignmentID: a.AssignmentID, VerifierNonce: "nonce:" + string(kind), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute)}}
}

// These Action projections are trusted verifier fixtures. Actual external
// Human proof verification is exercised by the separate mTLS integration test.
func fixture(t *testing.T, s *Store) (taskcoord.Assignment, actionbinding.AcceptRequest, actionbinding.View) {
	t.Helper()
	assignment, request := uncommittedAcceptanceFixture(t, s)
	view, err := s.CommitAcceptance(ctx, assignment.Revision, assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	return assignment, request, view
}

func uncommittedAcceptanceFixture(t *testing.T, s *Store) (taskcoord.Assignment, actionbinding.AcceptRequest) {
	t.Helper()
	p, offer := offerFixture(t)
	if err := s.RegisterParticipant(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatal(err)
	}
	accepted, err := taskcoord.Apply(offer.Assignment, taskEvent(offer.Assignment, taskcoord.OperationAccept, base.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitAssignment(ctx, 1, accepted.Assignment, accepted.Record); err != nil {
		t.Fatal(err)
	}
	request := actionbinding.AcceptRequest{AssignmentID: accepted.Assignment.AssignmentID, EventID: "action:accept", ActionID: "action:1", ActionDigest: "sha256:" + strings.Repeat("b", 64), RecoveryPolicy: actionlifecycle.RecoveryPolicy{Mode: actionlifecycle.RecoveryReconcileBeforeResume, MaxAttempts: 2}}
	digest, err := actionbinding.AcceptanceRequestDigest(accepted.Assignment, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Auth = &actionlifecycle.AuthenticatedOperation{ActorID: accepted.Assignment.ParticipantID, AuthorizationID: "authorization:action", ProofID: "proof:action", Operation: actionlifecycle.EventAccept, ActionID: request.ActionID, ActionDigest: request.ActionDigest, MutationDigest: digest, VerifierNonce: "nonce:action", IssuedAt: base, ExpiresAt: base.Add(time.Hour)}
	return accepted.Assignment, request
}

func actionEvent(t *testing.T, a actionlifecycle.Snapshot, kind actionlifecycle.EventKind, at time.Time) actionlifecycle.Event {
	t.Helper()
	e := actionlifecycle.Event{ID: "action:event:" + string(kind), Kind: kind, ExpectedRevision: a.Revision, At: at, Auth: &actionlifecycle.AuthenticatedOperation{ActorID: "agent:executor", AuthorizationID: "authorization:executor", ProofID: "proof:" + string(kind), Operation: kind, ActionID: a.ActionID, ActionDigest: a.ActionDigest, VerifierNonce: "nonce:" + string(kind), IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Hour)}}
	if kind == actionlifecycle.EventStart || kind == actionlifecycle.EventResume || kind == actionlifecycle.EventTakeover {
		e.Lease = &actionlifecycle.ExecutorLease{LeaseID: "lease:" + string(kind), ExecutorID: e.Auth.ActorID, Generation: a.LeaseGeneration + 1, IssuedAt: at, ExpiresAt: at.Add(time.Minute)}
	}
	if a.ExecutorLease != nil {
		e.Fence = &actionlifecycle.LeaseFence{LeaseID: a.ExecutorLease.LeaseID, ExecutorID: a.ExecutorLease.ExecutorID, Generation: a.ExecutorLease.Generation}
	}
	switch kind {
	case actionlifecycle.EventStart:
		e.Reason.Code = actionlifecycle.ReasonStarted
	case actionlifecycle.EventResume:
		e.Reason.Code = actionlifecycle.ReasonResumed
	case actionlifecycle.EventComplete:
		e.Reason.Code = actionlifecycle.ReasonCompleted
		e.ResultRef = "urn:result:1"
	}
	bind(t, &e)
	return e
}

func bind(t *testing.T, e *actionlifecycle.Event) {
	t.Helper()
	d, err := actionlifecycle.MutationRequestDigest(*e)
	if err != nil {
		t.Fatal(err)
	}
	e.Auth.MutationDigest = d
}

func service(t *testing.T, s *Store) *actionbinding.Service {
	t.Helper()
	v, err := actionbinding.NewService(s, s.now)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRestartPreservesAcceptanceAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	a, request, first := fixture(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path, base.Add(2*time.Hour))
	got, err := s.CommitAcceptance(ctx, a.Revision, a, request)
	if err != nil || !reflect.DeepEqual(got, first) {
		t.Fatalf("exact expired retry changed canonical view: %v", err)
	}
	fresh := request
	auth := *request.Auth
	auth.ProofID = "proof:fresh"
	auth.VerifierNonce = "nonce:fresh"
	auth.IssuedAt = base.Add(time.Hour)
	auth.ExpiresAt = base.Add(3 * time.Hour)
	fresh.Auth = &auth
	if _, err = s.CommitAcceptance(ctx, a.Revision, a, fresh); !errors.Is(err, actionbinding.ErrAcceptanceReconciliationRequired) {
		t.Fatalf("fresh proof: %v", err)
	}
	revoked, err := taskcoord.Apply(a, taskEvent(a, taskcoord.OperationRevoke, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitAssignment(ctx, a.Revision, revoked.Assignment, revoked.Record); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(2*time.Hour))
	event := actionEvent(t, first.Action, actionlifecycle.EventStart, s.now())
	transition, err := actionlifecycle.Apply(first.Action, event)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitExecutionTransition(ctx, a.Revision, a, first.Action.Revision, first.Action, event, transition, first.Binding); !errors.Is(err, actionbinding.ErrStoreConflict) {
		t.Fatalf("stale assignment started after durable revoke: %v", err)
	}
	current, err := s.Load(ctx, first.Action.ActionID)
	if err != nil || current.State != actionlifecycle.StateAccepted {
		t.Fatalf("failed start wrote action: %v %#v", err, current)
	}
}

func TestIndependentHandlesSerializeRevokeAndStart(t *testing.T) {
	const revokeWinner = "revoke"
	for _, winner := range []string{revokeWinner, "start"} {
		t.Run(winner, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "coord.db")
			s := openTest(t, path, base.Add(2*time.Second))
			a, _, v := fixture(t, s)
			other := openTest(t, path, s.now())
			event := actionEvent(t, v.Action, actionlifecycle.EventStart, s.now())
			transition, err := actionlifecycle.Apply(v.Action, event)
			if err != nil {
				t.Fatal(err)
			}
			revoke, err := taskcoord.Apply(a, taskEvent(a, taskcoord.OperationRevoke, s.now()))
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- s.run(ctx, true, func(tx *transaction) error {
					close(entered)
					<-release
					if winner == revokeWinner {
						return tx.CommitAssignment(ctx, a.Revision, revoke.Assignment, revoke.Record)
					}
					return tx.actions.CommitExecutionTransition(ctx, a.Revision, a, v.Action.Revision, v.Action, event, transition, v.Binding)
				})
			}()
			<-entered
			attempted := make(chan struct{})
			loser := make(chan error, 1)
			go func() {
				close(attempted)
				if winner == revokeWinner {
					loser <- other.CommitExecutionTransition(ctx, a.Revision, a, v.Action.Revision, v.Action, event, transition, v.Binding)
				} else {
					loser <- other.CommitAssignment(ctx, a.Revision, revoke.Assignment, revoke.Record)
				}
			}()
			<-attempted
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			err = <-loser
			if winner == revokeWinner && !errors.Is(err, actionbinding.ErrStoreConflict) {
				t.Fatalf("revoke winner failed to fence start: %v", err)
			}
			if winner == "start" && err != nil {
				t.Fatal(err)
			}
			current, err := other.Load(ctx, v.Action.ActionID)
			if err != nil {
				t.Fatal(err)
			}
			want := actionlifecycle.StateAccepted
			if winner == "start" {
				want = actionlifecycle.StateRunning
			}
			if current.State != want {
				t.Fatalf("state=%s want=%s", current.State, want)
			}
			assignment, err := other.LoadAssignment(ctx, a.AssignmentID)
			if err != nil || assignment.Status != taskcoord.AssignmentRevoked {
				t.Fatalf("revoke lost: %v", err)
			}
		})
	}
}

func TestConcurrentAcceptanceReturnsFirstResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	a, r, first := fixture(t, s)
	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		other := openTest(t, path, s.now())
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := other.CommitAcceptance(ctx, a.Revision, a, r)
			if e == nil && !reflect.DeepEqual(v, first) {
				e = errors.New("canonical response changed")
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}

func TestDependencyWaitResumeAndCompletionSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	_, _, v := fixture(t, s)
	svc := service(t, s)
	v, err := svc.Transition(ctx, v.Action.ActionID, actionEvent(t, v.Action, actionlifecycle.EventStart, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	deps := []taskcoord.Dependency{{Schema: taskcoord.DependencySchemaV1, DependencyID: "dependency:1", FromTaskID: v.Binding.TaskID, ToTaskID: "task:upstream", GroupID: "group:1", Mode: taskcoord.DependencyAll, Active: true}}
	if err = s.SetDependencies(ctx, deps); err != nil {
		t.Fatal(err)
	}
	event := actionEvent(t, v.Action, actionlifecycle.EventWait, s.now())
	event.Reason.Code = actionlifecycle.ReasonDependencyPending
	signal, err := actionbinding.DependencyWaitSignal(v.Binding.TaskID, v.Binding.ActionID, v.Action.Revision+1, deps)
	if err != nil {
		t.Fatal(err)
	}
	event.ResumeCondition = &actionlifecycle.ResumeCondition{Type: actionlifecycle.ResumeSignal, Signal: signal}
	bind(t, &event)
	v, wait, err := svc.WaitForDependencies(ctx, v.Action.ActionID, event)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(3*time.Second))
	svc = service(t, s)
	stored, err := s.LoadDependencyWait(ctx, v.Action.ActionID, v.Action.Revision)
	if err != nil || !reflect.DeepEqual(stored, wait) {
		t.Fatalf("lost wait: %v", err)
	}
	resume := actionEvent(t, v.Action, actionlifecycle.EventResume, s.now())
	if _, err = svc.ResumeDependencyWait(ctx, v.Action.ActionID, resume); err == nil {
		t.Fatal("resumed unsatisfied dependency")
	}
	if err = s.SetDependencySatisfied(ctx, "dependency:1", true); err != nil {
		t.Fatal(err)
	}
	deps[0].Satisfied = true
	evidence, err := actionbinding.DependencyResumeEvidence(v.Binding, v.Assignment, v.Action, wait, deps)
	if err != nil {
		t.Fatal(err)
	}
	resume.EvidenceRef = evidence
	bind(t, &resume)
	v, err = svc.ResumeDependencyWait(ctx, v.Action.ActionID, resume)
	if err != nil {
		t.Fatal(err)
	}
	v, err = svc.Transition(ctx, v.Action.ActionID, actionEvent(t, v.Action, actionlifecycle.EventComplete, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(4*time.Second))
	final, err := service(t, s).Load(ctx, v.Action.ActionID)
	if err != nil || final.Action.State != actionlifecycle.StateSucceeded {
		t.Fatalf("completion lost: %v", err)
	}
	if final.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatal("action completion silently fulfilled assignment")
	}
}

func TestOutboxLeaseFencingBackupAndRollback(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, filepath.Join(dir, "coord.db"), base.Add(2*time.Second))
	_, _, v := fixture(t, s)
	items, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:old", LeaseID: "lease:old", Limit: 10, LeaseDuration: time.Second})
	if err != nil || len(items) != 2 {
		t.Fatalf("poll %d: %v", len(items), err)
	}
	s.now = func() time.Time { return base.Add(4 * time.Second) }
	newer, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:new", LeaseID: "lease:new", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(newer) != 2 {
		t.Fatalf("reclaim: %v", err)
	}
	if err = s.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{DeliveryID: items[0].DeliveryID, ConsumerID: "worker:old", LeaseID: "lease:old"}); !errors.Is(err, taskcoord.ErrOutboxConflict) {
		t.Fatalf("stale ack: %v", err)
	}
	if err = s.AcknowledgeOutbox(ctx, taskcoord.OutboxAcknowledgement{DeliveryID: newer[0].DeliveryID, ConsumerID: "worker:new", LeaseID: "lease:new"}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "backup.db")
	if err = s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	restored := openTest(t, backup, s.now())
	got, err := restored.Load(ctx, v.Action.ActionID)
	if err != nil || !reflect.DeepEqual(got, v.Action) {
		t.Fatalf("backup action mismatch: %v", err)
	}
	restored.now = func() time.Time { return base.Add(2 * time.Minute) }
	pending, err := restored.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:restore", LeaseID: "lease:restore", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(pending) != 1 {
		t.Fatalf("backup lost ack/lease: %d %v", len(pending), err)
	}
	if err = s.Backup(ctx, backup); err == nil {
		t.Fatal("backup overwrote existing evidence")
	}
	abort := errors.New("injected callback failure")
	err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if e := tx.MarkUsed("rollback:nonce", s.now().Add(time.Hour)); e != nil {
			return e
		}
		p, _ := offerFixture(t)
		p.ParticipantID = "human:rollback"
		if e := tx.RegisterParticipant(ctx, p); e != nil {
			return e
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if _, err = s.LoadParticipant(ctx, "human:rollback"); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("partial participant: %v", err)
	}
	if err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		return tx.MarkUsed("rollback:nonce", s.now().Add(time.Hour))
	}); err != nil {
		t.Fatalf("failed transaction burned nonce: %v", err)
	}
}

func TestEmptyOutboxPollDoesNotConsumeLeaseBudget(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_idle_state_rewrite BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT, 'idle poll rewrote state'); END`); err != nil {
		t.Fatal(err)
	}
	request := taskcoord.OutboxPoll{ConsumerID: "worker:idle", LeaseID: "lease:reusable-empty", Limit: 10, LeaseDuration: time.Minute}
	for i := 0; i < 2; i++ {
		items, err := s.PollOutbox(ctx, request)
		if err != nil || len(items) != 0 {
			t.Fatalf("empty poll %d = %d, %v", i, len(items), err)
		}
	}
	var leases int
	if err := s.db.QueryRow("SELECT count(*) FROM outbox_leases").Scan(&leases); err != nil {
		t.Fatal(err)
	}
	if leases != 0 {
		t.Fatalf("empty polls retained %d lease IDs", leases)
	}
}

func TestProcessCrashAtomicHumanOutcome(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "coord.db")
			s := openTest(t, path, base.Add(2*time.Second))
			_ = s.Close()
			runctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			command := exec.CommandContext(runctx, os.Args[0], "-test.run=^TestCrashHelper$")
			command.Env = append(os.Environ(), "ASB_SQLITE_CRASH_PATH="+path, "ASB_SQLITE_CRASH_PHASE="+phase)
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			command.Stderr = os.Stderr
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(stdout)
			if !scanner.Scan() || scanner.Text() != "CRASH_BARRIER" {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatal("child did not reach barrier")
			}
			if err = command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			s = openTest(t, path, base.Add(2*time.Second))
			_, loadErr := s.LoadAssignment(ctx, "assignment:1")
			deliveries, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:restart", LeaseID: "lease:restart", Limit: 10, LeaseDuration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			outcomeErr := s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
				_, err := tx.LookupHumanOutcome(ctx, "event:offer")
				return err
			})
			replayErr := s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error { return tx.MarkUsed("crash:nonce", base.Add(time.Hour)) })
			if phase == "before" {
				if !errors.Is(loadErr, taskcoord.ErrNotFound) || len(deliveries) != 0 || !errors.Is(outcomeErr, asbbinding.ErrHumanOutcomeNotFound) || replayErr != nil {
					t.Fatalf("partial precommit: %v %d %v %v", loadErr, len(deliveries), outcomeErr, replayErr)
				}
			} else {
				if loadErr != nil || len(deliveries) != 1 || outcomeErr != nil || !errors.Is(replayErr, identitypolicy.ErrReplayDetected) {
					t.Fatalf("lost postcommit: %v %d %v %v", loadErr, len(deliveries), outcomeErr, replayErr)
				}
			}
		})
	}
}

func TestCrashHelper(t *testing.T) {
	path := os.Getenv("ASB_SQLITE_CRASH_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s := openTest(t, path, base.Add(2*time.Second))
	p, offer := offerFixture(t)
	barrier := func() { fmt.Println("CRASH_BARRIER"); select {} }
	err := s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if err := tx.RegisterParticipant(ctx, p); err != nil {
			return err
		}
		if err := tx.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
			return err
		}
		if err := tx.MarkUsed("crash:nonce", base.Add(time.Hour)); err != nil {
			return err
		}
		response, err := json.Marshal(asbbinding.ExecuteResponse{Operation: asbbinding.OperationAssignmentOffer, Assignment: &offer.Assignment, Record: &offer.Record})
		if err != nil {
			return err
		}
		if err = tx.PutHumanOutcome(ctx, asbbinding.HumanOutcome{OperationID: offer.Record.EventID, RequestDigest: strings.Repeat("c", 64), ParticipantID: p.ParticipantID, ActorID: offer.Record.ActorID, Response: response}); err != nil {
			return err
		}
		if os.Getenv("ASB_SQLITE_CRASH_PHASE") == "before" {
			barrier()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	barrier()
}

func TestExpiredLeaseAndUnknownOutcomeRequireReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	_, _, v := fixture(t, s)
	v, err := service(t, s).Transition(ctx, v.Action.ActionID, actionEvent(t, v.Action, actionlifecycle.EventStart, s.now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service(t, s).ExpireLease(ctx, v.Action.ActionID); err == nil {
		t.Fatal("expired a live lease")
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(2*time.Minute))
	v, err = service(t, s).ExpireLease(ctx, v.Action.ActionID)
	if err != nil || v.Action.State != actionlifecycle.StateOrphaned {
		t.Fatalf("expiry: %v", err)
	}
	if _, err = service(t, s).Transition(ctx, v.Action.ActionID, actionEvent(t, v.Action, actionlifecycle.EventTakeover, s.now())); err == nil {
		t.Fatal("unknown effect restarted without reconciliation")
	}
	begin := actionEvent(t, v.Action, actionlifecycle.EventBeginReconciliation, s.now())
	begin.Reason.Code = actionlifecycle.ReasonReconciliationRequired
	bind(t, &begin)
	v, err = service(t, s).Transition(ctx, v.Action.ActionID, begin)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(3*time.Minute))
	v, err = service(t, s).Load(ctx, v.Action.ActionID)
	if err != nil || v.Action.State != actionlifecycle.StateIndeterminate || v.Action.Outcome != nil {
		t.Fatalf("unknown converted to outcome: %v", err)
	}
	// A trusted application query supplies this evidence. The database adapter
	// does not infer the external effect or invoke an execution callback.
	resolve := actionEvent(t, v.Action, actionlifecycle.EventResolveReconciliation, s.now())
	resolve.Reason.Code = actionlifecycle.ReasonReconciliationResolved
	resolve.ReconciliationResult = actionlifecycle.ReconciliationSucceeded
	resolve.EvidenceRef = "urn:authoritative-query:1"
	bind(t, &resolve)
	v, err = service(t, s).Transition(ctx, v.Action.ActionID, resolve)
	if err != nil || v.Action.State != actionlifecycle.StateSucceeded {
		t.Fatalf("resolve: %v", err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(4*time.Minute))
	v, err = service(t, s).Load(ctx, v.Action.ActionID)
	if err != nil || v.Action.Reconciliation.EvidenceRef != "urn:authoritative-query:1" {
		t.Fatalf("lost resolution: %v", err)
	}
}

func TestWriteFailureRollsBackAllRecords(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(2*time.Second))
	p, offer := offerFixture(t)
	_, err := s.db.Exec(`CREATE TRIGGER reject_state BEFORE UPDATE ON state BEGIN SELECT RAISE(ABORT, 'injected state write failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if err := tx.RegisterParticipant(ctx, p); err != nil {
			return err
		}
		if err := tx.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
			return err
		}
		return tx.MarkUsed("failure:nonce", base.Add(time.Hour))
	})
	if !errors.Is(err, taskcoord.ErrStoreUnavailable) {
		t.Fatalf("failure not propagated: %v", err)
	}
	if _, err = s.db.Exec(`DROP TRIGGER reject_state`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LoadAssignment(ctx, offer.Assignment.AssignmentID); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("partial assignment: %v", err)
	}
	if _, err = s.LoadParticipant(ctx, p.ParticipantID); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("partial participant: %v", err)
	}
	events, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:failure", LeaseID: "lease:failure", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(events) != 0 {
		t.Fatalf("partial outbox: %v", err)
	}
	if err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error { return tx.MarkUsed("failure:nonce", base.Add(time.Hour)) }); err != nil {
		t.Fatalf("partial replay: %v", err)
	}
}

func TestIgnoredOutboxFailureCannotCommitMutation(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(2*time.Second))
	p, offer := offerFixture(t)
	_, err := s.db.Exec(`CREATE TRIGGER reject_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if err := tx.RegisterParticipant(ctx, p); err != nil {
			return err
		}
		_ = tx.CommitAssignment(ctx, 0, offer.Assignment, offer.Record)
		return nil
	})
	if !errors.Is(err, taskcoord.ErrStoreUnavailable) {
		t.Fatalf("ignored error committed: %v", err)
	}
	if _, err = s.LoadParticipant(ctx, p.ParticipantID); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("partial state after ignored error: %v", err)
	}
}

func TestIndependentProcessesRetryCanonicalAcceptance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	_, _, first := fixture(t, s)
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			command := exec.CommandContext(runctx, os.Args[0], "-test.run=^TestAcceptanceProcessHelper$")
			command.Env = append(os.Environ(), "ASB_SQLITE_ACCEPT_PATH="+path)
			out, err := command.CombinedOutput()
			if err != nil {
				failures <- fmt.Errorf("process: %w: %s", err, out)
				return
			}
			failures <- nil
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	current, err := service(t, s).Load(ctx, first.Action.ActionID)
	if err != nil || !reflect.DeepEqual(current, first) {
		t.Fatalf("concurrent process mutation changed first result: %v", err)
	}
	events, err := s.PollOutbox(ctx, taskcoord.OutboxPoll{ConsumerID: "worker:process", LeaseID: "lease:process", Limit: 10, LeaseDuration: time.Minute})
	if err != nil || len(events) != 2 {
		t.Fatalf("duplicate outbox: %d %v", len(events), err)
	}
}

func TestAcceptanceProcessHelper(t *testing.T) {
	path := os.Getenv("ASB_SQLITE_ACCEPT_PATH")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s := openTest(t, path, base.Add(2*time.Second))
	fixture(t, s)
}

func TestCorruptPersistedStateFailsClosed(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "coord.db"), base.Add(2*time.Second))
	_, _, v := fixture(t, s)
	if _, err := s.db.Exec(`UPDATE state SET actions='{"schema":"unsupported"}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, v.Action.ActionID); !errors.Is(err, taskcoord.ErrStoreUnavailable) {
		t.Fatalf("corruption accepted: %v", err)
	}
	p, _ := offerFixture(t)
	p.ParticipantID = "human:new"
	if err := s.RegisterParticipant(ctx, p); !errors.Is(err, taskcoord.ErrStoreUnavailable) {
		t.Fatalf("write reset corrupt state: %v", err)
	}
}

func TestOutcomePreservesExactBytesAndIgnoredReplayRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(2*time.Second))
	p, offer := offerFixture(t)
	response, err := json.MarshalIndent(asbbinding.ExecuteResponse{Operation: asbbinding.OperationAssignmentOffer, Assignment: &offer.Assignment, Record: &offer.Record}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	outcome := asbbinding.HumanOutcome{OperationID: offer.Record.EventID, RequestDigest: strings.Repeat("c", 64), ParticipantID: offer.Record.ParticipantID, ActorID: offer.Record.ActorID, Response: response}
	if err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if err := tx.MarkUsed("nonce:used", base.Add(time.Hour)); err != nil {
			return err
		}
		return tx.PutHumanOutcome(ctx, outcome)
	}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(2*time.Second))
	if err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		got, err := tx.LookupHumanOutcome(ctx, outcome.OperationID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, outcome) {
			return errors.New("stored response bytes changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	err = s.RunHumanTransaction(ctx, func(tx asbbinding.HumanTransaction) error {
		if err := tx.RegisterParticipant(ctx, p); err != nil {
			return err
		}
		if err := tx.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
			return err
		}
		_ = tx.MarkUsed("nonce:used", base.Add(time.Hour))
		return nil
	})
	if !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("ignored replay error committed: %v", err)
	}
	if _, err = s.LoadAssignment(ctx, offer.Assignment.AssignmentID); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("replay bypass wrote assignment: %v", err)
	}
}
