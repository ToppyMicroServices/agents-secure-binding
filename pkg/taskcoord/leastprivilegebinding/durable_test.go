// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilegebinding

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func durableBindingPlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("durable filesystem adapter supports Linux and macOS")
	}
}

type uncertainCommitStore struct {
	taskcoord.Store
	commits    int
	failBefore bool
}

func (s *uncertainCommitStore) CommitDelegation(ctx context.Context, revision uint64, transition taskcoord.DelegationTransition) error {
	s.commits++
	if s.failBefore {
		return errors.New("TaskCoord store unavailable before commit")
	}
	if err := s.Store.CommitDelegation(ctx, revision, transition); err != nil {
		return err
	}
	return errors.New("TaskCoord commit acknowledgment lost")
}

func TestDurableDelegationReconcilesActualCommittedEffect(t *testing.T) {
	durableBindingPlatform(t)
	f := newBindingFixture(t)
	ctx := context.Background()
	in, state := taskCoordInput(t, f)
	journal, err := lp.CreateDurableStore(filepath.Join(t.TempDir(), "journal"), 4)
	if err != nil {
		t.Fatal(err)
	}
	store := &uncertainCommitStore{Store: state}
	r, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, store)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || r.State != lp.ExecutionUnknown {
		t.Fatalf("commit ambiguity lost: %+v %v", r, err)
	}
	if _, err := state.LoadAssignment(ctx, in.Child.AssignmentID); err != nil {
		t.Fatalf("fixture did not actually commit effect: %v", err)
	}
	if _, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, store); !errors.Is(err, lp.ErrOutcomeUnknown) || store.commits != 1 {
		t.Fatalf("blind commit retry: %d %v", store.commits, err)
	}
	action, err := Action(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	request := lp.Request{ActorID: f.mandate.ActorID, TaskID: f.mandate.TaskID, Action: action}
	r, err = ReconcileDelegation(ctx, in.Event.ID, f.mandate, request, journal, state)
	if err != nil || r.State != lp.ExecutionSucceeded || r.EvidenceDigest == "" || store.commits != 1 {
		t.Fatalf("read-only authoritative reconciliation failed: %+v %d %v", r, store.commits, err)
	}
}

func TestDurableDelegationMissingEffectStaysUnknown(t *testing.T) {
	durableBindingPlatform(t)
	f := newBindingFixture(t)
	ctx := context.Background()
	in, state := taskCoordInput(t, f)
	journal, err := lp.CreateDurableStore(filepath.Join(t.TempDir(), "journal"), 4)
	if err != nil {
		t.Fatal(err)
	}
	store := &uncertainCommitStore{Store: state, failBefore: true}
	r, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, store)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || r.State != lp.ExecutionUnknown {
		t.Fatalf("failed commit did not preserve reservation: %+v %v", r, err)
	}
	action, err := Action(f.delegation)
	if err != nil {
		t.Fatal(err)
	}
	request := lp.Request{ActorID: f.mandate.ActorID, TaskID: f.mandate.TaskID, Action: action}
	r, err = ReconcileDelegation(ctx, in.Event.ID, f.mandate, request, journal, state)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || r.State != lp.ExecutionUnknown || store.commits != 1 {
		t.Fatalf("missing effect incorrectly treated as retry permission: %+v %d %v", r, store.commits, err)
	}
	wrong := request
	wrong.TaskID = "task:other"
	if _, err := ReconcileDelegation(ctx, in.Event.ID, f.mandate, wrong, journal, state); !errors.Is(err, lp.ErrBinding) {
		t.Fatalf("reconciliation binding substitution accepted: %v", err)
	}
}

func TestDurableDelegationValidatesTransitionBeforeReservation(t *testing.T) {
	durableBindingPlatform(t)
	f := newBindingFixture(t)
	ctx := context.Background()
	in, state := taskCoordInput(t, f)
	journal, err := lp.CreateDurableStore(filepath.Join(t.TempDir(), "journal"), 4)
	if err != nil {
		t.Fatal(err)
	}
	bad := in
	bad.Event.ExpectedRevision++
	if _, err := DelegateAndCommit(ctx, bad, f.capability, f.key, f.mandate, f.now, journal, state); !errors.Is(err, taskcoord.ErrRevisionConflict) {
		t.Fatalf("invalid transition admitted: %v", err)
	}
	r, err := DelegateAndCommit(ctx, in, f.capability, f.key, f.mandate, f.now, journal, state)
	if err != nil || r.State != lp.ExecutionSucceeded {
		t.Fatalf("failed preflight consumed mandate: %+v %v", r, err)
	}
}
