// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

// AcceptRequest contains caller-selected immutable Action fields. Owner and
// acceptance time are derived from current trusted application state.
type AcceptRequest struct {
	AssignmentID   string
	EventID        string
	ActionID       string
	ActionDigest   string
	RecoveryPolicy actionlifecycle.RecoveryPolicy
}

// View is one revalidated Task responsibility and Action execution view.
type View struct {
	Binding    Binding
	Assignment taskcoord.Assignment
	Action     actionlifecycle.Snapshot
}

// Service is the application boundary for Task-linked Actions. It loads all
// current snapshots itself and delegates every mutation to Store CAS.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService rejects a missing or typed-nil Store.
func NewService(store Store, now func() time.Time) (*Service, error) {
	if isNilStore(store) {
		return nil, ErrMissingStore
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}, nil
}

// Accept creates and atomically commits a revision-one Action and Binding for
// the current ACCEPTED Assignment.
func (s *Service) Accept(ctx context.Context, request AcceptRequest) (View, error) {
	if ctx == nil {
		return View{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	assignment, err := s.store.LoadAssignment(ctx, request.AssignmentID)
	if err != nil {
		return View{}, fmt.Errorf("load Assignment: %w", err)
	}
	initial, err := actionlifecycle.NewSnapshot(actionlifecycle.Definition{
		EventID: request.EventID, ActionID: request.ActionID, ActionDigest: request.ActionDigest,
		OwnerID: assignment.ParticipantID, RecoveryPolicy: request.RecoveryPolicy,
		AcceptedAt: s.now().UTC(),
	})
	if err != nil {
		return View{}, err
	}
	binding, err := NewBinding(assignment, initial)
	if err != nil {
		return View{}, err
	}
	if err := s.store.CommitBinding(ctx, assignment.Revision, assignment, initial, binding); err != nil {
		return View{}, fmt.Errorf("commit Action binding: %w", err)
	}
	return View{Binding: binding, Assignment: assignment, Action: initial.Snapshot}, nil
}

// Load returns a view only after revalidating the immutable identity join.
func (s *Service) Load(ctx context.Context, actionID string) (View, error) {
	if ctx == nil {
		return View{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	binding, err := s.store.LoadBinding(ctx, actionID)
	if err != nil {
		return View{}, fmt.Errorf("load Binding: %w", err)
	}
	assignment, err := s.store.LoadAssignment(ctx, binding.AssignmentID)
	if err != nil {
		return View{}, fmt.Errorf("load Assignment: %w", err)
	}
	action, err := s.store.Load(ctx, actionID)
	if err != nil {
		return View{}, fmt.Errorf("load Action: %w", err)
	}
	if err := ValidateCurrent(binding, assignment, action); err != nil {
		return View{}, err
	}
	return View{Binding: binding, Assignment: assignment, Action: action}, nil
}

// Transition applies an ordinary Action event. Dependency WAIT and RESUME
// must use their dedicated methods so topology checks and Action CAS share one
// Store transaction.
func (s *Service) Transition(ctx context.Context, actionID string, event actionlifecycle.Event) (View, error) {
	view, err := s.Load(ctx, actionID)
	if err != nil {
		return View{}, err
	}
	if event.Kind == actionlifecycle.EventWait && event.Reason.Code == actionlifecycle.ReasonDependencyPending {
		return View{}, ErrUseDependencyOperation
	}
	if event.Kind == actionlifecycle.EventResume && view.Action.ResumeCondition != nil &&
		view.Action.ResumeCondition.Type == actionlifecycle.ResumeSignal &&
		strings.HasPrefix(view.Action.ResumeCondition.Signal, dependencySignalPrefix) {
		return View{}, ErrUseDependencyOperation
	}
	if view.Assignment.Status != taskcoord.AssignmentAccepted && startsOrExtendsExecution(event.Kind) {
		return View{}, ErrAssignmentNotAccepted
	}
	transition, err := actionlifecycle.Apply(view.Action, event)
	if err != nil {
		return View{}, err
	}
	if err := s.store.Commit(ctx, view.Action.Revision, transition.Snapshot, transition.Record); err != nil {
		return View{}, fmt.Errorf("commit Action transition: %w", err)
	}
	view.Action = transition.Snapshot
	return view, nil
}

// WaitForDependencies loads current dependency state and atomically commits
// the resulting Action transition and immutable wait record.
func (s *Service) WaitForDependencies(ctx context.Context, actionID string, event actionlifecycle.Event) (View, DependencyWait, error) {
	view, err := s.Load(ctx, actionID)
	if err != nil {
		return View{}, DependencyWait{}, err
	}
	dependencies, err := s.store.ListDependencies(ctx, view.Binding.TaskID)
	if err != nil {
		return View{}, DependencyWait{}, fmt.Errorf("load dependencies: %w", err)
	}
	transition, wait, err := WaitForDependencies(view.Binding, view.Assignment, view.Action, dependencies, event)
	if err != nil {
		return View{}, DependencyWait{}, err
	}
	if err := s.store.CommitDependencyWait(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, transition, view.Binding, wait,
	); err != nil {
		return View{}, DependencyWait{}, fmt.Errorf("commit dependency wait: %w", err)
	}
	view.Action = transition.Snapshot
	return view, wait, nil
}

// ResumeDependencyWait reloads current dependency state and atomically commits
// RESUME only when the exact stored topology is satisfied.
func (s *Service) ResumeDependencyWait(ctx context.Context, actionID string, event actionlifecycle.Event) (View, error) {
	view, err := s.Load(ctx, actionID)
	if err != nil {
		return View{}, err
	}
	wait, err := s.store.LoadDependencyWait(ctx, actionID, view.Action.Revision)
	if err != nil {
		return View{}, fmt.Errorf("load dependency wait: %w", err)
	}
	dependencies, err := s.store.ListDependencies(ctx, view.Binding.TaskID)
	if err != nil {
		return View{}, fmt.Errorf("load dependencies: %w", err)
	}
	transition, err := ResumeDependencyWait(view.Binding, view.Assignment, view.Action, wait, dependencies, event)
	if err != nil {
		return View{}, err
	}
	if err := s.store.CommitDependencyResume(
		ctx, view.Assignment.Revision, view.Assignment, view.Action.Revision, view.Action,
		dependencies, transition, view.Binding, wait,
	); err != nil {
		return View{}, fmt.Errorf("commit dependency resume: %w", err)
	}
	view.Action = transition.Snapshot
	return view, nil
}

func startsOrExtendsExecution(kind actionlifecycle.EventKind) bool {
	switch kind {
	case actionlifecycle.EventStart, actionlifecycle.EventResume,
		actionlifecycle.EventTakeover, actionlifecycle.EventRenewLease:
		return true
	default:
		return false
	}
}

func isNilStore(store Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
