// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

type memoryActionCommit struct {
	actionID                     string
	revision                     uint64
	hash                         [sha256.Size]byte
	record                       actionlifecycle.TransitionRecord
	acceptanceAttemptFingerprint string
	acceptanceAssignment         taskcoord.Assignment
	acceptanceAction             actionlifecycle.Snapshot
	acceptanceBinding            Binding
}

// MemoryStore is a concurrency-safe reference adapter for Service and Store
// contract tests. It performs each multi-record commit under one lock, but it
// does not survive restart and is not a production persistence adapter.
type MemoryStore struct {
	mu                 sync.RWMutex
	now                func() time.Time
	assignments        map[string]taskcoord.Assignment
	dependencies       map[string][]taskcoord.Dependency
	actions            map[string]actionlifecycle.Snapshot
	bindings           map[string]Binding
	actionByAssignment map[string]string
	waits              map[string]map[uint64]DependencyWait
	events             map[string]memoryActionCommit
}

// NewMemoryStore validates and copies the authoritative Assignment and
// dependency fixtures used by the reference adapter.
func NewMemoryStore(assignments []taskcoord.Assignment, dependencies []taskcoord.Dependency) (*MemoryStore, error) {
	return NewMemoryStoreWithClock(assignments, dependencies, time.Now)
}

// NewMemoryStoreWithClock is the deterministic reference constructor used by
// commit-time authorization and lease-expiry tests.
func NewMemoryStoreWithClock(
	assignments []taskcoord.Assignment,
	dependencies []taskcoord.Dependency,
	now func() time.Time,
) (*MemoryStore, error) {
	if now == nil {
		return nil, fmt.Errorf("%w: transaction clock is required", ErrInvalidBinding)
	}
	store := &MemoryStore{
		now:         now,
		assignments: make(map[string]taskcoord.Assignment), dependencies: make(map[string][]taskcoord.Dependency),
		actions: make(map[string]actionlifecycle.Snapshot), bindings: make(map[string]Binding),
		actionByAssignment: make(map[string]string),
		waits:              make(map[string]map[uint64]DependencyWait), events: make(map[string]memoryActionCommit),
	}
	for _, assignment := range assignments {
		if err := assignment.Validate(); err != nil {
			return nil, err
		}
		if _, exists := store.assignments[assignment.AssignmentID]; exists {
			return nil, fmt.Errorf("%w: assignment %s", ErrAlreadyExists, assignment.AssignmentID)
		}
		store.assignments[assignment.AssignmentID] = cloneAssignment(assignment)
	}
	if _, err := taskcoord.DetectDeadlockedTasks(nil, dependencies); err != nil {
		return nil, err
	}
	for _, dependency := range dependencies {
		store.dependencies[dependency.FromTaskID] = append(store.dependencies[dependency.FromTaskID], dependency)
	}
	for taskID := range store.dependencies {
		sortDependencies(store.dependencies[taskID])
	}
	return store, nil
}

// LoadAssignment returns a detached current Assignment snapshot.
func (s *MemoryStore) LoadAssignment(ctx context.Context, assignmentID string) (taskcoord.Assignment, error) {
	if ctx == nil {
		return taskcoord.Assignment{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	assignment, exists := s.assignments[assignmentID]
	if !exists {
		return taskcoord.Assignment{}, fmt.Errorf("%w: assignment %s", ErrNotFound, assignmentID)
	}
	return cloneAssignment(assignment), nil
}

// ListDependencies returns a detached, dependency-ID-sorted Task view.
func (s *MemoryStore) ListDependencies(ctx context.Context, taskID string) ([]taskcoord.Dependency, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]taskcoord.Dependency(nil), s.dependencies[taskID]...), nil
}

// Load returns a detached current Action snapshot.
func (s *MemoryStore) Load(ctx context.Context, actionID string) (actionlifecycle.Snapshot, error) {
	if ctx == nil {
		return actionlifecycle.Snapshot{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	action, exists := s.actions[actionID]
	if !exists {
		return actionlifecycle.Snapshot{}, fmt.Errorf("%w: Action %s", ErrNotFound, actionID)
	}
	return cloneAction(action), nil
}

// LoadBinding returns one immutable Binding by Action identifier.
func (s *MemoryStore) LoadBinding(ctx context.Context, actionID string) (Binding, error) {
	if ctx == nil {
		return Binding{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, exists := s.bindings[actionID]
	if !exists {
		return Binding{}, fmt.Errorf("%w: Binding for Action %s", ErrNotFound, actionID)
	}
	return binding, nil
}

// LoadDependencyWait returns one immutable wait by Action and Action revision.
func (s *MemoryStore) LoadDependencyWait(ctx context.Context, actionID string, revision uint64) (DependencyWait, error) {
	if ctx == nil {
		return DependencyWait{}, fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	wait, exists := s.waits[actionID][revision]
	if !exists {
		return DependencyWait{}, fmt.Errorf("%w: dependency wait for Action %s revision %d", ErrNotFound, actionID, revision)
	}
	return cloneWait(wait), nil
}

// CommitAuthorizedTransition commits an ordinary authenticated Action mutation
// after rechecking the complete current snapshot and authorization/lease
// deadlines with the transaction clock.
func (s *MemoryStore) CommitAuthorizedTransition(
	ctx context.Context,
	expectedRevision uint64,
	current actionlifecycle.Snapshot,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	if expectedRevision != current.Revision {
		return ErrStoreConflict
	}
	if startsOrExtendsExecution(event.Kind) || event.Kind == actionlifecycle.EventLeaseExpired {
		return ErrWrongCommitPath
	}
	if err := validateDerivedTransition(current, event, transition); err != nil {
		return err
	}
	hash, err := validateActionCommit(expectedRevision, transition.Snapshot, transition.Record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedRevision, transition.Snapshot, transition.Record, hash)
	if err != nil || idempotent {
		return err
	}
	stored, exists := s.actions[current.ActionID]
	if !exists || !sameJSON(stored, current) {
		return fmt.Errorf("%w: Action changed", ErrStoreConflict)
	}
	if err := validateDerivedTransition(stored, event, transition); err != nil {
		return err
	}
	if err := validateAuthenticatedCommitAt(stored, event, transition, s.now().UTC()); err != nil {
		return err
	}
	s.writeActionCommitLocked(transition.Snapshot, transition.Record, hash)
	return nil
}

// CommitAcceptance owns the transaction timestamp and returns the first
// canonical committed View for an exact business request and proof attempt.
func (s *MemoryStore) CommitAcceptance(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	request AcceptRequest,
) (View, error) {
	if ctx == nil {
		return View{}, fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	if expectedAssignmentRevision != assignment.Revision {
		return View{}, ErrStoreConflict
	}
	if assignment.AssignmentID != request.AssignmentID {
		return View{}, fmt.Errorf("%w: acceptance Assignment does not match request", ErrInvalidBinding)
	}
	if err := assignment.Validate(); err != nil {
		return View{}, fmt.Errorf("%w: invalid Assignment: %v", ErrInvalidBinding, err)
	}
	if err := validateAcceptanceRequestShape(request); err != nil {
		return View{}, err
	}
	attemptFingerprint, err := AcceptanceAttemptFingerprint(request.Auth)
	if err != nil {
		return View{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if view, found, err := s.acceptanceRetryLocked(request, attemptFingerprint); found || err != nil {
		return view, err
	}
	if err := s.compareAssignmentLocked(assignment); err != nil {
		return View{}, err
	}
	storedAssignment := s.assignments[assignment.AssignmentID]
	transactionTime := s.now().UTC()
	if err := validateAcceptanceRequestAt(storedAssignment, request, transactionTime); err != nil {
		return View{}, err
	}
	definition, err := acceptanceDefinition(storedAssignment, request, transactionTime)
	if err != nil {
		return View{}, err
	}
	initial, err := actionlifecycle.NewSnapshot(definition)
	if err != nil {
		return View{}, err
	}
	binding, err := NewBinding(storedAssignment, initial)
	if err != nil {
		return View{}, err
	}
	hash, err := validateActionCommit(0, initial.Snapshot, initial.Record)
	if err != nil {
		return View{}, err
	}
	if indexedActionID, exists := s.actionByAssignment[binding.AssignmentID]; exists {
		if indexedActionID != binding.ActionID {
			return View{}, fmt.Errorf(
				"%w: Assignment %s already has Action %s",
				ErrAlreadyExists,
				binding.AssignmentID,
				indexedActionID,
			)
		}
		return View{}, fmt.Errorf("%w: partial acceptance index", ErrStoreConflict)
	}
	if _, exists := s.actions[binding.ActionID]; exists {
		return View{}, fmt.Errorf("%w: Action %s", ErrAlreadyExists, binding.ActionID)
	}
	if _, exists := s.bindings[binding.ActionID]; exists {
		return View{}, fmt.Errorf("%w: partial acceptance Binding", ErrStoreConflict)
	}
	if _, exists := s.events[initial.Record.EventID]; exists {
		return View{}, fmt.Errorf("%w: %s", ErrEventConflict, initial.Record.EventID)
	}
	s.writeAcceptanceCommitLocked(storedAssignment, initial, binding, hash, attemptFingerprint)
	return View{
		Binding:    binding,
		Assignment: cloneAssignment(storedAssignment),
		Action:     cloneAction(initial.Snapshot),
	}, nil
}

// CommitExecutionTransition atomically rechecks responsibility and execution
// state before committing an Action transition that starts or extends work.
func (s *MemoryStore) CommitExecutionTransition(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	expectedActionRevision uint64,
	current actionlifecycle.Snapshot,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
	binding Binding,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	if expectedAssignmentRevision != assignment.Revision || expectedActionRevision != current.Revision {
		return ErrStoreConflict
	}
	if assignment.Status != taskcoord.AssignmentAccepted || !startsOrExtendsExecution(event.Kind) {
		return ErrAssignmentNotAccepted
	}
	if event.Kind == actionlifecycle.EventResume && current.ResumeCondition != nil &&
		current.ResumeCondition.Type == actionlifecycle.ResumeSignal &&
		strings.HasPrefix(current.ResumeCondition.Signal, dependencySignalPrefix) {
		return ErrUseDependencyOperation
	}
	if err := ValidateCurrent(binding, assignment, current); err != nil {
		return err
	}
	if err := validateDerivedTransition(current, event, transition); err != nil {
		return err
	}
	hash, err := validateActionCommit(expectedActionRevision, transition.Snapshot, transition.Record)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedActionRevision, transition.Snapshot, transition.Record, hash)
	if err != nil || idempotent {
		return err
	}
	if err := s.compareLinkedInputsLocked(assignment, current, binding); err != nil {
		return err
	}
	stored := s.actions[current.ActionID]
	if err := validateDerivedTransition(stored, event, transition); err != nil {
		return err
	}
	if err := validateAuthenticatedCommitAt(stored, event, transition, s.now().UTC()); err != nil {
		return err
	}
	s.writeActionCommitLocked(transition.Snapshot, transition.Record, hash)
	return nil
}

// CommitDependencyWait atomically compares Assignment, Action, Binding, and
// dependencies before recording both the WAIT transition and wait document.
func (s *MemoryStore) CommitDependencyWait(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	expectedActionRevision uint64,
	current actionlifecycle.Snapshot,
	dependencies []taskcoord.Dependency,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
	binding Binding,
	wait DependencyWait,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	if expectedAssignmentRevision != assignment.Revision || expectedActionRevision != current.Revision {
		return ErrStoreConflict
	}
	if err := validateDerivedTransition(current, event, transition); err != nil {
		return err
	}
	expectedWait, err := NewDependencyWait(binding, assignment, transition, dependencies)
	if err != nil {
		return err
	}
	if !sameJSON(expectedWait, wait) {
		return fmt.Errorf("%w: wait does not match transition", ErrInvalidDependencyWait)
	}
	hash, err := validateActionCommit(expectedActionRevision, transition.Snapshot, transition.Record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedActionRevision, transition.Snapshot, transition.Record, hash)
	if err != nil {
		return err
	}
	waits := s.waits[wait.ActionID]
	storedWait, waitExists := waits[wait.ActionRevision]
	if idempotent {
		if waitExists && sameJSON(storedWait, wait) {
			return nil
		}
		return fmt.Errorf("%w: partial dependency WAIT retry", ErrStoreConflict)
	}
	if err := s.compareInputsLocked(assignment, current, dependencies, binding); err != nil {
		return err
	}
	stored := s.actions[current.ActionID]
	if err := validateDerivedTransition(stored, event, transition); err != nil {
		return err
	}
	if waitExists {
		return fmt.Errorf("%w: dependency wait", ErrAlreadyExists)
	}
	if err := validateAuthenticatedCommitAt(stored, event, transition, s.now().UTC()); err != nil {
		return err
	}
	if waits == nil {
		waits = make(map[uint64]DependencyWait)
		s.waits[wait.ActionID] = waits
	}
	s.writeActionCommitLocked(transition.Snapshot, transition.Record, hash)
	waits[wait.ActionRevision] = cloneWait(wait)
	return nil
}

// CommitDependencyResume atomically rechecks the exact satisfied topology and
// commits the RESUME transition.
func (s *MemoryStore) CommitDependencyResume(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	expectedActionRevision uint64,
	current actionlifecycle.Snapshot,
	dependencies []taskcoord.Dependency,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
	binding Binding,
	wait DependencyWait,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	if expectedAssignmentRevision != assignment.Revision || expectedActionRevision != current.Revision {
		return ErrStoreConflict
	}
	if err := validateDerivedTransition(current, event, transition); err != nil {
		return err
	}
	evidence, err := dependencyResumeEvidence(binding, assignment, current, wait, dependencies)
	if err != nil {
		return err
	}
	if transition.Record.Kind != actionlifecycle.EventResume ||
		transition.Record.From != actionlifecycle.StateWaiting ||
		transition.Record.To != actionlifecycle.StateRunning ||
		transition.Record.EvidenceRef != evidence {
		return fmt.Errorf("%w: invalid dependency RESUME transition", ErrInvalidDependencyWait)
	}
	hash, err := validateActionCommit(expectedActionRevision, transition.Snapshot, transition.Record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedActionRevision, transition.Snapshot, transition.Record, hash)
	if err != nil || idempotent {
		return err
	}
	if err := s.compareInputsLocked(assignment, current, dependencies, binding); err != nil {
		return err
	}
	stored := s.actions[current.ActionID]
	if err := validateDerivedTransition(stored, event, transition); err != nil {
		return err
	}
	storedWait, exists := s.waits[wait.ActionID][wait.ActionRevision]
	if !exists || !sameJSON(storedWait, wait) {
		return fmt.Errorf("%w: dependency wait", ErrStoreConflict)
	}
	if err := validateAuthenticatedCommitAt(stored, event, transition, s.now().UTC()); err != nil {
		return err
	}
	s.writeActionCommitLocked(transition.Snapshot, transition.Record, hash)
	return nil
}

// CommitTrustedLeaseExpiry is the only unauthenticated Action commit used by
// Service. It proves expiry from the stored lease and the transaction clock;
// caller-supplied future timestamps cannot orphan a live executor.
func (s *MemoryStore) CommitTrustedLeaseExpiry(
	ctx context.Context,
	expectedRevision uint64,
	current actionlifecycle.Snapshot,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	if expectedRevision != current.Revision || event.Kind != actionlifecycle.EventLeaseExpired {
		return ErrStoreConflict
	}
	if err := validateDerivedTransition(current, event, transition); err != nil {
		return err
	}
	hash, err := validateActionCommit(expectedRevision, transition.Snapshot, transition.Record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedRevision, transition.Snapshot, transition.Record, hash)
	if err != nil || idempotent {
		return err
	}
	stored, exists := s.actions[current.ActionID]
	if !exists || !sameJSON(stored, current) {
		return fmt.Errorf("%w: Action changed", ErrStoreConflict)
	}
	if err := validateDerivedTransition(stored, event, transition); err != nil {
		return err
	}
	if current.ExecutorLease == nil {
		return actionlifecycle.ErrLeaseRequired
	}
	now := s.now().UTC()
	if now.Before(current.ExecutorLease.ExpiresAt) {
		return fmt.Errorf("%w: lease remains active", actionlifecycle.ErrInvalidEvent)
	}
	if transition.Record.At.Before(current.ExecutorLease.ExpiresAt) || transition.Record.At.After(now) {
		return fmt.Errorf("%w: untrusted lease expiry timestamp", actionlifecycle.ErrInvalidEvent)
	}
	s.writeActionCommitLocked(transition.Snapshot, transition.Record, hash)
	return nil
}

// SetDependencySatisfied is a reference-adapter helper used by demos. A
// production deployment updates dependency state through its authenticated
// Task application transaction, not through this method.
func (s *MemoryStore) SetDependencySatisfied(ctx context.Context, dependencyID string, satisfied bool) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for taskID, dependencies := range s.dependencies {
		for index := range dependencies {
			if dependencies[index].DependencyID == dependencyID {
				dependencies[index].Satisfied = satisfied
				s.dependencies[taskID] = dependencies
				return nil
			}
		}
	}
	return fmt.Errorf("%w: dependency %s", ErrNotFound, dependencyID)
}

func (s *MemoryStore) compareInputsLocked(assignment taskcoord.Assignment, action actionlifecycle.Snapshot, dependencies []taskcoord.Dependency, binding Binding) error {
	if err := s.compareLinkedInputsLocked(assignment, action, binding); err != nil {
		return err
	}
	if !sameDependencySet(s.dependencies[binding.TaskID], dependencies) {
		return fmt.Errorf("%w: dependencies changed", ErrStoreConflict)
	}
	return nil
}

func (s *MemoryStore) compareLinkedInputsLocked(assignment taskcoord.Assignment, action actionlifecycle.Snapshot, binding Binding) error {
	if err := s.compareAssignmentLocked(assignment); err != nil {
		return err
	}
	storedAction, exists := s.actions[action.ActionID]
	if !exists || !sameJSON(storedAction, action) {
		return fmt.Errorf("%w: Action changed", ErrStoreConflict)
	}
	if storedBinding, exists := s.bindings[binding.ActionID]; !exists || storedBinding != binding {
		return fmt.Errorf("%w: Binding changed", ErrStoreConflict)
	}
	return nil
}

func (s *MemoryStore) compareAssignmentLocked(assignment taskcoord.Assignment) error {
	stored, exists := s.assignments[assignment.AssignmentID]
	if !exists || !sameJSON(stored, assignment) {
		return fmt.Errorf("%w: Assignment changed", ErrStoreConflict)
	}
	return nil
}

func (s *MemoryStore) checkActionCommitLocked(expectedRevision uint64, next actionlifecycle.Snapshot, record actionlifecycle.TransitionRecord, hash [sha256.Size]byte) (bool, error) {
	if committed, exists := s.events[record.EventID]; exists {
		if committed.actionID == next.ActionID && committed.revision == next.Revision &&
			committed.hash == hash && committed.record == record {
			return true, nil
		}
		return false, fmt.Errorf("%w: %s", ErrEventConflict, record.EventID)
	}
	current, exists := s.actions[next.ActionID]
	if expectedRevision == 0 {
		if exists {
			return false, fmt.Errorf("%w: Action %s", ErrAlreadyExists, next.ActionID)
		}
	} else if !exists || current.Revision != expectedRevision {
		return false, fmt.Errorf("%w: Action %s", ErrStoreConflict, next.ActionID)
	}
	return false, nil
}

func (s *MemoryStore) acceptanceRetryLocked(
	request AcceptRequest,
	attemptFingerprint string,
) (View, bool, error) {
	committed, exists := s.events[request.EventID]
	if !exists {
		return View{}, false, nil
	}
	if committed.revision != 1 || committed.record.Kind != actionlifecycle.EventAccept ||
		committed.actionID != request.ActionID {
		return View{}, true, fmt.Errorf("%w: %s", ErrEventConflict, request.EventID)
	}
	if committed.acceptanceAttemptFingerprint == "" || committed.acceptanceAssignment.AssignmentID == "" ||
		committed.acceptanceAction.ActionID == "" || committed.acceptanceBinding.ActionID == "" {
		return View{}, true, fmt.Errorf("%w: incomplete acceptance outcome", ErrStoreConflict)
	}
	businessDigest, err := AcceptanceRequestDigest(committed.acceptanceAssignment, request)
	if err != nil || businessDigest != committed.record.MutationDigest {
		return View{}, true, fmt.Errorf("%w: %s", ErrEventConflict, request.EventID)
	}
	if request.Auth.MutationDigest != businessDigest {
		return View{}, true, fmt.Errorf("%w: authenticated acceptance binding mismatch", actionlifecycle.ErrInvalidEvent)
	}
	if committed.acceptanceAttemptFingerprint != attemptFingerprint {
		return View{}, true, ErrAcceptanceReconciliationRequired
	}
	storedAction, actionExists := s.actions[request.ActionID]
	storedBinding, bindingExists := s.bindings[request.ActionID]
	indexedActionID, assignmentBound := s.actionByAssignment[committed.acceptanceAssignment.AssignmentID]
	if !actionExists || !bindingExists || !assignmentBound || indexedActionID != request.ActionID ||
		storedBinding != committed.acceptanceBinding {
		return View{}, true, fmt.Errorf("%w: incomplete acceptance join", ErrStoreConflict)
	}
	hash, err := validateActionCommit(0, committed.acceptanceAction, committed.record)
	if err != nil || hash != committed.hash {
		return View{}, true, fmt.Errorf("%w: invalid stored acceptance outcome", ErrStoreConflict)
	}
	if err := ValidateCurrent(committed.acceptanceBinding, committed.acceptanceAssignment, storedAction); err != nil {
		return View{}, true, fmt.Errorf("%w: current Action no longer matches acceptance: %v", ErrStoreConflict, err)
	}
	return View{
		Binding:    committed.acceptanceBinding,
		Assignment: cloneAssignment(committed.acceptanceAssignment),
		Action:     cloneAction(committed.acceptanceAction),
	}, true, nil
}

func (s *MemoryStore) writeAcceptanceCommitLocked(
	assignment taskcoord.Assignment,
	initial actionlifecycle.Transition,
	binding Binding,
	hash [sha256.Size]byte,
	attemptFingerprint string,
) {
	s.writeActionCommitLocked(initial.Snapshot, initial.Record, hash)
	committed := s.events[initial.Record.EventID]
	committed.acceptanceAttemptFingerprint = attemptFingerprint
	committed.acceptanceAssignment = cloneAssignment(assignment)
	committed.acceptanceAction = cloneAction(initial.Snapshot)
	committed.acceptanceBinding = binding
	s.events[initial.Record.EventID] = committed
	s.bindings[binding.ActionID] = binding
	s.actionByAssignment[binding.AssignmentID] = binding.ActionID
}

func (s *MemoryStore) writeActionCommitLocked(next actionlifecycle.Snapshot, record actionlifecycle.TransitionRecord, hash [sha256.Size]byte) {
	s.actions[next.ActionID] = cloneAction(next)
	s.events[record.EventID] = memoryActionCommit{
		actionID: next.ActionID, revision: next.Revision, hash: hash, record: record,
	}
}

func validateActionCommit(expectedRevision uint64, next actionlifecycle.Snapshot, record actionlifecycle.TransitionRecord) ([sha256.Size]byte, error) {
	transition := actionlifecycle.Transition{Snapshot: next, Record: record}
	if err := validateTransition(transition); err != nil {
		return [sha256.Size]byte{}, err
	}
	if next.Revision != expectedRevision+1 {
		return [sha256.Size]byte{}, fmt.Errorf("%w: next Action revision is not expected plus one", ErrStoreConflict)
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func cloneAssignment(in taskcoord.Assignment) taskcoord.Assignment {
	out := in
	if in.AcceptedAt != nil {
		acceptedAt := *in.AcceptedAt
		out.AcceptedAt = &acceptedAt
	}
	if in.DueAt != nil {
		dueAt := *in.DueAt
		out.DueAt = &dueAt
	}
	return out
}

func cloneAction(in actionlifecycle.Snapshot) actionlifecycle.Snapshot {
	out := in
	if in.ExecutorLease != nil {
		value := *in.ExecutorLease
		out.ExecutorLease = &value
	}
	if in.ResumeCondition != nil {
		value := *in.ResumeCondition
		if in.ResumeCondition.NotBefore != nil {
			notBefore := *in.ResumeCondition.NotBefore
			value.NotBefore = &notBefore
		}
		if in.ResumeCondition.ProbeAfter != nil {
			probeAfter := *in.ResumeCondition.ProbeAfter
			value.ProbeAfter = &probeAfter
		}
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

func cloneWait(in DependencyWait) DependencyWait {
	out := in
	out.DependencyIDs = append([]string(nil), in.DependencyIDs...)
	return out
}

func sameDependencySet(left, right []taskcoord.Dependency) bool {
	leftCopy := append([]taskcoord.Dependency(nil), left...)
	rightCopy := append([]taskcoord.Dependency(nil), right...)
	sortDependencies(leftCopy)
	sortDependencies(rightCopy)
	return sameJSON(leftCopy, rightCopy)
}

func sortDependencies(dependencies []taskcoord.Dependency) {
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].DependencyID < dependencies[j].DependencyID })
}

func sameJSON(left, right any) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftRaw) == string(rightRaw)
}
