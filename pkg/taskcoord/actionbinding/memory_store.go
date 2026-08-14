// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

type memoryActionCommit struct {
	actionID string
	revision uint64
	hash     [sha256.Size]byte
	record   actionlifecycle.TransitionRecord
}

// MemoryStore is a concurrency-safe reference adapter for Service and Store
// contract tests. It performs each multi-record commit under one lock, but it
// does not survive restart and is not a production persistence adapter.
type MemoryStore struct {
	mu           sync.RWMutex
	assignments  map[string]taskcoord.Assignment
	dependencies map[string][]taskcoord.Dependency
	actions      map[string]actionlifecycle.Snapshot
	bindings     map[string]Binding
	waits        map[string]map[uint64]DependencyWait
	events       map[string]memoryActionCommit
}

// NewMemoryStore validates and copies the authoritative Assignment and
// dependency fixtures used by the reference adapter.
func NewMemoryStore(assignments []taskcoord.Assignment, dependencies []taskcoord.Dependency) (*MemoryStore, error) {
	store := &MemoryStore{
		assignments: make(map[string]taskcoord.Assignment), dependencies: make(map[string][]taskcoord.Dependency),
		actions: make(map[string]actionlifecycle.Snapshot), bindings: make(map[string]Binding),
		waits: make(map[string]map[uint64]DependencyWait), events: make(map[string]memoryActionCommit),
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

// Commit applies an ordinary Action CAS and event-ID deduplication atomically.
func (s *MemoryStore) Commit(ctx context.Context, expectedRevision uint64, next actionlifecycle.Snapshot, record actionlifecycle.TransitionRecord) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	hash, err := validateActionCommit(expectedRevision, next, record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idempotent, err := s.checkActionCommitLocked(expectedRevision, next, record, hash)
	if err != nil || idempotent {
		return err
	}
	s.writeActionCommitLocked(next, record, hash)
	return nil
}

// CommitBinding atomically compares current responsibility, creates the
// initial Action, records its event, and inserts the immutable Binding.
func (s *MemoryStore) CommitBinding(
	ctx context.Context,
	expectedAssignmentRevision uint64,
	assignment taskcoord.Assignment,
	initial actionlifecycle.Transition,
	binding Binding,
) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidBinding)
	}
	if expectedAssignmentRevision != assignment.Revision {
		return ErrStoreConflict
	}
	expectedBinding, err := NewBinding(assignment, initial)
	if err != nil {
		return err
	}
	if expectedBinding != binding {
		return fmt.Errorf("%w: Binding does not match initial snapshots", ErrInvalidBinding)
	}
	hash, err := validateActionCommit(0, initial.Snapshot, initial.Record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.compareAssignmentLocked(assignment); err != nil {
		return err
	}
	idempotent, err := s.checkActionCommitLocked(0, initial.Snapshot, initial.Record, hash)
	if err != nil {
		return err
	}
	storedBinding, bindingExists := s.bindings[binding.ActionID]
	if idempotent {
		if bindingExists && storedBinding == binding {
			return nil
		}
		return fmt.Errorf("%w: partial Binding retry", ErrStoreConflict)
	}
	if bindingExists {
		return fmt.Errorf("%w: Binding for Action %s", ErrAlreadyExists, binding.ActionID)
	}
	s.writeActionCommitLocked(initial.Snapshot, initial.Record, hash)
	s.bindings[binding.ActionID] = binding
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
	if err := validateConsecutiveAction(current, transition); err != nil {
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
	if err := s.compareInputsLocked(assignment, current, dependencies, binding); err != nil {
		return err
	}
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
	if waitExists {
		return fmt.Errorf("%w: dependency wait", ErrAlreadyExists)
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
	if err := validateConsecutiveAction(current, transition); err != nil {
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
	if err := s.compareInputsLocked(assignment, current, dependencies, binding); err != nil {
		return err
	}
	storedWait, exists := s.waits[wait.ActionID][wait.ActionRevision]
	if !exists || !sameJSON(storedWait, wait) {
		return fmt.Errorf("%w: dependency wait", ErrStoreConflict)
	}
	idempotent, err := s.checkActionCommitLocked(expectedActionRevision, transition.Snapshot, transition.Record, hash)
	if err != nil || idempotent {
		return err
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
	if !sameDependencySet(s.dependencies[binding.TaskID], dependencies) {
		return fmt.Errorf("%w: dependencies changed", ErrStoreConflict)
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

func validateConsecutiveAction(current actionlifecycle.Snapshot, transition actionlifecycle.Transition) error {
	if err := current.Validate(); err != nil {
		return err
	}
	if err := validateTransition(transition); err != nil {
		return err
	}
	next := transition.Snapshot
	if next.ActionID != current.ActionID || next.ActionDigest != current.ActionDigest ||
		next.OwnerID != current.OwnerID || !next.CreatedAt.Equal(current.CreatedAt) ||
		next.RecoveryPolicy != current.RecoveryPolicy || next.Revision != current.Revision+1 ||
		transition.Record.From != current.State {
		return fmt.Errorf("%w: Action transition is not consecutive", ErrStoreConflict)
	}
	return nil
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
