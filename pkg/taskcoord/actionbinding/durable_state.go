// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const memoryStateSchema = "asb.task-action-store/v1"

type durableActionEvent struct {
	ActionID                     string                           `json:"action_id"`
	Revision                     uint64                           `json:"revision"`
	SnapshotHash                 string                           `json:"snapshot_hash"`
	Record                       actionlifecycle.TransitionRecord `json:"record"`
	AcceptanceAttemptFingerprint string                           `json:"acceptance_attempt_fingerprint,omitempty"`
	Acceptance                   *View                            `json:"acceptance,omitempty"`
}

type durableActionState struct {
	Schema             string                              `json:"schema"`
	Dependencies       []taskcoord.Dependency              `json:"dependencies"`
	Actions            map[string]actionlifecycle.Snapshot `json:"actions"`
	Bindings           map[string]Binding                  `json:"bindings"`
	ActionByAssignment map[string]string                   `json:"action_by_assignment"`
	Waits              []DependencyWait                    `json:"waits"`
	Events             map[string]durableActionEvent       `json:"events"`
}

// ExportState preserves execution, dependency, and idempotency state. Current
// Assignments are deliberately excluded: their authoritative TaskCoord rows
// must be loaded in the same durable transaction during restoration. An
// immutable original acceptance View retains its historical Assignment solely
// to recover the first canonical response and its original proof provenance.
func (s *MemoryStore) ExportState() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := durableActionState{
		Schema: memoryStateSchema, Dependencies: []taskcoord.Dependency{}, Actions: s.actions,
		Bindings: s.bindings, ActionByAssignment: s.actionByAssignment, Waits: []DependencyWait{},
		Events: make(map[string]durableActionEvent, len(s.events)),
	}
	for _, dependencies := range s.dependencies {
		state.Dependencies = append(state.Dependencies, dependencies...)
	}
	sortDependencies(state.Dependencies)
	for _, waits := range s.waits {
		for _, wait := range waits {
			state.Waits = append(state.Waits, wait)
		}
	}
	sort.Slice(state.Waits, func(i, j int) bool {
		if state.Waits[i].ActionID == state.Waits[j].ActionID {
			return state.Waits[i].ActionRevision < state.Waits[j].ActionRevision
		}
		return state.Waits[i].ActionID < state.Waits[j].ActionID
	})
	for id, event := range s.events {
		stored := durableActionEvent{
			ActionID: event.actionID, Revision: event.revision, SnapshotHash: hex.EncodeToString(event.hash[:]),
			Record: event.record, AcceptanceAttemptFingerprint: event.acceptanceAttemptFingerprint,
		}
		if event.acceptanceAttemptFingerprint != "" {
			stored.Acceptance = &View{Binding: event.acceptanceBinding, Assignment: event.acceptanceAssignment, Action: event.acceptanceAction}
		}
		state.Events[id] = stored
	}
	return json.Marshal(state)
}

// RestoreMemoryStore restores only trusted local persistence. It must never be
// exposed as a peer-input or verifier-projection decoder. Callers protect the
// storage from tampering/rollback and supply current Assignments read in the
// same transaction. Empty data creates an empty execution store. Corrupt state
// fails closed instead of discarding execution or idempotency history.
func RestoreMemoryStore(data []byte, authoritativeAssignments []taskcoord.Assignment, now func() time.Time) (*MemoryStore, error) {
	if len(data) == 0 {
		return NewMemoryStoreWithClock(authoritativeAssignments, nil, now)
	}
	if err := strictjson.ValidateDocument(data, int64(len(data))); err != nil {
		return nil, fmt.Errorf("task action binding: invalid stored state: %w", err)
	}
	var state durableActionState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("task action binding: decode stored state: %w", err)
	}
	if state.Schema != memoryStateSchema || state.Dependencies == nil || state.Actions == nil || state.Bindings == nil ||
		state.ActionByAssignment == nil || state.Waits == nil || state.Events == nil {
		return nil, fmt.Errorf("task action binding: unsupported or incomplete stored state")
	}
	store, err := NewMemoryStoreWithClock(authoritativeAssignments, state.Dependencies, now)
	if err != nil {
		return nil, err
	}
	store.actions, store.bindings, store.actionByAssignment = state.Actions, state.Bindings, state.ActionByAssignment
	if len(store.actions) != len(store.bindings) || len(store.actions) != len(store.actionByAssignment) {
		return nil, fmt.Errorf("task action binding: incomplete stored binding index")
	}
	for id, action := range store.actions {
		binding, exists := store.bindings[id]
		assignment, assignmentExists := store.assignments[binding.AssignmentID]
		if id != action.ActionID || !exists || binding.ActionID != id || !assignmentExists || store.actionByAssignment[binding.AssignmentID] != id {
			return nil, fmt.Errorf("task action binding: inconsistent stored binding %q", id)
		}
		if err := ValidateCurrent(binding, assignment, action); err != nil {
			return nil, err
		}
	}
	for id, event := range state.Events {
		hash, err := hex.DecodeString(event.SnapshotHash)
		if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != event.SnapshotHash || id != event.Record.EventID {
			return nil, fmt.Errorf("task action binding: invalid stored event %q", id)
		}
		if err := event.Record.Validate(); err != nil {
			return nil, err
		}
		stored := memoryActionCommit{actionID: event.ActionID, revision: event.Revision, hash: [sha256.Size]byte(hash), record: event.Record}
		if event.Record.Kind == actionlifecycle.EventAccept {
			if event.Revision != 1 || event.Acceptance == nil || event.Acceptance.Action.ActionID != event.ActionID ||
				validateDigest(event.AcceptanceAttemptFingerprint) != nil {
				return nil, fmt.Errorf("task action binding: incomplete stored acceptance %q", id)
			}
			view := event.Acceptance
			contextDigest, err := AcceptanceContextDigest(view.Assignment)
			if err != nil || contextDigest != event.Record.AcceptanceContextDigest {
				return nil, fmt.Errorf("task action binding: stored acceptance context mismatch %q", id)
			}
			binding, err := NewBinding(view.Assignment, actionlifecycle.Transition{Snapshot: view.Action, Record: event.Record})
			if err != nil || binding != view.Binding || store.bindings[event.ActionID] != view.Binding {
				return nil, fmt.Errorf("task action binding: invalid stored acceptance binding %q", id)
			}
			got, err := validateActionCommit(0, view.Action, event.Record)
			if err != nil || got != stored.hash {
				return nil, fmt.Errorf("task action binding: invalid stored acceptance hash %q", id)
			}
			stored.acceptanceAttemptFingerprint = event.AcceptanceAttemptFingerprint
			stored.acceptanceAssignment, stored.acceptanceAction, stored.acceptanceBinding = view.Assignment, view.Action, view.Binding
		} else if event.Acceptance != nil || event.AcceptanceAttemptFingerprint != "" {
			return nil, fmt.Errorf("task action binding: unexpected stored acceptance %q", id)
		}
		store.events[id] = stored
	}
	if err := store.validateStoredActionHistory(); err != nil {
		return nil, err
	}
	for _, wait := range state.Waits {
		if err := wait.Validate(); err != nil {
			return nil, err
		}
		action, exists := store.actions[wait.ActionID]
		if !exists || wait.ActionRevision > action.Revision || store.bindings[wait.ActionID].TaskID != wait.TaskID {
			return nil, fmt.Errorf("task action binding: inconsistent stored dependency wait")
		}
		if store.waits[wait.ActionID] == nil {
			store.waits[wait.ActionID] = make(map[uint64]DependencyWait)
		}
		if _, exists := store.waits[wait.ActionID][wait.ActionRevision]; exists {
			return nil, fmt.Errorf("task action binding: duplicate stored dependency wait")
		}
		store.waits[wait.ActionID][wait.ActionRevision] = wait
	}
	for _, event := range store.events {
		wait, hasWait := store.waits[event.actionID][event.revision]
		isWait := event.record.Kind == actionlifecycle.EventWait && event.record.Reason.Code == actionlifecycle.ReasonDependencyPending
		if hasWait != isWait || (hasWait && !wait.CreatedAt.Equal(event.record.At)) {
			return nil, fmt.Errorf("task action binding: stored dependency wait does not match history")
		}
	}
	return store, nil
}

func (s *MemoryStore) validateStoredActionHistory() error {
	byAction := make(map[string][]memoryActionCommit)
	for _, event := range s.events {
		if _, exists := s.actions[event.actionID]; !exists {
			return fmt.Errorf("task action binding: stored event has no Action")
		}
		byAction[event.actionID] = append(byAction[event.actionID], event)
	}
	for id, action := range s.actions {
		events := byAction[id]
		if uint64(len(events)) != action.Revision {
			return fmt.Errorf("task action binding: incomplete stored Action history %q", id)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].revision < events[j].revision })
		initial := events[0].acceptanceAction
		if action.ActionDigest != initial.ActionDigest || action.OwnerID != initial.OwnerID ||
			action.RecoveryPolicy != initial.RecoveryPolicy || !action.CreatedAt.Equal(initial.CreatedAt) {
			return fmt.Errorf("task action binding: stored Action rewrites acceptance identity %q", id)
		}
		for index, event := range events {
			if event.revision != uint64(index)+1 || (index == 0 && event.record.Kind != actionlifecycle.EventAccept) {
				return fmt.Errorf("task action binding: invalid stored Action revision %q", id)
			}
			if index > 0 && (events[index-1].record.To != event.record.From || event.record.At.Before(events[index-1].record.At)) {
				return fmt.Errorf("task action binding: inconsistent stored Action history %q", id)
			}
		}
		last := events[len(events)-1]
		hash, err := validateActionCommit(action.Revision-1, action, last.record)
		if err != nil || hash != last.hash {
			return fmt.Errorf("task action binding: stored Action does not match history %q", id)
		}
	}
	return nil
}

// SetDependencies replaces the dependency graph after application-owned
// authorization. It validates edge and group consistency, not a claim that the
// application is deadlock-free. A topology change during an active dependency
// wait makes the existing resume operation fail closed with a topology mismatch.
// This is a trusted application API, not a peer authorization boundary.
func (s *MemoryStore) SetDependencies(ctx context.Context, dependencies []taskcoord.Dependency) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidDependencyWait)
	}
	if _, err := taskcoord.DetectDeadlockedTasks(nil, dependencies); err != nil {
		return err
	}
	byTask := make(map[string][]taskcoord.Dependency)
	for _, dependency := range dependencies {
		byTask[dependency.FromTaskID] = append(byTask[dependency.FromTaskID], dependency)
	}
	for taskID := range byTask {
		sortDependencies(byTask[taskID])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dependencies = byTask
	return nil
}
