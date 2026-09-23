// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
)

const memoryStateSchema = "asb.taskcoord-store/v1"

type durableTaskEvent struct {
	AssignmentID string           `json:"assignment_id"`
	Revision     uint64           `json:"revision"`
	SnapshotHash string           `json:"snapshot_hash"`
	Record       TransitionRecord `json:"record"`
}

type durableTaskState struct {
	Schema            string                      `json:"schema"`
	Participants      map[string]Participant      `json:"participants"`
	Assignments       map[string]Assignment       `json:"assignments"`
	Delegations       map[string]DelegationRecord `json:"delegations"`
	Events            map[string]durableTaskEvent `json:"events"`
	InteractionEvents map[string]InteractionEvent `json:"interaction_events"`
	InteractionOrder  map[string][]string         `json:"interaction_order"`
}

// ExportState encodes a consistent snapshot, including immutable event
// deduplication records. Persistence, locking between processes, and atomic
// commits with other stores remain the caller's responsibility.
func (s *MemoryStore) ExportState() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := make(map[string]durableTaskEvent, len(s.events))
	for id, event := range s.events {
		events[id] = durableTaskEvent{event.assignmentID, event.revision, hex.EncodeToString(event.snapshotHash[:]), event.record}
	}
	return json.Marshal(durableTaskState{
		Schema: memoryStateSchema, Participants: s.participants, Assignments: s.assignments,
		Delegations: s.delegations, Events: events, InteractionEvents: s.interactionEvents,
		InteractionOrder: s.interactionOrder,
	})
}

// RestoreMemoryStore restores trusted local storage, never a peer request or
// an authentication projection. Empty data creates an empty store. Corrupt or
// unsupported state fails closed; it is never replaced with an empty store.
// Callers must protect the storage from tampering and rollback.
func RestoreMemoryStore(data []byte) (*MemoryStore, error) {
	store := NewMemoryStore()
	if len(data) == 0 {
		return store, nil
	}
	if err := strictjson.ValidateDocument(data, int64(len(data))); err != nil {
		return nil, fmt.Errorf("task coordination: invalid stored state: %w", err)
	}
	var state durableTaskState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, fmt.Errorf("task coordination: decode stored state: %w", err)
	}
	if state.Schema != memoryStateSchema || state.Participants == nil || state.Assignments == nil ||
		state.Delegations == nil || state.Events == nil || state.InteractionEvents == nil || state.InteractionOrder == nil {
		return nil, fmt.Errorf("task coordination: unsupported or incomplete stored state")
	}
	for id, participant := range state.Participants {
		if err := participant.Validate(); err != nil || id != participant.ParticipantID {
			return nil, fmt.Errorf("task coordination: invalid stored participant %q", id)
		}
	}
	store.participants = state.Participants
	store.assignments = state.Assignments
	store.delegations = state.Delegations
	for id, event := range state.Events {
		hash, err := hex.DecodeString(event.SnapshotHash)
		if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != event.SnapshotHash ||
			id != event.Record.EventID || event.AssignmentID != event.Record.AssignmentID || event.Revision != event.Record.Revision {
			return nil, fmt.Errorf("task coordination: invalid stored event %q", id)
		}
		if err := event.Record.Validate(); err != nil {
			return nil, fmt.Errorf("task coordination: invalid stored event %q: %w", id, err)
		}
		store.events[id] = committedEvent{event.AssignmentID, event.Revision, [sha256.Size]byte(hash), event.Record}
	}
	if err := store.validateStoredAssignments(); err != nil {
		return nil, err
	}
	// Replay each interaction in its stored order to check lineage without
	// treating historical records as fresh, currently authorized mutations.
	for interactionID, ids := range state.InteractionOrder {
		if len(ids) == 0 {
			return nil, fmt.Errorf("task coordination: empty stored interaction %q", interactionID)
		}
		for _, id := range ids {
			event, exists := state.InteractionEvents[id]
			_, duplicate := store.interactionEvents[id]
			_, conflict := store.events[id]
			assignment, assignmentExists := store.assignments[event.AssignmentID]
			_, participantExists := store.participants[event.ParticipantID]
			if !exists || duplicate || conflict || event.EventID != id || event.InteractionID != interactionID ||
				!assignmentExists || assignment.TaskID != event.TaskID || !participantExists {
				return nil, fmt.Errorf("task coordination: inconsistent stored interaction event %q", id)
			}
			if err := event.Validate(); err != nil {
				return nil, err
			}
			if err := store.validateInteractionRelations(event); err != nil {
				return nil, err
			}
			store.interactionEvents[id] = event
			store.interactionOrder[interactionID] = append(store.interactionOrder[interactionID], id)
		}
	}
	if len(store.interactionEvents) != len(state.InteractionEvents) {
		return nil, fmt.Errorf("task coordination: unindexed stored interaction events")
	}
	return store, nil
}

// Assignments returns detached authoritative snapshots sorted by identifier.
// A durable adapter uses these snapshots from the same transaction when
// reconstructing an Action store; independently cached copies are insufficient.
func (s *MemoryStore) Assignments() []Assignment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	assignments := make([]Assignment, 0, len(s.assignments))
	for _, assignment := range s.assignments {
		assignments = append(assignments, cloneAssignment(assignment))
	}
	sort.Slice(assignments, func(i, j int) bool { return assignments[i].AssignmentID < assignments[j].AssignmentID })
	return assignments
}

func (s *MemoryStore) validateStoredAssignments() error {
	byAssignment := make(map[string][]committedEvent)
	for _, event := range s.events {
		if _, exists := s.assignments[event.assignmentID]; !exists {
			return fmt.Errorf("task coordination: stored event has no Assignment")
		}
		byAssignment[event.assignmentID] = append(byAssignment[event.assignmentID], event)
	}
	snapshots := make(map[string]Assignment, len(s.events))
	initial := make(map[string]Assignment, len(s.assignments))
	for id, assignment := range s.assignments {
		if err := assignment.Validate(); err != nil || assignment.AssignmentID != id {
			return fmt.Errorf("task coordination: invalid stored Assignment %q", id)
		}
		events := byAssignment[id]
		if uint64(len(events)) != assignment.Revision {
			return fmt.Errorf("task coordination: incomplete stored Assignment history %q", id)
		}
		sort.Slice(events, func(i, j int) bool { return events[i].revision < events[j].revision })
		var previous Assignment
		for index, event := range events {
			if event.revision != uint64(index)+1 {
				return fmt.Errorf("task coordination: invalid stored Assignment revision %q", id)
			}
			next := cloneAssignment(assignment)
			next.Revision, next.Status, next.UpdatedAt, next.LastTransition = event.revision, event.record.To, event.record.At, event.record
			if index == 0 {
				next.AcceptedAt = nil
				if err := ValidateAssignmentCommit(0, next, event.record); err != nil {
					return err
				}
				initial[id] = next
			} else {
				next.AcceptedAt = previous.AcceptedAt
				if event.record.Kind == OperationAccept {
					acceptedAt := event.record.At
					next.AcceptedAt = &acceptedAt
				}
				if err := ValidateAssignmentTransition(previous, next, event.record); err != nil {
					return err
				}
			}
			hash, err := assignmentHash(next)
			if err != nil || hash != event.snapshotHash {
				return fmt.Errorf("task coordination: stored Assignment history hash mismatch %q", id)
			}
			snapshots[event.record.EventID] = next
			previous = next
		}
		got, _ := assignmentHash(previous)
		want, _ := assignmentHash(assignment)
		if got != want {
			return fmt.Errorf("task coordination: stored Assignment does not match history %q", id)
		}
	}
	for id, delegation := range s.delegations {
		parent, exists := snapshots[id]
		child, childExists := initial[delegation.ChildAssignmentID]
		if !exists || !childExists || id != delegation.EventID || parent.Revision < 2 {
			return fmt.Errorf("task coordination: incomplete stored delegation %q", id)
		}
		if err := validateDelegationTransition(parent.Revision-1, DelegationTransition{
			Parent: parent, ParentRecord: parent.LastTransition, Child: child,
			ChildRecord: child.LastTransition, Delegation: delegation,
		}); err != nil {
			return err
		}
	}
	for id, event := range s.events {
		if event.record.Kind == OperationDelegate {
			if _, exists := s.delegations[id]; !exists {
				return fmt.Errorf("task coordination: missing stored delegation %q", id)
			}
		}
	}
	return nil
}
