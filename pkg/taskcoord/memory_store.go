// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
)

type committedEvent struct {
	assignmentID string
	revision     uint64
	snapshotHash [sha256.Size]byte
	record       TransitionRecord
}

// MemoryStore is a concurrency-safe development stub. It exercises the same
// CAS and atomic delegation contract as a durable Store but does not survive
// process restart and is not a production durability implementation.
type MemoryStore struct {
	mu                sync.RWMutex
	participants      map[string]Participant
	assignments       map[string]Assignment
	delegations       map[string]DelegationRecord
	events            map[string]committedEvent
	interactionEvents map[string]InteractionEvent
	interactionOrder  map[string][]string
}

// NewMemoryStore returns an empty in-process Store stub.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		participants:      make(map[string]Participant),
		assignments:       make(map[string]Assignment),
		delegations:       make(map[string]DelegationRecord),
		events:            make(map[string]committedEvent),
		interactionEvents: make(map[string]InteractionEvent),
		interactionOrder:  make(map[string][]string),
	}
}

// RegisterParticipant inserts an immutable participant registry record. An
// identical retry is idempotent; changing an existing identifier is rejected.
func (s *MemoryStore) RegisterParticipant(_ context.Context, participant Participant) error {
	if err := participant.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.participants[participant.ParticipantID]; ok {
		if existing == participant {
			return nil
		}
		return fmt.Errorf("%w: participant %s", ErrAlreadyExists, participant.ParticipantID)
	}
	s.participants[participant.ParticipantID] = participant
	return nil
}

// LoadParticipant returns one registered participant.
func (s *MemoryStore) LoadParticipant(_ context.Context, participantID string) (Participant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	participant, ok := s.participants[participantID]
	if !ok {
		return Participant{}, fmt.Errorf("%w: participant %s", ErrNotFound, participantID)
	}
	return participant, nil
}

// LoadAssignment returns a detached copy of one Assignment snapshot.
func (s *MemoryStore) LoadAssignment(_ context.Context, assignmentID string) (Assignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	assignment, ok := s.assignments[assignmentID]
	if !ok {
		return Assignment{}, fmt.Errorf("%w: assignment %s", ErrNotFound, assignmentID)
	}
	return cloneAssignment(assignment), nil
}

// LoadDelegation returns one immutable delegation by its event identifier.
func (s *MemoryStore) LoadDelegation(_ context.Context, eventID string) (DelegationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	delegation, ok := s.delegations[eventID]
	if !ok {
		return DelegationRecord{}, fmt.Errorf("%w: delegation %s", ErrNotFound, eventID)
	}
	return cloneDelegationRecord(delegation), nil
}

// LoadInteractionEvent returns one immutable event by its event identifier.
func (s *MemoryStore) LoadInteractionEvent(_ context.Context, eventID string) (InteractionEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.interactionEvents[eventID]
	if !ok {
		return InteractionEvent{}, fmt.Errorf("%w: interaction event %s", ErrNotFound, eventID)
	}
	return cloneInteractionEvent(event), nil
}

// ListInteractionEvents returns a detached append-order history for one
// interaction. It does not collapse corrections or withdrawals.
func (s *MemoryStore) ListInteractionEvents(_ context.Context, interactionID string) ([]InteractionEvent, error) {
	if err := validateID("interaction_id", interactionID); err != nil {
		return nil, invalidInteractionError(err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids, ok := s.interactionOrder[interactionID]
	if !ok {
		return nil, fmt.Errorf("%w: interaction %s", ErrNotFound, interactionID)
	}
	events := make([]InteractionEvent, 0, len(ids))
	for _, eventID := range ids {
		events = append(events, cloneInteractionEvent(s.interactionEvents[eventID]))
	}
	return events, nil
}

// AppendInteractionEvent appends an immutable event without modifying the
// related Assignment. An identical event-ID retry is idempotent.
func (s *MemoryStore) AppendInteractionEvent(_ context.Context, event InteractionEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.interactionEvents[event.EventID]; ok {
		if sameInteractionEvent(existing, event) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrEventConflict, event.EventID)
	}
	if _, ok := s.events[event.EventID]; ok {
		return fmt.Errorf("%w: %s", ErrEventConflict, event.EventID)
	}
	assignment, ok := s.assignments[event.AssignmentID]
	if !ok {
		return fmt.Errorf("%w: assignment %s", ErrNotFound, event.AssignmentID)
	}
	if assignment.TaskID != event.TaskID {
		return invalidInteraction("event Task does not match Assignment")
	}
	participant, ok := s.participants[event.ParticipantID]
	if !ok {
		return fmt.Errorf("%w: participant %s", ErrNotFound, event.ParticipantID)
	}
	if participant.Status != ParticipantActive {
		return ErrParticipantUnavailable
	}
	if err := s.validateInteractionRelations(event); err != nil {
		return err
	}
	s.interactionEvents[event.EventID] = cloneInteractionEvent(event)
	s.interactionOrder[event.InteractionID] = append(s.interactionOrder[event.InteractionID], event.EventID)
	return nil
}

// CommitAssignment atomically applies one initial offer or CAS transition.
func (s *MemoryStore) CommitAssignment(_ context.Context, expectedRevision uint64, next Assignment, record TransitionRecord) error {
	if err := ValidateAssignmentCommit(expectedRevision, next, record); err != nil {
		return err
	}
	if expectedRevision != 0 && record.Kind == OperationDelegate {
		return fmt.Errorf("%w: delegation requires CommitDelegation", ErrInvalidTransition)
	}
	nextHash, err := assignmentHash(next)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.interactionEvents[record.EventID]; ok {
		return fmt.Errorf("%w: %s", ErrEventConflict, record.EventID)
	}
	if committed, ok := s.events[record.EventID]; ok {
		if committed.assignmentID == next.AssignmentID &&
			committed.revision == next.Revision &&
			committed.snapshotHash == nextHash &&
			sameTransitionRecord(committed.record, record) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrEventConflict, record.EventID)
	}
	current, exists := s.assignments[next.AssignmentID]
	if expectedRevision == 0 {
		if exists {
			return fmt.Errorf("%w: assignment %s", ErrAlreadyExists, next.AssignmentID)
		}
	} else {
		if !exists || current.Revision != expectedRevision {
			return fmt.Errorf("%w: assignment %s", ErrRevisionConflict, next.AssignmentID)
		}
		if err := ValidateAssignmentTransition(current, next, record); err != nil {
			return err
		}
	}
	s.assignments[next.AssignmentID] = cloneAssignment(next)
	s.events[record.EventID] = committedEvent{
		assignmentID: next.AssignmentID,
		revision:     next.Revision,
		snapshotHash: nextHash,
		record:       cloneTransitionRecord(record),
	}
	return nil
}

// CommitDelegation atomically applies the parent audit transition, creates the
// child offer, and records the delegation provenance edge.
func (s *MemoryStore) CommitDelegation(_ context.Context, expectedParentRevision uint64, transition DelegationTransition) error {
	if err := validateDelegationTransition(expectedParentRevision, transition); err != nil {
		return err
	}
	parentHash, err := assignmentHash(transition.Parent)
	if err != nil {
		return err
	}
	childHash, err := assignmentHash(transition.Child)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.interactionEvents[transition.ParentRecord.EventID]; ok {
		return fmt.Errorf("%w: %s", ErrEventConflict, transition.ParentRecord.EventID)
	}
	if _, ok := s.interactionEvents[transition.ChildRecord.EventID]; ok {
		return fmt.Errorf("%w: %s", ErrEventConflict, transition.ChildRecord.EventID)
	}
	parentCommitted, parentSeen := s.events[transition.ParentRecord.EventID]
	childCommitted, childSeen := s.events[transition.ChildRecord.EventID]
	if parentSeen || childSeen {
		if parentSeen && childSeen &&
			parentCommitted.assignmentID == transition.Parent.AssignmentID &&
			parentCommitted.revision == transition.Parent.Revision &&
			parentCommitted.snapshotHash == parentHash &&
			sameTransitionRecord(parentCommitted.record, transition.ParentRecord) &&
			childCommitted.assignmentID == transition.Child.AssignmentID &&
			childCommitted.revision == transition.Child.Revision &&
			childCommitted.snapshotHash == childHash &&
			sameTransitionRecord(childCommitted.record, transition.ChildRecord) {
			if stored, ok := s.delegations[transition.Delegation.EventID]; ok &&
				sameDelegationRecord(stored, transition.Delegation) {
				return nil
			}
		}
		return fmt.Errorf("%w: partial or conflicting delegation retry", ErrEventConflict)
	}
	parent, ok := s.assignments[transition.Parent.AssignmentID]
	if !ok || parent.Revision != expectedParentRevision {
		return fmt.Errorf("%w: parent assignment %s", ErrRevisionConflict, transition.Parent.AssignmentID)
	}
	if err := ValidateAssignmentTransition(parent, transition.Parent, transition.ParentRecord); err != nil {
		return err
	}
	if _, exists := s.assignments[transition.Child.AssignmentID]; exists {
		return fmt.Errorf("%w: child assignment %s", ErrAlreadyExists, transition.Child.AssignmentID)
	}
	if _, exists := s.delegations[transition.Delegation.EventID]; exists {
		return fmt.Errorf("%w: delegation %s", ErrAlreadyExists, transition.Delegation.EventID)
	}

	s.assignments[transition.Parent.AssignmentID] = cloneAssignment(transition.Parent)
	s.assignments[transition.Child.AssignmentID] = cloneAssignment(transition.Child)
	s.delegations[transition.Delegation.EventID] = cloneDelegationRecord(transition.Delegation)
	s.events[transition.ParentRecord.EventID] = committedEvent{
		assignmentID: transition.Parent.AssignmentID,
		revision:     transition.Parent.Revision,
		snapshotHash: parentHash,
		record:       cloneTransitionRecord(transition.ParentRecord),
	}
	s.events[transition.ChildRecord.EventID] = committedEvent{
		assignmentID: transition.Child.AssignmentID,
		revision:     transition.Child.Revision,
		snapshotHash: childHash,
		record:       cloneTransitionRecord(transition.ChildRecord),
	}
	return nil
}

func (s *MemoryStore) validateInteractionRelations(event InteractionEvent) error {
	if event.Kind == InteractionQuestion && event.InReplyTo == "" {
		if len(s.interactionOrder[event.InteractionID]) != 0 {
			return invalidInteraction("interaction already has a root question")
		}
		return nil
	}

	replyTarget, ok := s.interactionEvents[event.InReplyTo]
	if !ok {
		return invalidInteraction("in_reply_to event was not appended")
	}
	if !sameInteractionContext(event, replyTarget) {
		return invalidInteraction("in_reply_to crosses an interaction, Task, or Assignment")
	}
	if event.At.Before(replyTarget.At) {
		return invalidInteraction("event predates in_reply_to")
	}
	if event.Kind == InteractionQuestion {
		if replyTarget.Kind != InteractionResponse && replyTarget.Kind != InteractionCorrection {
			return invalidInteraction("follow-up QUESTION must reply to a response or correction")
		}
		return nil
	}
	if replyTarget.Kind != InteractionQuestion {
		return invalidInteraction("response lineage must reply to a QUESTION")
	}
	if event.Kind == InteractionResponse {
		return nil
	}

	superseded, ok := s.interactionEvents[event.Supersedes]
	if !ok {
		return invalidInteraction("superseded event was not appended")
	}
	if !sameInteractionContext(event, superseded) || superseded.InReplyTo != event.InReplyTo {
		return invalidInteraction("supersedes crosses a response lineage")
	}
	if event.At.Before(superseded.At) {
		return invalidInteraction("event predates superseded response")
	}
	if superseded.Kind != InteractionResponse && superseded.Kind != InteractionCorrection {
		return invalidInteraction("only a response or correction may be superseded")
	}
	if superseded.ParticipantID != event.ParticipantID {
		return invalidInteraction("participant may only correct or withdraw its own response")
	}
	return nil
}

func sameInteractionContext(a, b InteractionEvent) bool {
	return a.InteractionID == b.InteractionID &&
		a.TaskID == b.TaskID &&
		a.AssignmentID == b.AssignmentID
}

func sameInteractionEvent(a, b InteractionEvent) bool {
	return a.Schema == b.Schema &&
		a.EventID == b.EventID &&
		a.InteractionID == b.InteractionID &&
		a.TaskID == b.TaskID &&
		a.AssignmentID == b.AssignmentID &&
		a.Kind == b.Kind &&
		a.InReplyTo == b.InReplyTo &&
		a.Supersedes == b.Supersedes &&
		a.Finality == b.Finality &&
		a.ContentRef == b.ContentRef &&
		a.ContentDigest == b.ContentDigest &&
		a.At.Equal(b.At) &&
		a.ActorID == b.ActorID &&
		a.ParticipantID == b.ParticipantID &&
		a.AuthorizationID == b.AuthorizationID &&
		a.ProofID == b.ProofID &&
		a.EvidenceRef == b.EvidenceRef &&
		sameAssuranceProvenance(a.Assurance, b.Assurance)
}

func cloneInteractionEvent(in InteractionEvent) InteractionEvent {
	out := in
	out.Assurance = cloneAssuranceProvenance(in.Assurance)
	return out
}

func cloneDelegationRecord(in DelegationRecord) DelegationRecord {
	out := in
	out.Assurance = cloneAssuranceProvenance(in.Assurance)
	return out
}

func sameDelegationRecord(left, right DelegationRecord) bool {
	leftAssurance := left.Assurance
	rightAssurance := right.Assurance
	left.Assurance = nil
	right.Assurance = nil
	return left == right && sameAssuranceProvenance(leftAssurance, rightAssurance)
}

func assignmentHash(assignment Assignment) ([sha256.Size]byte, error) {
	raw, err := json.Marshal(assignment)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("%w: encode assignment: %v", ErrInvalidAssignment, err)
	}
	return sha256.Sum256(raw), nil
}

func validateDelegationTransition(expectedParentRevision uint64, transition DelegationTransition) error {
	if err := transition.Parent.Validate(); err != nil {
		return err
	}
	if err := transition.Child.Validate(); err != nil {
		return err
	}
	if err := transition.ParentRecord.Validate(); err != nil {
		return fmt.Errorf("%w: invalid parent record: %v", ErrInvalidTransition, err)
	}
	if err := transition.ChildRecord.Validate(); err != nil {
		return fmt.Errorf("%w: invalid child record: %v", ErrInvalidTransition, err)
	}
	if err := transition.Delegation.Validate(); err != nil {
		return err
	}
	if transition.Parent.Revision != expectedParentRevision+1 || transition.Child.Revision != 1 {
		return fmt.Errorf("%w: invalid delegation revisions", ErrInvalidTransition)
	}
	if !sameTransitionRecord(transition.Parent.LastTransition, transition.ParentRecord) ||
		!sameTransitionRecord(transition.Child.LastTransition, transition.ChildRecord) {
		return fmt.Errorf("%w: delegation records do not match snapshots", ErrInvalidTransition)
	}
	if transition.Parent.Status != AssignmentAccepted ||
		transition.ParentRecord.Kind != OperationDelegate ||
		transition.ParentRecord.From != AssignmentAccepted ||
		transition.ParentRecord.To != AssignmentAccepted {
		return fmt.Errorf("%w: parent delegation audit state is invalid", ErrInvalidDelegation)
	}
	if transition.Child.Status != AssignmentOffered ||
		transition.ChildRecord.Kind != OperationOffer ||
		transition.ChildRecord.From != "" ||
		transition.ChildRecord.To != AssignmentOffered {
		return fmt.Errorf("%w: child delegation offer state is invalid", ErrInvalidDelegation)
	}
	if transition.Delegation.EventID != transition.ParentRecord.EventID ||
		transition.Delegation.ParentAssignmentID != transition.Parent.AssignmentID ||
		transition.Delegation.ChildAssignmentID != transition.Child.AssignmentID ||
		transition.Child.ParentAssignmentID != transition.Parent.AssignmentID ||
		transition.Delegation.ParentTaskID != transition.Parent.TaskID ||
		transition.Delegation.ChildTaskID != transition.Child.TaskID {
		return fmt.Errorf("%w: delegation edge does not match snapshots", ErrInvalidDelegation)
	}
	if transition.Delegation.FromParticipantID != transition.Parent.ParticipantID ||
		transition.Delegation.ToParticipantID != transition.Child.ParticipantID ||
		transition.Child.OfferedByParticipantID != transition.Parent.ParticipantID ||
		transition.ParentRecord.ParticipantID != transition.Parent.ParticipantID ||
		transition.ChildRecord.ParticipantID != transition.Parent.ParticipantID {
		return fmt.Errorf("%w: delegation participant provenance mismatch", ErrInvalidDelegation)
	}
	if transition.Delegation.ParentAuthorityDigest != transition.Parent.AuthorityDigest ||
		transition.Delegation.ChildAuthorityDigest != transition.Child.AuthorityDigest {
		return fmt.Errorf("%w: delegation authority provenance mismatch", ErrInvalidDelegation)
	}
	if !transition.Delegation.At.Equal(transition.ParentRecord.At) ||
		!transition.Delegation.At.Equal(transition.ChildRecord.At) ||
		!transition.Delegation.At.Equal(transition.Parent.UpdatedAt) ||
		!transition.Delegation.At.Equal(transition.Child.CreatedAt) ||
		!transition.Delegation.At.Equal(transition.Child.UpdatedAt) {
		return fmt.Errorf("%w: delegation timestamp provenance mismatch", ErrInvalidDelegation)
	}
	if transition.ParentRecord.ActorID != transition.ChildRecord.ActorID ||
		transition.ParentRecord.AuthorizationID != transition.ChildRecord.AuthorizationID ||
		transition.ParentRecord.ProofID != transition.ChildRecord.ProofID {
		return fmt.Errorf("%w: delegation authorization provenance mismatch", ErrInvalidDelegation)
	}
	if !sameAssuranceProvenance(transition.ParentRecord.Assurance, transition.ChildRecord.Assurance) ||
		!sameAssuranceProvenance(transition.ParentRecord.Assurance, transition.Delegation.Assurance) {
		return fmt.Errorf("%w: delegation assurance provenance mismatch", ErrInvalidDelegation)
	}
	if transition.ChildRecord.Reason.Detail != "" || transition.ChildRecord.EvidenceRef != "" {
		return fmt.Errorf("%w: child offer contains non-generated audit data", ErrInvalidDelegation)
	}
	if transition.ParentRecord.EventID == transition.ChildRecord.EventID {
		return fmt.Errorf("%w: parent and child event identifiers must differ", ErrInvalidDelegation)
	}
	return nil
}
