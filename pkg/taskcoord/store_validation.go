// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import "fmt"

// ValidateAssignmentCommit applies the Store input contract without reading
// or changing backend state. Durable adapters must still perform revision CAS
// and event deduplication in their atomic commit.
func ValidateAssignmentCommit(expectedRevision uint64, next Assignment, record TransitionRecord) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}
	if !sameTransitionRecord(next.LastTransition, record) {
		return fmt.Errorf("%w: record does not match snapshot", ErrInvalidTransition)
	}
	if next.Revision != expectedRevision+1 {
		return fmt.Errorf("%w: next revision must equal expected revision plus one", ErrInvalidTransition)
	}
	return nil
}

// ValidateAssignmentTransition checks a non-initial Assignment commit against
// the complete snapshot read inside the backend transaction. It prevents a
// caller from preserving the revision while rewriting immutable identity,
// authority, timestamps, or prior lifecycle state.
func ValidateAssignmentTransition(current, next Assignment, record TransitionRecord) error {
	if err := current.Validate(); err != nil {
		return err
	}
	if err := ValidateAssignmentCommit(current.Revision, next, record); err != nil {
		return err
	}
	if record.From != current.Status {
		return fmt.Errorf("%w: transition origin does not match current snapshot", ErrInvalidTransition)
	}
	if record.At.Before(current.UpdatedAt) {
		return fmt.Errorf("%w: transition predates current snapshot", ErrInvalidTransition)
	}
	if operationRequiresAssignee(record.Kind) && record.ParticipantID != current.ParticipantID {
		return fmt.Errorf("%w: participant does not own assignment", ErrInvalidTransition)
	}

	expected := cloneAssignment(current)
	expected.Revision++
	expected.Status = record.To
	expected.UpdatedAt = record.At
	expected.LastTransition = record
	if record.Kind == OperationAccept {
		acceptedAt := record.At
		expected.AcceptedAt = &acceptedAt
	}
	expectedHash, err := assignmentHash(expected)
	if err != nil {
		return err
	}
	nextHash, err := assignmentHash(next)
	if err != nil {
		return err
	}
	if expectedHash != nextHash {
		return fmt.Errorf("%w: next snapshot rewrites current assignment", ErrInvalidTransition)
	}
	return nil
}

// ValidateDelegationCommit applies the atomic delegation input contract
// without reading or changing backend state.
func ValidateDelegationCommit(expectedParentRevision uint64, transition DelegationTransition) error {
	return validateDelegationTransition(expectedParentRevision, transition)
}

// ValidateInteractionAppend applies all immutable relation checks that do not
// depend on the interaction-order index. Durable adapters must separately make
// root-question uniqueness and the append itself atomic.
func ValidateInteractionAppend(
	event InteractionEvent,
	assignment Assignment,
	participant Participant,
	replyTarget *InteractionEvent,
	superseded *InteractionEvent,
) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if err := assignment.Validate(); err != nil {
		return err
	}
	if assignment.AssignmentID != event.AssignmentID || assignment.TaskID != event.TaskID {
		return invalidInteraction("event Task does not match Assignment")
	}
	if err := participant.Validate(); err != nil {
		return err
	}
	if participant.ParticipantID != event.ParticipantID {
		return invalidInteraction("event Participant does not match registry")
	}
	if participant.Status != ParticipantActive {
		return ErrParticipantUnavailable
	}

	if event.Kind == InteractionQuestion && event.InReplyTo == "" {
		if replyTarget != nil || superseded != nil {
			return invalidInteraction("root question has unexpected relation records")
		}
		return nil
	}
	if replyTarget == nil || replyTarget.EventID != event.InReplyTo {
		return invalidInteraction("in_reply_to event was not appended")
	}
	if !sameInteractionContext(event, *replyTarget) {
		return invalidInteraction("in_reply_to crosses an interaction, Task, or Assignment")
	}
	if event.At.Before(replyTarget.At) {
		return invalidInteraction("event predates in_reply_to")
	}
	if event.Kind == InteractionQuestion {
		if superseded != nil || (replyTarget.Kind != InteractionResponse && replyTarget.Kind != InteractionCorrection) {
			return invalidInteraction("follow-up QUESTION must reply to a response or correction")
		}
		return nil
	}
	if replyTarget.Kind != InteractionQuestion {
		return invalidInteraction("response lineage must reply to a QUESTION")
	}
	if event.Kind == InteractionResponse {
		if superseded != nil {
			return invalidInteraction("response has unexpected supersession record")
		}
		return nil
	}
	if superseded == nil || superseded.EventID != event.Supersedes {
		return invalidInteraction("superseded event was not appended")
	}
	if !sameInteractionContext(event, *superseded) || superseded.InReplyTo != event.InReplyTo {
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
