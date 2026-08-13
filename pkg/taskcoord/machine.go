// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"fmt"
	"time"
)

// Offer creates a root Assignment in OFFERED state. Delegated assignments
// must be created with Delegate so that the provenance edge is atomic.
func Offer(def AssignmentDefinition, target Participant, auth AuthenticatedOperation) (Transition, error) {
	if def.ParentAssignmentID != "" {
		return Transition{}, fmt.Errorf("%w: delegated assignment requires Delegate", ErrInvalidTransition)
	}
	if err := validateDefinition(def); err != nil {
		return Transition{}, err
	}
	if err := requireActiveParticipant(target, def.ParticipantID); err != nil {
		return Transition{}, err
	}
	if err := validateOperation(auth, OperationOffer, def.TaskID, def.AssignmentID, def.OfferedAt); err != nil {
		return Transition{}, err
	}
	if auth.TargetParticipantID != def.ParticipantID || auth.TargetTaskID != "" || auth.TargetAssignmentID != "" {
		return Transition{}, fmt.Errorf("%w: offer target binding mismatch", ErrInvalidTransition)
	}

	record := initialOfferRecord(def, auth)
	assignment := Assignment{
		Schema:                 AssignmentSchemaV1,
		AssignmentID:           def.AssignmentID,
		TaskID:                 def.TaskID,
		ParticipantID:          def.ParticipantID,
		OfferedByParticipantID: auth.ParticipantID,
		Role:                   def.Role,
		AuthorityDigest:        def.AuthorityDigest,
		Revision:               1,
		Status:                 AssignmentOffered,
		DueAt:                  cloneTime(def.DueAt),
		LastTransition:         record,
		CreatedAt:              def.OfferedAt,
		UpdatedAt:              def.OfferedAt,
	}
	if err := assignment.Validate(); err != nil {
		return Transition{}, err
	}
	return Transition{Assignment: assignment, Record: record}, nil
}

// Apply performs an Assignment state transition. DELEGATE is handled by
// Delegate because it creates two snapshots and one provenance edge.
func Apply(current Assignment, event Event) (Transition, error) {
	if err := current.Validate(); err != nil {
		return Transition{}, err
	}
	if event.Kind == OperationDelegate || event.Kind == OperationOffer {
		return Transition{}, fmt.Errorf("%w: operation requires a creation transition", ErrInvalidTransition)
	}
	if err := validateEvent(event); err != nil {
		return Transition{}, err
	}
	if event.ExpectedRevision != current.Revision {
		return Transition{}, fmt.Errorf("%w: expected %d, have %d", ErrRevisionConflict, event.ExpectedRevision, current.Revision)
	}
	if event.At.Before(current.UpdatedAt) {
		return Transition{}, fmt.Errorf("%w: event predates current snapshot", ErrInvalidTransition)
	}
	if current.Status.Terminal() {
		return Transition{}, fmt.Errorf("%w: terminal assignment", ErrInvalidTransition)
	}
	if err := validateOperation(event.Auth, event.Kind, current.TaskID, current.AssignmentID, event.At); err != nil {
		return Transition{}, err
	}
	if event.Auth.TargetTaskID != "" || event.Auth.TargetAssignmentID != "" || event.Auth.TargetParticipantID != "" {
		return Transition{}, fmt.Errorf("%w: unexpected target binding", ErrInvalidTransition)
	}

	nextStatus, err := nextStatus(current.Status, event.Kind)
	if err != nil {
		return Transition{}, err
	}
	if operationRequiresAssignee(event.Kind) && event.Auth.ParticipantID != current.ParticipantID {
		return Transition{}, fmt.Errorf("%w: participant does not own assignment", ErrInvalidTransition)
	}

	next := cloneAssignment(current)
	next.Revision++
	next.Status = nextStatus
	next.UpdatedAt = event.At
	if event.Kind == OperationAccept {
		acceptedAt := event.At
		next.AcceptedAt = &acceptedAt
	}
	record := transitionRecord(current, next, event)
	next.LastTransition = record
	if err := next.Validate(); err != nil {
		return Transition{}, err
	}
	return Transition{Assignment: next, Record: record}, nil
}

// Delegate creates a child OFFER while retaining the parent's ACCEPTED
// responsibility. Releasing or fulfilling the parent requires a later,
// separately authorized operation.
func Delegate(
	parent Assignment,
	delegator Participant,
	target Participant,
	childDef AssignmentDefinition,
	event Event,
	verified VerifiedDelegation,
) (DelegationTransition, error) {
	if err := parent.Validate(); err != nil {
		return DelegationTransition{}, err
	}
	if parent.Status != AssignmentAccepted {
		return DelegationTransition{}, fmt.Errorf("%w: only ACCEPTED assignments may delegate", ErrInvalidTransition)
	}
	if err := requireActiveParticipant(delegator, parent.ParticipantID); err != nil {
		return DelegationTransition{}, err
	}
	if !delegator.MayDelegate {
		return DelegationTransition{}, ErrDelegationNotPermitted
	}
	if err := requireActiveParticipant(target, childDef.ParticipantID); err != nil {
		return DelegationTransition{}, err
	}
	if target.ParticipantID == parent.ParticipantID {
		return DelegationTransition{}, fmt.Errorf("%w: self-delegation is not allowed", ErrInvalidDelegation)
	}
	if err := validateDefinition(childDef); err != nil {
		return DelegationTransition{}, err
	}
	if childDef.ParentAssignmentID != parent.AssignmentID {
		return DelegationTransition{}, fmt.Errorf("%w: child parent binding mismatch", ErrInvalidDelegation)
	}
	if childDef.EventID == event.ID {
		return DelegationTransition{}, fmt.Errorf("%w: parent and child event identifiers must differ", ErrInvalidDelegation)
	}
	if !childDef.OfferedAt.Equal(event.At) {
		return DelegationTransition{}, fmt.Errorf("%w: child offer time must equal delegation time", ErrInvalidDelegation)
	}
	if err := validateEvent(event); err != nil {
		return DelegationTransition{}, err
	}
	if event.Kind != OperationDelegate {
		return DelegationTransition{}, fmt.Errorf("%w: expected DELEGATE", ErrInvalidTransition)
	}
	if event.ExpectedRevision != parent.Revision {
		return DelegationTransition{}, fmt.Errorf("%w: expected %d, have %d", ErrRevisionConflict, event.ExpectedRevision, parent.Revision)
	}
	if event.At.Before(parent.UpdatedAt) {
		return DelegationTransition{}, fmt.Errorf("%w: event predates parent snapshot", ErrInvalidTransition)
	}
	if err := validateOperation(event.Auth, OperationDelegate, parent.TaskID, parent.AssignmentID, event.At); err != nil {
		return DelegationTransition{}, err
	}
	if event.Auth.ParticipantID != parent.ParticipantID ||
		event.Auth.TargetTaskID != childDef.TaskID ||
		event.Auth.TargetAssignmentID != childDef.AssignmentID ||
		event.Auth.TargetParticipantID != childDef.ParticipantID {
		return DelegationTransition{}, fmt.Errorf("%w: delegation binding mismatch", ErrInvalidDelegation)
	}
	if err := verified.Validate(); err != nil {
		return DelegationTransition{}, err
	}
	if verified.VerifiedAt.After(event.At) {
		return DelegationTransition{}, fmt.Errorf("%w: policy decision postdates delegation", ErrInvalidDelegation)
	}
	if verified.ParentAssignmentID != parent.AssignmentID ||
		verified.ChildAssignmentID != childDef.AssignmentID ||
		verified.FromParticipantID != parent.ParticipantID ||
		verified.ToParticipantID != childDef.ParticipantID ||
		verified.ParentAuthorityDigest != parent.AuthorityDigest ||
		verified.ChildAuthorityDigest != childDef.AuthorityDigest {
		return DelegationTransition{}, fmt.Errorf("%w: verified delegation binding mismatch", ErrInvalidDelegation)
	}

	nextParent := cloneAssignment(parent)
	nextParent.Revision++
	nextParent.UpdatedAt = event.At
	parentRecord := transitionRecord(parent, nextParent, event)
	nextParent.LastTransition = parentRecord

	childRecord := initialOfferRecord(childDef, event.Auth)
	child := Assignment{
		Schema:                 AssignmentSchemaV1,
		AssignmentID:           childDef.AssignmentID,
		TaskID:                 childDef.TaskID,
		ParticipantID:          childDef.ParticipantID,
		OfferedByParticipantID: parent.ParticipantID,
		Role:                   childDef.Role,
		AuthorityDigest:        childDef.AuthorityDigest,
		ParentAssignmentID:     parent.AssignmentID,
		Revision:               1,
		Status:                 AssignmentOffered,
		DueAt:                  cloneTime(childDef.DueAt),
		LastTransition:         childRecord,
		CreatedAt:              childDef.OfferedAt,
		UpdatedAt:              childDef.OfferedAt,
	}
	delegation := DelegationRecord{
		EventID:               event.ID,
		DecisionID:            verified.DecisionID,
		ParentAssignmentID:    parent.AssignmentID,
		ChildAssignmentID:     child.AssignmentID,
		ParentTaskID:          parent.TaskID,
		ChildTaskID:           child.TaskID,
		FromParticipantID:     parent.ParticipantID,
		ToParticipantID:       child.ParticipantID,
		ParentAuthorityDigest: parent.AuthorityDigest,
		ChildAuthorityDigest:  child.AuthorityDigest,
		PolicyRef:             verified.PolicyRef,
		EvidenceRef:           verified.EvidenceRef,
		At:                    event.At,
	}
	if err := nextParent.Validate(); err != nil {
		return DelegationTransition{}, err
	}
	if err := child.Validate(); err != nil {
		return DelegationTransition{}, err
	}
	if err := delegation.Validate(); err != nil {
		return DelegationTransition{}, err
	}
	return DelegationTransition{
		Parent:       nextParent,
		ParentRecord: parentRecord,
		Child:        child,
		ChildRecord:  childRecord,
		Delegation:   delegation,
	}, nil
}

func validateDefinition(def AssignmentDefinition) error {
	for field, value := range map[string]string{
		"event_id":       def.EventID,
		"assignment_id":  def.AssignmentID,
		"task_id":        def.TaskID,
		"participant_id": def.ParticipantID,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTransition, err)
		}
	}
	if def.ParentAssignmentID != "" {
		if err := validateID("parent_assignment_id", def.ParentAssignmentID); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTransition, err)
		}
		if def.ParentAssignmentID == def.AssignmentID {
			return fmt.Errorf("%w: assignment may not be its own parent", ErrInvalidTransition)
		}
	}
	switch def.Role {
	case RoleOwner, RoleAssignee, RoleReviewer:
	default:
		return fmt.Errorf("%w: unsupported assignment role", ErrInvalidTransition)
	}
	if err := validateDigest("authority_digest", def.AuthorityDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTransition, err)
	}
	if def.OfferedAt.IsZero() {
		return fmt.Errorf("%w: offered_at is required", ErrInvalidTransition)
	}
	if def.DueAt != nil && !def.DueAt.After(def.OfferedAt) {
		return fmt.Errorf("%w: due_at must be after offered_at", ErrInvalidTransition)
	}
	return nil
}

func validateEvent(event Event) error {
	if err := validateID("event_id", event.ID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if !validOperation(event.Kind) {
		return fmt.Errorf("%w: unsupported operation", ErrInvalidEvent)
	}
	if event.At.IsZero() {
		return fmt.Errorf("%w: event timestamp is required", ErrInvalidEvent)
	}
	if err := validateDetail(event.Detail); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if event.EvidenceRef != "" {
		if err := validateReference("evidence_ref", event.EvidenceRef); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
		}
	}
	return nil
}

func validateOperation(auth AuthenticatedOperation, kind OperationKind, taskID, assignmentID string, at time.Time) error {
	for field, value := range map[string]string{
		"actor_id":         auth.ActorID,
		"participant_id":   auth.ParticipantID,
		"authorization_id": auth.AuthorizationID,
		"proof_id":         auth.ProofID,
		"task_id":          auth.TaskID,
		"assignment_id":    auth.AssignmentID,
		"verifier_nonce":   auth.VerifierNonce,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrAuthenticationRequired, err)
		}
	}
	if auth.Operation != kind || auth.TaskID != taskID || auth.AssignmentID != assignmentID {
		return fmt.Errorf("%w: operation target mismatch", ErrAuthenticationRequired)
	}
	if auth.IssuedAt.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.IssuedAt) {
		return fmt.Errorf("%w: invalid authorization validity window", ErrAuthenticationRequired)
	}
	if at.Before(auth.IssuedAt) || !at.Before(auth.ExpiresAt) {
		return fmt.Errorf("%w: operation is outside authorization validity window", ErrAuthenticationRequired)
	}
	return nil
}

func requireActiveParticipant(participant Participant, expectedID string) error {
	if err := participant.Validate(); err != nil {
		return err
	}
	if participant.ParticipantID != expectedID {
		return fmt.Errorf("%w: participant binding mismatch", ErrInvalidTransition)
	}
	if participant.Status != ParticipantActive {
		return ErrParticipantUnavailable
	}
	return nil
}

func nextStatus(current AssignmentStatus, kind OperationKind) (AssignmentStatus, error) {
	switch current {
	case AssignmentOffered:
		switch kind {
		case OperationAccept:
			return AssignmentAccepted, nil
		case OperationDecline:
			return AssignmentDeclined, nil
		case OperationRevoke:
			return AssignmentRevoked, nil
		}
	case AssignmentAccepted:
		switch kind {
		case OperationRelease:
			return AssignmentReleased, nil
		case OperationRevoke:
			return AssignmentRevoked, nil
		case OperationFulfill:
			return AssignmentFulfilled, nil
		}
	}
	return "", fmt.Errorf("%w: %s cannot apply to %s", ErrInvalidTransition, kind, current)
}

func operationRequiresAssignee(kind OperationKind) bool {
	return kind == OperationAccept || kind == OperationDecline ||
		kind == OperationRelease || kind == OperationFulfill
}

func initialOfferRecord(def AssignmentDefinition, auth AuthenticatedOperation) TransitionRecord {
	return TransitionRecord{
		EventID:         def.EventID,
		AssignmentID:    def.AssignmentID,
		TaskID:          def.TaskID,
		Revision:        1,
		Kind:            OperationOffer,
		To:              AssignmentOffered,
		Reason:          Reason{Code: OperationOffer},
		At:              def.OfferedAt,
		ActorID:         auth.ActorID,
		ParticipantID:   auth.ParticipantID,
		AuthorizationID: auth.AuthorizationID,
		ProofID:         auth.ProofID,
	}
}

func transitionRecord(current, next Assignment, event Event) TransitionRecord {
	return TransitionRecord{
		EventID:         event.ID,
		AssignmentID:    current.AssignmentID,
		TaskID:          current.TaskID,
		Revision:        next.Revision,
		Kind:            event.Kind,
		From:            current.Status,
		To:              next.Status,
		Reason:          Reason{Code: event.Kind, Detail: event.Detail},
		At:              event.At,
		ActorID:         event.Auth.ActorID,
		ParticipantID:   event.Auth.ParticipantID,
		AuthorizationID: event.Auth.AuthorizationID,
		ProofID:         event.Auth.ProofID,
		EvidenceRef:     event.EvidenceRef,
	}
}

func cloneAssignment(in Assignment) Assignment {
	out := in
	out.AcceptedAt = cloneTime(in.AcceptedAt)
	out.DueAt = cloneTime(in.DueAt)
	return out
}

func cloneTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
