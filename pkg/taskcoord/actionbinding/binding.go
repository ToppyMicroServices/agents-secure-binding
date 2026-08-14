// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"fmt"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

// NewBinding creates the immutable join for an initial ACCEPTED Action. The
// Assignment must already be ACCEPTED, and the Action owner must be the
// accountable Participant on that Assignment.
func NewBinding(assignment taskcoord.Assignment, initial actionlifecycle.Transition) (Binding, error) {
	if err := assignment.Validate(); err != nil {
		return Binding{}, fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	if assignment.Status != taskcoord.AssignmentAccepted {
		return Binding{}, ErrAssignmentNotAccepted
	}
	if err := validateTransition(initial); err != nil {
		return Binding{}, err
	}
	if initial.Snapshot.Revision != 1 || initial.Snapshot.State != actionlifecycle.StateAccepted ||
		initial.Record.Kind != actionlifecycle.EventAccept || initial.Record.From != "" {
		return Binding{}, fmt.Errorf("%w: initial Action must be revision-one ACCEPT", ErrInvalidBinding)
	}
	if initial.Snapshot.OwnerID != assignment.ParticipantID {
		return Binding{}, fmt.Errorf("%w: Action owner does not match Assignment participant", ErrInvalidBinding)
	}
	if assignment.AcceptedAt == nil || initial.Snapshot.CreatedAt.Before(*assignment.AcceptedAt) {
		return Binding{}, fmt.Errorf("%w: Action predates Assignment acceptance", ErrInvalidBinding)
	}
	binding := Binding{
		Schema:       BindingSchemaV1,
		TaskID:       assignment.TaskID,
		AssignmentID: assignment.AssignmentID,
		ActionID:     initial.Snapshot.ActionID,
		CreatedAt:    initial.Snapshot.CreatedAt,
	}
	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// ValidateCurrent re-establishes the identity join from current snapshots.
// It does not require the Assignment to remain ACCEPTED; RELEASE, REVOKE, and
// FULFILL are separate decisions and never rewrite Action history.
func ValidateCurrent(binding Binding, assignment taskcoord.Assignment, action actionlifecycle.Snapshot) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := assignment.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	if err := action.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	if binding.TaskID != assignment.TaskID || binding.AssignmentID != assignment.AssignmentID ||
		binding.ActionID != action.ActionID || assignment.ParticipantID != action.OwnerID {
		return fmt.Errorf("%w: current identity mismatch", ErrInvalidBinding)
	}
	if assignment.AcceptedAt == nil || binding.CreatedAt.Before(*assignment.AcceptedAt) ||
		!binding.CreatedAt.Equal(action.CreatedAt) {
		return fmt.Errorf("%w: current timestamp mismatch", ErrInvalidBinding)
	}
	return nil
}

// FulfillmentEligible reports whether an application may propose a separate
// Assignment FULFILL operation. It never mutates either lifecycle.
func FulfillmentEligible(binding Binding, assignment taskcoord.Assignment, action actionlifecycle.Snapshot) (bool, error) {
	if err := ValidateCurrent(binding, assignment, action); err != nil {
		return false, err
	}
	return assignment.Status == taskcoord.AssignmentAccepted && action.State == actionlifecycle.StateSucceeded, nil
}

func validateTransition(transition actionlifecycle.Transition) error {
	if err := transition.Snapshot.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	last := transition.Snapshot.LastTransition
	record := transition.Record
	if last.EventID != record.EventID || last.Kind != record.Kind || last.From != record.From ||
		last.To != record.To || last.Reason != record.Reason || !last.At.Equal(record.At) ||
		last.ActorID != record.ActorID || last.AuthorizationID != record.AuthorizationID ||
		last.ProofID != record.ProofID || last.EvidenceRef != record.EvidenceRef ||
		last.LeaseGeneration != record.LeaseGeneration {
		return fmt.Errorf("%w: transition record does not match Action snapshot", ErrInvalidBinding)
	}
	return nil
}
