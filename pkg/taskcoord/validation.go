// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidParticipant     = errors.New("task coordination: invalid participant")
	ErrInvalidAssignment      = errors.New("task coordination: invalid assignment")
	ErrInvalidEvent           = errors.New("task coordination: invalid event")
	ErrInvalidTransition      = errors.New("task coordination: invalid transition")
	ErrInvalidDelegation      = errors.New("task coordination: invalid delegation")
	ErrInvalidInteraction     = errors.New("task coordination: invalid interaction")
	ErrInvalidDiscovery       = errors.New("task coordination: invalid discovery record")
	ErrHumanNotDiscoverable   = errors.New("task coordination: Human is not an Agent discovery target")
	ErrInvalidReachability    = errors.New("task coordination: invalid Human reachability record")
	ErrRevisionConflict       = errors.New("task coordination: revision conflict")
	ErrNotFound               = errors.New("task coordination: not found")
	ErrAlreadyExists          = errors.New("task coordination: already exists")
	ErrEventConflict          = errors.New("task coordination: event identifier conflict")
	ErrAuthenticationRequired = errors.New("task coordination: authenticated operation required")
	ErrParticipantUnavailable = errors.New("task coordination: participant is not active")
	ErrDelegationNotPermitted = errors.New("task coordination: participant may not delegate")
)

const (
	maxIDLength        = 256
	maxDetailLength    = 1024
	maxReferenceLength = 2048
)

// Validate checks a Task Participant record.
func (p Participant) Validate() error {
	if p.Schema != ParticipantSchemaV1 {
		return invalidParticipant("unsupported schema")
	}
	if err := validateID("participant_id", p.ParticipantID); err != nil {
		return invalidParticipantError(err)
	}
	switch p.Kind {
	case ParticipantHuman, ParticipantAgent, ParticipantAutomatedService:
	default:
		return invalidParticipant("unsupported participant kind")
	}
	if err := validateReference("identity_ref", p.IdentityRef); err != nil {
		return invalidParticipantError(err)
	}
	if p.Kind == ParticipantHuman && isPublicOrDirectContactReference(p.IdentityRef) {
		return invalidParticipant("Human identity_ref must be an opaque resolver reference")
	}
	switch p.Status {
	case ParticipantActive, ParticipantSuspended, ParticipantRevoked:
	default:
		return invalidParticipant("unsupported participant status")
	}
	if p.RegisteredAt.IsZero() {
		return invalidParticipant("registered_at is required")
	}
	return nil
}

// Validate checks all cross-field invariants in an Assignment snapshot.
func (a Assignment) Validate() error {
	if a.Schema != AssignmentSchemaV1 {
		return invalidAssignment("unsupported schema")
	}
	for field, value := range map[string]string{
		"assignment_id":             a.AssignmentID,
		"task_id":                   a.TaskID,
		"participant_id":            a.ParticipantID,
		"offered_by_participant_id": a.OfferedByParticipantID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidAssignmentError(err)
		}
	}
	if a.ParentAssignmentID != "" {
		if err := validateID("parent_assignment_id", a.ParentAssignmentID); err != nil {
			return invalidAssignmentError(err)
		}
		if a.ParentAssignmentID == a.AssignmentID {
			return invalidAssignment("assignment may not be its own parent")
		}
	}
	switch a.Role {
	case RoleOwner, RoleAssignee, RoleReviewer:
	default:
		return invalidAssignment("unsupported role")
	}
	if err := validateDigest("authority_digest", a.AuthorityDigest); err != nil {
		return invalidAssignmentError(err)
	}
	if a.Revision == 0 {
		return invalidAssignment("revision must be positive")
	}
	if !validAssignmentStatus(a.Status) {
		return invalidAssignment("unsupported status")
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() || a.UpdatedAt.Before(a.CreatedAt) {
		return invalidAssignment("invalid assignment timestamps")
	}
	if a.DueAt != nil && !a.DueAt.After(a.CreatedAt) {
		return invalidAssignment("due_at must be after created_at")
	}
	if a.AcceptedAt != nil {
		if a.AcceptedAt.Before(a.CreatedAt) || a.AcceptedAt.After(a.UpdatedAt) {
			return invalidAssignment("accepted_at is outside assignment lifetime")
		}
	}
	switch a.Status {
	case AssignmentOffered, AssignmentDeclined:
		if a.AcceptedAt != nil {
			return invalidAssignment("unaccepted assignment must not contain accepted_at")
		}
	case AssignmentAccepted, AssignmentReleased, AssignmentFulfilled:
		if a.AcceptedAt == nil {
			return invalidAssignment("status requires accepted_at")
		}
	case AssignmentRevoked:
		// An offer may be revoked before or after acceptance.
	}
	if err := a.LastTransition.Validate(); err != nil {
		return invalidAssignmentError(err)
	}
	if a.LastTransition.AssignmentID != a.AssignmentID ||
		a.LastTransition.TaskID != a.TaskID ||
		a.LastTransition.Revision != a.Revision ||
		a.LastTransition.To != a.Status ||
		a.LastTransition.Reason.Code != a.LastTransition.Kind ||
		!a.LastTransition.At.Equal(a.UpdatedAt) {
		return invalidAssignment("last transition does not match snapshot")
	}
	if a.Revision == 1 {
		if a.LastTransition.Kind != OperationOffer || a.LastTransition.From != "" || a.Status != AssignmentOffered {
			return invalidAssignment("revision one must be an OFFER transition")
		}
	} else if a.LastTransition.Kind == OperationOffer || a.LastTransition.From == "" {
		return invalidAssignment("non-initial transition has invalid origin")
	} else if !allowedTransition(a.LastTransition.From, a.LastTransition.Kind, a.LastTransition.To) {
		return invalidAssignment("last transition is not allowed")
	}
	if a.Status == AssignmentRevoked {
		if a.LastTransition.From == AssignmentOffered && a.AcceptedAt != nil {
			return invalidAssignment("offer revoked before acceptance must not contain accepted_at")
		}
		if a.LastTransition.From == AssignmentAccepted && a.AcceptedAt == nil {
			return invalidAssignment("accepted assignment revocation requires accepted_at")
		}
	}
	return nil
}

// Validate checks an appended Assignment transition record.
func (r TransitionRecord) Validate() error {
	for field, value := range map[string]string{
		"event_id":         r.EventID,
		"assignment_id":    r.AssignmentID,
		"task_id":          r.TaskID,
		"actor_id":         r.ActorID,
		"participant_id":   r.ParticipantID,
		"authorization_id": r.AuthorizationID,
		"proof_id":         r.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if r.Revision == 0 || !validOperation(r.Kind) || !validAssignmentStatus(r.To) {
		return fmt.Errorf("invalid transition type or revision")
	}
	if r.From != "" && !validAssignmentStatus(r.From) {
		return fmt.Errorf("unsupported transition origin")
	}
	if r.Reason.Code != r.Kind {
		return fmt.Errorf("reason code must equal operation kind")
	}
	if err := validateDetail(r.Reason.Detail); err != nil {
		return err
	}
	if r.At.IsZero() {
		return fmt.Errorf("transition timestamp is required")
	}
	if r.EvidenceRef != "" {
		if err := validateReference("evidence_ref", r.EvidenceRef); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks a verified delegation projection.
func (d VerifiedDelegation) Validate() error {
	for field, value := range map[string]string{
		"decision_id":          d.DecisionID,
		"parent_assignment_id": d.ParentAssignmentID,
		"child_assignment_id":  d.ChildAssignmentID,
		"from_participant_id":  d.FromParticipantID,
		"to_participant_id":    d.ToParticipantID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidDelegationError(err)
		}
	}
	if d.ParentAssignmentID == d.ChildAssignmentID || d.FromParticipantID == d.ToParticipantID {
		return invalidDelegation("verified delegation has a self-binding")
	}
	if err := validateDigest("parent_authority_digest", d.ParentAuthorityDigest); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateDigest("child_authority_digest", d.ChildAuthorityDigest); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateReference("policy_ref", d.PolicyRef); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateReference("evidence_ref", d.EvidenceRef); err != nil {
		return invalidDelegationError(err)
	}
	if d.VerifiedAt.IsZero() {
		return invalidDelegation("verified_at is required")
	}
	return nil
}

// Validate checks an immutable delegation provenance record.
func (d DelegationRecord) Validate() error {
	for field, value := range map[string]string{
		"event_id":             d.EventID,
		"decision_id":          d.DecisionID,
		"parent_assignment_id": d.ParentAssignmentID,
		"child_assignment_id":  d.ChildAssignmentID,
		"parent_task_id":       d.ParentTaskID,
		"child_task_id":        d.ChildTaskID,
		"from_participant_id":  d.FromParticipantID,
		"to_participant_id":    d.ToParticipantID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidDelegationError(err)
		}
	}
	if d.ParentAssignmentID == d.ChildAssignmentID {
		return invalidDelegation("parent and child assignment must differ")
	}
	if d.FromParticipantID == d.ToParticipantID {
		return invalidDelegation("self-delegation is not allowed")
	}
	if err := validateDigest("parent_authority_digest", d.ParentAuthorityDigest); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateDigest("child_authority_digest", d.ChildAuthorityDigest); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateReference("policy_ref", d.PolicyRef); err != nil {
		return invalidDelegationError(err)
	}
	if err := validateReference("evidence_ref", d.EvidenceRef); err != nil {
		return invalidDelegationError(err)
	}
	if d.At.IsZero() {
		return invalidDelegation("delegation timestamp is required")
	}
	return nil
}

// Validate checks the structural and cross-field invariants of one immutable
// interaction event. Thread and supersession targets are checked by Store.
func (e InteractionEvent) Validate() error {
	if e.Schema != InteractionEventSchemaV1 {
		return invalidInteraction("unsupported schema")
	}
	for field, value := range map[string]string{
		"event_id":         e.EventID,
		"interaction_id":   e.InteractionID,
		"task_id":          e.TaskID,
		"assignment_id":    e.AssignmentID,
		"actor_id":         e.ActorID,
		"participant_id":   e.ParticipantID,
		"authorization_id": e.AuthorizationID,
		"proof_id":         e.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidInteractionError(err)
		}
	}
	if e.InReplyTo != "" {
		if err := validateID("in_reply_to", e.InReplyTo); err != nil {
			return invalidInteractionError(err)
		}
		if e.InReplyTo == e.EventID {
			return invalidInteraction("event may not reply to itself")
		}
	}
	if e.Supersedes != "" {
		if err := validateID("supersedes", e.Supersedes); err != nil {
			return invalidInteractionError(err)
		}
		if e.Supersedes == e.EventID {
			return invalidInteraction("event may not supersede itself")
		}
	}
	if e.At.IsZero() {
		return invalidInteraction("at is required")
	}
	if e.EvidenceRef != "" {
		if err := validateReference("evidence_ref", e.EvidenceRef); err != nil {
			return invalidInteractionError(err)
		}
	}

	switch e.Kind {
	case InteractionQuestion:
		if e.Supersedes != "" || e.Finality != "" {
			return invalidInteraction("QUESTION must not supersede an event or declare finality")
		}
		if err := validateInteractionContent(e); err != nil {
			return err
		}
	case InteractionResponse:
		if e.InReplyTo == "" || e.Supersedes != "" || !validResponseFinality(e.Finality) {
			return invalidInteraction("RESPONSE requires in_reply_to and finality without supersedes")
		}
		if err := validateInteractionContent(e); err != nil {
			return err
		}
	case InteractionCorrection:
		if e.InReplyTo == "" || e.Supersedes == "" || !validResponseFinality(e.Finality) {
			return invalidInteraction("CORRECTION requires in_reply_to, supersedes, and finality")
		}
		if e.InReplyTo == e.Supersedes {
			return invalidInteraction("CORRECTION must not supersede its question")
		}
		if err := validateInteractionContent(e); err != nil {
			return err
		}
	case InteractionWithdrawal:
		if e.InReplyTo == "" || e.Supersedes == "" {
			return invalidInteraction("WITHDRAWAL requires in_reply_to and supersedes")
		}
		if e.InReplyTo == e.Supersedes {
			return invalidInteraction("WITHDRAWAL must not supersede its question")
		}
		if e.Finality != "" || e.ContentRef != "" || e.ContentDigest != "" {
			return invalidInteraction("WITHDRAWAL must not contain response content or finality")
		}
	default:
		return invalidInteraction("unsupported interaction kind")
	}
	return nil
}

func validateInteractionContent(e InteractionEvent) error {
	if err := validateReference("content_ref", e.ContentRef); err != nil {
		return invalidInteractionError(err)
	}
	if isDirectContactReference(e.ContentRef) {
		return invalidInteraction("content_ref must not contain a direct contact endpoint")
	}
	if err := validateDigest("content_digest", e.ContentDigest); err != nil {
		return invalidInteractionError(err)
	}
	return nil
}

func validResponseFinality(finality ResponseFinality) bool {
	return finality == ResponseInterim || finality == ResponseFinal
}

func validAssignmentStatus(s AssignmentStatus) bool {
	switch s {
	case AssignmentOffered, AssignmentAccepted, AssignmentDeclined,
		AssignmentReleased, AssignmentRevoked, AssignmentFulfilled:
		return true
	default:
		return false
	}
}

func validOperation(k OperationKind) bool {
	switch k {
	case OperationOffer, OperationAccept, OperationDecline, OperationRelease,
		OperationRevoke, OperationFulfill, OperationDelegate:
		return true
	default:
		return false
	}
}

func allowedTransition(from AssignmentStatus, kind OperationKind, to AssignmentStatus) bool {
	switch from {
	case AssignmentOffered:
		return (kind == OperationAccept && to == AssignmentAccepted) ||
			(kind == OperationDecline && to == AssignmentDeclined) ||
			(kind == OperationRevoke && to == AssignmentRevoked)
	case AssignmentAccepted:
		return (kind == OperationRelease && to == AssignmentReleased) ||
			(kind == OperationRevoke && to == AssignmentRevoked) ||
			(kind == OperationFulfill && to == AssignmentFulfilled) ||
			(kind == OperationDelegate && to == AssignmentAccepted)
	default:
		return false
	}
}

func validateID(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !utf8.ValidString(value) || len(value) > maxIDLength {
		return fmt.Errorf("%s is not a bounded UTF-8 identifier", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not have surrounding whitespace", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func validateDigest(field, value string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hexadecimal", field)
	}
	return nil
}

func validateReference(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !utf8.ValidString(value) || len(value) > maxReferenceLength {
		return fmt.Errorf("%s is not a bounded UTF-8 reference", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func validateDetail(value string) error {
	if !utf8.ValidString(value) || len(value) > maxDetailLength {
		return fmt.Errorf("detail is not bounded UTF-8")
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return fmt.Errorf("detail contains an unsupported control character")
		}
	}
	return nil
}

func invalidParticipant(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidParticipant, message)
}

func invalidParticipantError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidParticipant, err)
}

func invalidAssignment(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidAssignment, message)
}

func invalidAssignmentError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidAssignment, err)
}

func invalidDelegation(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDelegation, message)
}

func invalidDelegationError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidDelegation, err)
}

func invalidInteraction(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInteraction, message)
}

func invalidInteractionError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidInteraction, err)
}
