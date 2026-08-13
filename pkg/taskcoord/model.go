// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import "time"

const (
	// ParticipantSchemaV1 identifies the durable Task Participant profile.
	ParticipantSchemaV1 = "asb.task-participant/v1"
	// AssignmentSchemaV1 identifies the durable Task Assignment profile.
	AssignmentSchemaV1 = "asb.task-assignment/v1"
	// DependencySchemaV1 identifies the Task dependency profile.
	DependencySchemaV1 = "asb.task-dependency/v1"
	// InteractionEventSchemaV1 identifies an immutable Task interaction event.
	InteractionEventSchemaV1 = "asb.task-interaction-event/v1"
	// MaxDocumentBytes bounds strict JSON decoding.
	MaxDocumentBytes = 1 << 20
)

// ParticipantKind identifies the class of entity accepting task
// responsibility. A passive API or tool is not an AUTOMATED_SERVICE.
type ParticipantKind string

const (
	ParticipantHuman            ParticipantKind = "HUMAN"
	ParticipantAgent            ParticipantKind = "AGENT"
	ParticipantAutomatedService ParticipantKind = "AUTOMATED_SERVICE"
)

// ParticipantStatus is registry availability, not task execution state.
type ParticipantStatus string

const (
	ParticipantActive    ParticipantStatus = "ACTIVE"
	ParticipantSuspended ParticipantStatus = "SUSPENDED"
	ParticipantRevoked   ParticipantStatus = "REVOKED"
)

// Participant is an entity to which bounded responsibility may be assigned.
// IdentityRef is resolved and authenticated by the enclosing ASB profile.
type Participant struct {
	Schema        string            `json:"schema"`
	ParticipantID string            `json:"participant_id"`
	Kind          ParticipantKind   `json:"kind"`
	IdentityRef   string            `json:"identity_ref"`
	Status        ParticipantStatus `json:"status"`
	MayDelegate   bool              `json:"may_delegate"`
	RegisteredAt  time.Time         `json:"registered_at"`
}

// AssignmentRole records responsibility without conflating it with current
// execution permission.
type AssignmentRole string

const (
	RoleOwner    AssignmentRole = "OWNER"
	RoleAssignee AssignmentRole = "ASSIGNEE"
	RoleReviewer AssignmentRole = "REVIEWER"
)

// AssignmentStatus is the lifecycle of the responsibility relationship.
// WAITING and PAUSED belong to Task or Action lifecycle, not this enum.
type AssignmentStatus string

const (
	AssignmentOffered   AssignmentStatus = "OFFERED"
	AssignmentAccepted  AssignmentStatus = "ACCEPTED"
	AssignmentDeclined  AssignmentStatus = "DECLINED"
	AssignmentReleased  AssignmentStatus = "RELEASED"
	AssignmentRevoked   AssignmentStatus = "REVOKED"
	AssignmentFulfilled AssignmentStatus = "FULFILLED"
)

// Terminal reports whether the responsibility relationship can no longer
// transition.
func (s AssignmentStatus) Terminal() bool {
	return s == AssignmentDeclined || s == AssignmentReleased ||
		s == AssignmentRevoked || s == AssignmentFulfilled
}

// OperationKind is an authenticated mutation. DELEGATE creates a child
// assignment; it does not implicitly release the parent assignment.
type OperationKind string

const (
	OperationOffer    OperationKind = "OFFER"
	OperationAccept   OperationKind = "ACCEPT"
	OperationDecline  OperationKind = "DECLINE"
	OperationRelease  OperationKind = "RELEASE"
	OperationRevoke   OperationKind = "REVOKE"
	OperationFulfill  OperationKind = "FULFILL"
	OperationDelegate OperationKind = "DELEGATE"
)

// Reason records a machine-readable code and bounded diagnostic text.
type Reason struct {
	Code   OperationKind `json:"code"`
	Detail string        `json:"detail,omitempty"`
}

// AuthenticatedOperation is the projection of a freshly verified ASB
// authorization. ParticipantID is the accountable principal whose authority
// ActorID exercises; those identifiers are deliberately allowed to differ.
type AuthenticatedOperation struct {
	ActorID             string        `json:"actor_id"`
	ParticipantID       string        `json:"participant_id"`
	AuthorizationID     string        `json:"authorization_id"`
	ProofID             string        `json:"proof_id"`
	Operation           OperationKind `json:"operation"`
	TaskID              string        `json:"task_id"`
	AssignmentID        string        `json:"assignment_id"`
	TargetTaskID        string        `json:"target_task_id,omitempty"`
	TargetAssignmentID  string        `json:"target_assignment_id,omitempty"`
	TargetParticipantID string        `json:"target_participant_id,omitempty"`
	VerifierNonce       string        `json:"verifier_nonce"`
	IssuedAt            time.Time     `json:"issued_at"`
	ExpiresAt           time.Time     `json:"expires_at"`
}

// TransitionRecord is appended atomically with an Assignment snapshot.
type TransitionRecord struct {
	EventID         string           `json:"event_id"`
	AssignmentID    string           `json:"assignment_id"`
	TaskID          string           `json:"task_id"`
	Revision        uint64           `json:"revision"`
	Kind            OperationKind    `json:"kind"`
	From            AssignmentStatus `json:"from,omitempty"`
	To              AssignmentStatus `json:"to"`
	Reason          Reason           `json:"reason"`
	At              time.Time        `json:"at"`
	ActorID         string           `json:"actor_id"`
	ParticipantID   string           `json:"participant_id"`
	AuthorizationID string           `json:"authorization_id"`
	ProofID         string           `json:"proof_id"`
	EvidenceRef     string           `json:"evidence_ref,omitempty"`
}

// Assignment is the complete durable state of one responsibility relation.
type Assignment struct {
	Schema                 string           `json:"schema"`
	AssignmentID           string           `json:"assignment_id"`
	TaskID                 string           `json:"task_id"`
	ParticipantID          string           `json:"participant_id"`
	OfferedByParticipantID string           `json:"offered_by_participant_id"`
	Role                   AssignmentRole   `json:"role"`
	AuthorityDigest        string           `json:"authority_digest"`
	ParentAssignmentID     string           `json:"parent_assignment_id,omitempty"`
	Revision               uint64           `json:"revision"`
	Status                 AssignmentStatus `json:"status"`
	AcceptedAt             *time.Time       `json:"accepted_at,omitempty"`
	DueAt                  *time.Time       `json:"due_at,omitempty"`
	LastTransition         TransitionRecord `json:"last_transition"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

// AssignmentDefinition contains immutable fields for a new offer.
type AssignmentDefinition struct {
	EventID            string
	AssignmentID       string
	TaskID             string
	ParticipantID      string
	Role               AssignmentRole
	AuthorityDigest    string
	ParentAssignmentID string
	OfferedAt          time.Time
	DueAt              *time.Time
}

// Event is an attempted compare-and-swap Assignment mutation.
type Event struct {
	ID               string
	Kind             OperationKind
	ExpectedRevision uint64
	At               time.Time
	Detail           string
	EvidenceRef      string
	Auth             AuthenticatedOperation
}

// InteractionKind identifies an immutable conversational event. These values
// are deliberately separate from Assignment operations and states.
type InteractionKind string

const (
	InteractionQuestion   InteractionKind = "QUESTION"
	InteractionResponse   InteractionKind = "RESPONSE"
	InteractionCorrection InteractionKind = "CORRECTION"
	InteractionWithdrawal InteractionKind = "WITHDRAWAL"
)

// ResponseFinality is an author's assertion about one response version. FINAL
// does not close an interaction or fulfill an Assignment.
type ResponseFinality string

const (
	ResponseInterim ResponseFinality = "INTERIM"
	ResponseFinal   ResponseFinality = "FINAL"
)

// InteractionEventDefinition contains the semantic content of a new event.
// ContentRef addresses content outside this package and ContentDigest binds its
// exact bytes. WITHDRAWAL has neither field.
type InteractionEventDefinition struct {
	EventID       string
	InteractionID string
	TaskID        string
	AssignmentID  string
	Kind          InteractionKind
	InReplyTo     string
	Supersedes    string
	Finality      ResponseFinality
	ContentRef    string
	ContentDigest string
	EvidenceRef   string
	At            time.Time
}

// AuthenticatedInteraction is the projection of a freshly verified ASB
// authorization for one exact interaction event. ParticipantID is the author
// whose authority ActorID exercises; a Human gateway and Human therefore keep
// distinct identifiers.
type AuthenticatedInteraction struct {
	ActorID         string           `json:"actor_id"`
	ParticipantID   string           `json:"participant_id"`
	AuthorizationID string           `json:"authorization_id"`
	ProofID         string           `json:"proof_id"`
	EventID         string           `json:"event_id"`
	InteractionID   string           `json:"interaction_id"`
	TaskID          string           `json:"task_id"`
	AssignmentID    string           `json:"assignment_id"`
	Kind            InteractionKind  `json:"kind"`
	InReplyTo       string           `json:"in_reply_to,omitempty"`
	Supersedes      string           `json:"supersedes,omitempty"`
	Finality        ResponseFinality `json:"finality,omitempty"`
	ContentRef      string           `json:"content_ref,omitempty"`
	ContentDigest   string           `json:"content_digest,omitempty"`
	EvidenceRef     string           `json:"evidence_ref,omitempty"`
	At              time.Time        `json:"at"`
	VerifierNonce   string           `json:"verifier_nonce"`
	IssuedAt        time.Time        `json:"issued_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
}

// InteractionEvent is an append-only question, response, correction, or
// withdrawal. Corrections and withdrawals preserve the superseded event.
type InteractionEvent struct {
	Schema          string           `json:"schema"`
	EventID         string           `json:"event_id"`
	InteractionID   string           `json:"interaction_id"`
	TaskID          string           `json:"task_id"`
	AssignmentID    string           `json:"assignment_id"`
	Kind            InteractionKind  `json:"kind"`
	InReplyTo       string           `json:"in_reply_to,omitempty"`
	Supersedes      string           `json:"supersedes,omitempty"`
	Finality        ResponseFinality `json:"finality,omitempty"`
	ContentRef      string           `json:"content_ref,omitempty"`
	ContentDigest   string           `json:"content_digest,omitempty"`
	At              time.Time        `json:"at"`
	ActorID         string           `json:"actor_id"`
	ParticipantID   string           `json:"participant_id"`
	AuthorizationID string           `json:"authorization_id"`
	ProofID         string           `json:"proof_id"`
	EvidenceRef     string           `json:"evidence_ref,omitempty"`
}

// Transition is committed atomically by a Store.
type Transition struct {
	Assignment Assignment
	Record     TransitionRecord
}

// VerifiedDelegation is produced by an authorization/policy verifier. The
// state machine checks its bindings but does not infer scope narrowing from
// opaque digests.
type VerifiedDelegation struct {
	DecisionID            string    `json:"decision_id"`
	ParentAssignmentID    string    `json:"parent_assignment_id"`
	ChildAssignmentID     string    `json:"child_assignment_id"`
	FromParticipantID     string    `json:"from_participant_id"`
	ToParticipantID       string    `json:"to_participant_id"`
	ParentAuthorityDigest string    `json:"parent_authority_digest"`
	ChildAuthorityDigest  string    `json:"child_authority_digest"`
	PolicyRef             string    `json:"policy_ref"`
	EvidenceRef           string    `json:"evidence_ref"`
	VerifiedAt            time.Time `json:"verified_at"`
}

// DelegationRecord preserves the immutable parent-child provenance edge.
type DelegationRecord struct {
	EventID               string    `json:"event_id"`
	DecisionID            string    `json:"decision_id"`
	ParentAssignmentID    string    `json:"parent_assignment_id"`
	ChildAssignmentID     string    `json:"child_assignment_id"`
	ParentTaskID          string    `json:"parent_task_id"`
	ChildTaskID           string    `json:"child_task_id"`
	FromParticipantID     string    `json:"from_participant_id"`
	ToParticipantID       string    `json:"to_participant_id"`
	ParentAuthorityDigest string    `json:"parent_authority_digest"`
	ChildAuthorityDigest  string    `json:"child_authority_digest"`
	PolicyRef             string    `json:"policy_ref"`
	EvidenceRef           string    `json:"evidence_ref"`
	At                    time.Time `json:"at"`
}

// DelegationTransition must be committed atomically: the parent audit event,
// child offer, and immutable delegation edge either all persist or none do.
type DelegationTransition struct {
	Parent       Assignment
	ParentRecord TransitionRecord
	Child        Assignment
	ChildRecord  TransitionRecord
	Delegation   DelegationRecord
}
