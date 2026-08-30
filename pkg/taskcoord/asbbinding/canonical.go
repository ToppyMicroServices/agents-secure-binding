// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	ProfileID                 = "asb.taskcoord-human-request/v1"
	RequestDigestDomain       = "ASB-TASKCOORD-HUMAN-REQUEST-v1"
	RequestContextDomain      = "ASB-TASKCOORD-HUMAN-CONTEXT-v1"
	AuthorizationDetailPrefix = "urn:asb:taskcoord-human-request:v1:sha256:"

	RequestKindAssignmentOffer      RequestKind = "ASSIGNMENT_OFFER"
	RequestKindAssignmentTransition RequestKind = "ASSIGNMENT_TRANSITION"
	RequestKindAssignmentDelegation RequestKind = "ASSIGNMENT_DELEGATION"
	RequestKindInteractionAppend    RequestKind = "INTERACTION_APPEND"
)

const (
	maxIDBytes        = 256
	maxDetailBytes    = 1024
	maxReferenceBytes = 2048
)

var (
	ErrInvalidRequest = errors.New("asbbinding: invalid Human request")
	ErrTranscriptSize = errors.New("asbbinding: request transcript exceeds limit")
)

type RequestKind string

type Digest [sha256.Size]byte

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

type OfferRequest struct {
	ParticipantID       string                   `json:"participant_id"`
	EventID             string                   `json:"event_id"`
	TaskID              string                   `json:"task_id"`
	AssignmentID        string                   `json:"assignment_id"`
	TargetParticipantID string                   `json:"target_participant_id"`
	Role                taskcoord.AssignmentRole `json:"role"`
	AuthorityDigest     string                   `json:"authority_digest"`
	DueAt               *time.Time               `json:"due_at,omitempty"`
}

type TransitionRequest struct {
	ParticipantID    string                  `json:"participant_id"`
	EventID          string                  `json:"event_id"`
	TaskID           string                  `json:"task_id"`
	AssignmentID     string                  `json:"assignment_id"`
	Operation        taskcoord.OperationKind `json:"operation"`
	ExpectedRevision uint64                  `json:"expected_revision"`
	Detail           string                  `json:"detail,omitempty"`
	EvidenceRef      string                  `json:"evidence_ref,omitempty"`
}

type DelegationRequest struct {
	ParticipantID       string                   `json:"participant_id"`
	EventID             string                   `json:"event_id"`
	ParentTaskID        string                   `json:"parent_task_id"`
	ParentAssignmentID  string                   `json:"parent_assignment_id"`
	ExpectedRevision    uint64                   `json:"expected_revision"`
	Detail              string                   `json:"detail,omitempty"`
	EvidenceRef         string                   `json:"evidence_ref,omitempty"`
	DecisionID          string                   `json:"decision_id"`
	ChildEventID        string                   `json:"child_event_id"`
	ChildTaskID         string                   `json:"child_task_id"`
	ChildAssignmentID   string                   `json:"child_assignment_id"`
	TargetParticipantID string                   `json:"target_participant_id"`
	Role                taskcoord.AssignmentRole `json:"role"`
	AuthorityDigest     string                   `json:"authority_digest"`
	DueAt               *time.Time               `json:"due_at,omitempty"`
}

type InteractionRequest struct {
	ParticipantID string                     `json:"participant_id"`
	EventID       string                     `json:"event_id"`
	InteractionID string                     `json:"interaction_id"`
	TaskID        string                     `json:"task_id"`
	AssignmentID  string                     `json:"assignment_id"`
	Kind          taskcoord.InteractionKind  `json:"kind"`
	InReplyTo     string                     `json:"in_reply_to,omitempty"`
	Supersedes    string                     `json:"supersedes,omitempty"`
	Finality      taskcoord.ResponseFinality `json:"finality,omitempty"`
	ContentRef    string                     `json:"content_ref,omitempty"`
	ContentDigest string                     `json:"content_digest,omitempty"`
	EvidenceRef   string                     `json:"evidence_ref,omitempty"`
}

func OfferDigest(request OfferRequest) (Digest, error) {
	if err := request.validate(); err != nil {
		return Digest{}, err
	}
	encoder := newTranscript(RequestKindAssignmentOffer)
	encoder.addString("participant_id", request.ParticipantID)
	encoder.addString("event_id", request.EventID)
	encoder.addString("task_id", request.TaskID)
	encoder.addString("assignment_id", request.AssignmentID)
	encoder.addString("target_participant_id", request.TargetParticipantID)
	encoder.addString("role", string(request.Role))
	encoder.addDigest("authority_digest", request.AuthorityDigest)
	encoder.addTime("due_at", request.DueAt)
	return encoder.digest()
}

func TransitionDigest(request TransitionRequest) (Digest, error) {
	if err := request.validate(); err != nil {
		return Digest{}, err
	}
	encoder := newTranscript(RequestKindAssignmentTransition)
	encoder.addString("participant_id", request.ParticipantID)
	encoder.addString("event_id", request.EventID)
	encoder.addString("task_id", request.TaskID)
	encoder.addString("assignment_id", request.AssignmentID)
	encoder.addString("operation", string(request.Operation))
	encoder.addUint64("expected_revision", request.ExpectedRevision)
	encoder.addString("detail", request.Detail)
	encoder.addString("evidence_ref", request.EvidenceRef)
	return encoder.digest()
}

func DelegationDigest(request DelegationRequest) (Digest, error) {
	if err := request.validate(); err != nil {
		return Digest{}, err
	}
	encoder := newTranscript(RequestKindAssignmentDelegation)
	encoder.addString("participant_id", request.ParticipantID)
	encoder.addString("event_id", request.EventID)
	encoder.addString("parent_task_id", request.ParentTaskID)
	encoder.addString("parent_assignment_id", request.ParentAssignmentID)
	encoder.addUint64("expected_revision", request.ExpectedRevision)
	encoder.addString("detail", request.Detail)
	encoder.addString("evidence_ref", request.EvidenceRef)
	encoder.addString("decision_id", request.DecisionID)
	encoder.addString("child_event_id", request.ChildEventID)
	encoder.addString("child_task_id", request.ChildTaskID)
	encoder.addString("child_assignment_id", request.ChildAssignmentID)
	encoder.addString("target_participant_id", request.TargetParticipantID)
	encoder.addString("role", string(request.Role))
	encoder.addDigest("authority_digest", request.AuthorityDigest)
	encoder.addTime("due_at", request.DueAt)
	return encoder.digest()
}

func InteractionDigest(request InteractionRequest) (Digest, error) {
	if err := request.validate(); err != nil {
		return Digest{}, err
	}
	encoder := newTranscript(RequestKindInteractionAppend)
	encoder.addString("participant_id", request.ParticipantID)
	encoder.addString("event_id", request.EventID)
	encoder.addString("interaction_id", request.InteractionID)
	encoder.addString("task_id", request.TaskID)
	encoder.addString("assignment_id", request.AssignmentID)
	encoder.addString("kind", string(request.Kind))
	encoder.addString("in_reply_to", request.InReplyTo)
	encoder.addString("supersedes", request.Supersedes)
	encoder.addString("finality", string(request.Finality))
	encoder.addString("content_ref", request.ContentRef)
	encoder.addOptionalDigest("content_digest", request.ContentDigest)
	encoder.addString("evidence_ref", request.EvidenceRef)
	return encoder.digest()
}

func AuthorizationDetail(digest Digest) string {
	return AuthorizationDetailPrefix + digest.String()
}

func RequestContext(digest Digest) []byte {
	encoder := transcriptEncoder{}
	encoder.buffer.WriteString(RequestContextDomain)
	encoder.buffer.WriteByte(0)
	encoder.add("request_digest", digest[:])
	return append([]byte(nil), encoder.buffer.Bytes()...)
}

func RequestContextSHA256(digest Digest) string {
	sum := sha256.Sum256(RequestContext(digest))
	return hex.EncodeToString(sum[:])
}

func (r OfferRequest) validate() error {
	for name, value := range map[string]string{
		"participant_id":        r.ParticipantID,
		"event_id":              r.EventID,
		"task_id":               r.TaskID,
		"assignment_id":         r.AssignmentID,
		"target_participant_id": r.TargetParticipantID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if !validRole(r.Role) {
		return invalid("unsupported assignment role")
	}
	if _, err := decodeDigest("authority_digest", r.AuthorityDigest, false); err != nil {
		return err
	}
	return validateOptionalTime("due_at", r.DueAt)
}

func (r TransitionRequest) validate() error {
	for name, value := range map[string]string{
		"participant_id": r.ParticipantID,
		"event_id":       r.EventID,
		"task_id":        r.TaskID,
		"assignment_id":  r.AssignmentID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	switch r.Operation {
	case taskcoord.OperationAccept, taskcoord.OperationDecline, taskcoord.OperationRelease,
		taskcoord.OperationRevoke, taskcoord.OperationFulfill:
	default:
		return invalid("unsupported assignment transition operation")
	}
	if r.ExpectedRevision == 0 {
		return invalid("expected_revision must be positive")
	}
	if err := validateDetail(r.Detail); err != nil {
		return err
	}
	return validateOptionalReference("evidence_ref", r.EvidenceRef)
}

func (r DelegationRequest) validate() error {
	for name, value := range map[string]string{
		"participant_id":        r.ParticipantID,
		"event_id":              r.EventID,
		"parent_task_id":        r.ParentTaskID,
		"parent_assignment_id":  r.ParentAssignmentID,
		"decision_id":           r.DecisionID,
		"child_event_id":        r.ChildEventID,
		"child_task_id":         r.ChildTaskID,
		"child_assignment_id":   r.ChildAssignmentID,
		"target_participant_id": r.TargetParticipantID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if r.ExpectedRevision == 0 {
		return invalid("expected_revision must be positive")
	}
	if r.ParentAssignmentID == r.ChildAssignmentID {
		return invalid("parent and child assignment must differ")
	}
	if r.ParticipantID == r.TargetParticipantID {
		return invalid("self-delegation is not allowed")
	}
	if !validRole(r.Role) {
		return invalid("unsupported assignment role")
	}
	if err := validateDetail(r.Detail); err != nil {
		return err
	}
	if err := validateOptionalReference("evidence_ref", r.EvidenceRef); err != nil {
		return err
	}
	if _, err := decodeDigest("authority_digest", r.AuthorityDigest, false); err != nil {
		return err
	}
	return validateOptionalTime("due_at", r.DueAt)
}

func (r InteractionRequest) validate() error {
	for name, value := range map[string]string{
		"participant_id": r.ParticipantID,
		"event_id":       r.EventID,
		"interaction_id": r.InteractionID,
		"task_id":        r.TaskID,
		"assignment_id":  r.AssignmentID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{
		"in_reply_to": r.InReplyTo,
		"supersedes":  r.Supersedes,
	} {
		if value != "" {
			if err := validateID(name, value); err != nil {
				return err
			}
			if value == r.EventID {
				return invalid(name + " must not reference the event itself")
			}
		}
	}
	if err := validateOptionalReference("evidence_ref", r.EvidenceRef); err != nil {
		return err
	}

	requireContent := func() error {
		if err := validateRequiredReference("content_ref", r.ContentRef); err != nil {
			return err
		}
		_, err := decodeDigest("content_digest", r.ContentDigest, false)
		return err
	}
	switch r.Kind {
	case taskcoord.InteractionQuestion:
		if r.Supersedes != "" || r.Finality != "" {
			return invalid("QUESTION must not contain supersedes or finality")
		}
		return requireContent()
	case taskcoord.InteractionResponse:
		if r.InReplyTo == "" || r.Supersedes != "" || !validFinality(r.Finality) {
			return invalid("RESPONSE requires in_reply_to and finality only")
		}
		return requireContent()
	case taskcoord.InteractionCorrection:
		if r.InReplyTo == "" || r.Supersedes == "" || !validFinality(r.Finality) {
			return invalid("CORRECTION requires in_reply_to, supersedes, and finality")
		}
		return requireContent()
	case taskcoord.InteractionWithdrawal:
		if r.InReplyTo == "" || r.Supersedes == "" || r.Finality != "" ||
			r.ContentRef != "" || r.ContentDigest != "" {
			return invalid("WITHDRAWAL requires reply and supersession without content or finality")
		}
		return nil
	default:
		return invalid("unsupported interaction kind")
	}
}

type transcriptEncoder struct {
	buffer bytes.Buffer
	err    error
}

func newTranscript(kind RequestKind) *transcriptEncoder {
	encoder := &transcriptEncoder{}
	encoder.buffer.WriteString(RequestDigestDomain)
	encoder.buffer.WriteByte(0)
	encoder.addString("request_kind", string(kind))
	return encoder
}

func (e *transcriptEncoder) addString(name, value string) {
	e.add(name, []byte(value))
}

func (e *transcriptEncoder) addUint64(name string, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	e.add(name, encoded[:])
}

func (e *transcriptEncoder) addTime(name string, value *time.Time) {
	if value == nil {
		e.add(name, nil)
		return
	}
	var encoded [12]byte
	binary.BigEndian.PutUint64(encoded[:8], uint64(value.Unix()))
	binary.BigEndian.PutUint32(encoded[8:], uint32(value.Nanosecond()))
	e.add(name, encoded[:])
}

func (e *transcriptEncoder) addDigest(name, value string) {
	raw, err := decodeDigest(name, value, false)
	if err != nil {
		e.err = err
		return
	}
	e.add(name, raw)
}

func (e *transcriptEncoder) addOptionalDigest(name, value string) {
	raw, err := decodeDigest(name, value, true)
	if err != nil {
		e.err = err
		return
	}
	e.add(name, raw)
}

func (e *transcriptEncoder) add(name string, value []byte) {
	if e.err != nil {
		return
	}
	if len(name) > math.MaxUint16 || uint64(len(value)) > math.MaxUint32 {
		e.err = ErrTranscriptSize
		return
	}
	var lengths [4]byte
	binary.BigEndian.PutUint16(lengths[:2], uint16(len(name)))
	e.buffer.Write(lengths[:2])
	e.buffer.WriteString(name)
	binary.BigEndian.PutUint32(lengths[:], uint32(len(value)))
	e.buffer.Write(lengths[:])
	e.buffer.Write(value)
	if e.buffer.Len() > taskcoord.MaxDocumentBytes {
		e.err = ErrTranscriptSize
	}
}

func (e *transcriptEncoder) digest() (Digest, error) {
	if e.err != nil {
		return Digest{}, e.err
	}
	return sha256.Sum256(e.buffer.Bytes()), nil
}

func validateID(name, value string) error {
	if value == "" || !utf8.ValidString(value) || len(value) > maxIDBytes {
		return invalid(name + " is not a bounded UTF-8 identifier")
	}
	if strings.TrimSpace(value) != value {
		return invalid(name + " has surrounding whitespace")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return invalid(name + " contains a control character")
		}
	}
	return nil
}

func validateDetail(value string) error {
	if !utf8.ValidString(value) || len(value) > maxDetailBytes {
		return invalid("detail is not bounded UTF-8")
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			return invalid("detail contains an unsupported control character")
		}
	}
	return nil
}

func validateRequiredReference(name, value string) error {
	if value == "" {
		return invalid(name + " is required")
	}
	return validateOptionalReference(name, value)
}

func validateOptionalReference(name, value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) || len(value) > maxReferenceBytes {
		return invalid(name + " is not a bounded UTF-8 reference")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return invalid(name + " contains a control character")
		}
	}
	return nil
}

func validateOptionalTime(name string, value *time.Time) error {
	if value != nil && value.IsZero() {
		return invalid(name + " must not be zero")
	}
	return nil
}

func decodeDigest(name, value string, optional bool) ([]byte, error) {
	if optional && value == "" {
		return nil, nil
	}
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return nil, invalid(name + " must be 64 lowercase hexadecimal characters")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, invalid(name + " must be hexadecimal")
	}
	return raw, nil
}

func validRole(role taskcoord.AssignmentRole) bool {
	return role == taskcoord.RoleOwner || role == taskcoord.RoleAssignee || role == taskcoord.RoleReviewer
}

func validFinality(finality taskcoord.ResponseFinality) bool {
	return finality == taskcoord.ResponseInterim || finality == taskcoord.ResponseFinal
}

func invalid(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, message)
}
