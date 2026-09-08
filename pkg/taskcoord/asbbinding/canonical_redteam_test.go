// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/schemas"
)

// These are deterministic parser boundary cases rather than an unbounded
// parser fuzzer. Keeping the seeds small makes this suite suitable for the
// ordinary Mac and CI race-test gates.
func TestIngressStrictJSONRejectsAdversarialDocuments(t *testing.T) {
	t.Parallel()

	tooDeep := []byte(strings.Repeat("[", 10_001) + "0" + strings.Repeat("]", 10_001))
	tooLarge := []byte(strings.Repeat(" ", taskcoord.MaxDocumentBytes+1))
	invalidUTF8 := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}

	tests := []struct {
		name   string
		raw    []byte
		target func() any
	}{
		{
			name: "escaped duplicate member",
			raw: []byte(
				`{"operation":"ASSIGNMENT_TRANSITION","oper\u0061tion":"INTERACTION_APPEND","request":{}}`,
			),
			target: func() any { return new(any) },
		},
		{
			name: "nested escaped duplicate member",
			raw: []byte(
				`{"request":{"participant_id":"human:one","p\u0061rticipant_id":"human:two"}}`,
			),
			target: func() any { return new(any) },
		},
		{
			name:   "invalid UTF-8",
			raw:    invalidUTF8,
			target: func() any { return new(any) },
		},
		{
			name:   "trailing document",
			raw:    []byte(`{"value":1}{"value":2}`),
			target: func() any { return new(any) },
		},
		{
			name:   "excessive nesting",
			raw:    tooDeep,
			target: func() any { return new(any) },
		},
		{
			name: "uint64 overflow",
			raw: []byte(
				`{"participant_id":"human:one","event_id":"event:one","task_id":"task:one",` +
					`"assignment_id":"assignment:one","operation":"ACCEPT",` +
					`"expected_revision":18446744073709551616}`,
			),
			target: func() any { return new(TransitionRequest) },
		},
		{
			name: "timestamp outside JSON time range",
			raw: []byte(
				`{"participant_id":"human:one","event_id":"event:one","task_id":"task:one",` +
					`"assignment_id":"assignment:one","target_participant_id":"agent:one",` +
					`"role":"ASSIGNEE","authority_digest":"` + strings.Repeat("a", 64) + `",` +
					`"due_at":"10000-01-01T00:00:00Z"}`,
			),
			target: func() any { return new(OfferRequest) },
		},
		{
			name:   "document byte limit",
			raw:    tooLarge,
			target: func() any { return new(any) },
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := decodeIngressJSON(strings.NewReader(string(test.raw)), test.target()); err == nil {
				t.Fatal("adversarial JSON document was accepted")
			}
		})
	}
}

func FuzzHumanIngressStrictJSONDifferential(f *testing.F) {
	valid := []byte(
		`{"operation":"ASSIGNMENT_TRANSITION","request":{` +
			`"participant_id":"human:fuzz","event_id":"event:fuzz","task_id":"task:fuzz",` +
			`"assignment_id":"assignment:fuzz","operation":"ACCEPT","expected_revision":1}}`,
	)
	seeds := [][]byte{
		valid,
		[]byte(`{"operation":"ASSIGNMENT_TRANSITION","oper\u0061tion":"INTERACTION_APPEND","request":{}}`),
		[]byte(`{"request":{"participant_id":"human:one","p\u0061rticipant_id":"human:two"}}`),
		{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		[]byte(`{"value":1}{"value":2}`),
		[]byte(strings.Repeat("[", 10_001) + "0" + strings.Repeat("]", 10_001)),
		[]byte(
			`{"participant_id":"human:one","event_id":"event:one","task_id":"task:one",` +
				`"assignment_id":"assignment:one","operation":"ACCEPT",` +
				`"expected_revision":18446744073709551616}`,
		),
		[]byte(
			`{"participant_id":"human:one","event_id":"event:one","task_id":"task:one",` +
				`"assignment_id":"assignment:one","target_participant_id":"agent:one",` +
				`"role":"ASSIGNEE","authority_digest":"` + strings.Repeat("a", 64) + `",` +
				`"due_at":"10000-01-01T00:00:00Z"}`,
		),
		[]byte(strings.Repeat(" ", taskcoord.MaxDocumentBytes+1)),
		[]byte(
			`{"operation":"ASSIGNMENT_TRANSITION","request":{` +
				`"participant_id":"` + strings.Repeat("é", maxIDBytes/2+1) + `",` +
				`"event_id":"event:fuzz","task_id":"task:fuzz","assignment_id":"assignment:fuzz",` +
				`"operation":"ACCEPT","expected_revision":1}}`,
		),
		[]byte(
			`{"operation":"ASSIGNMENT_DELEGATION","request":{` +
				`"participant_id":"human:fuzz","event_id":"event:fuzz","parent_task_id":"task:parent",` +
				`"parent_assignment_id":"assignment:same","expected_revision":1,"decision_id":"decision:fuzz",` +
				`"child_event_id":"event:child","child_task_id":"task:child","child_assignment_id":"assignment:same",` +
				`"target_participant_id":"agent:fuzz","role":"ASSIGNEE","authority_digest":"` + strings.Repeat("a", 64) + `"}}`,
		),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var envelope ChallengeRequest
		if err := decodeIngressEnvelope(
			bytes.NewReader(raw),
			&envelope,
			schemas.ValidateHumanIngressChallengeJSON,
		); err != nil {
			return
		}

		operation, err := decodeOperation(envelope.Operation, envelope.Request)
		if err != nil {
			if knownSchemaSemanticGap(operation) {
				return
			}
			t.Fatalf("schema accepted an operation rejected outside the documented semantic-only rules: %v", err)
		}
		recomputed, err := canonicalRedTeamDigest(operation)
		if err != nil {
			t.Fatalf("schema-accepted operation failed canonical recomputation: %v", err)
		}
		if recomputed != operation.digest {
			t.Fatal("canonical digest changed across identical decode and recomputation")
		}
	})
}

// knownSchemaSemanticGap names the rules that Draft 2020-12 cannot express in
// the published schema: UTF-8 octet ceilings, equality between two properties,
// and the verifier's exclusion of the zero time instant. Every other
// schema-accepted semantic rejection is a differential failure.
func knownSchemaSemanticGap(operation operationEnvelope) bool {
	switch operation.kind {
	case RequestKindAssignmentOffer:
		if operation.offer == nil {
			return false
		}
		request := operation.offer
		return anyUTF8ValueOver(maxIDBytes,
			request.ParticipantID, request.EventID, request.TaskID,
			request.AssignmentID, request.TargetParticipantID,
		) || (request.DueAt != nil && request.DueAt.IsZero())
	case RequestKindAssignmentTransition:
		if operation.transition == nil {
			return false
		}
		request := operation.transition
		return anyUTF8ValueOver(maxIDBytes,
			request.ParticipantID, request.EventID, request.TaskID, request.AssignmentID,
		) || anyUTF8ValueOver(maxDetailBytes, request.Detail) ||
			anyUTF8ValueOver(maxReferenceBytes, request.EvidenceRef)
	case RequestKindAssignmentDelegation:
		if operation.delegation == nil {
			return false
		}
		request := operation.delegation
		return anyUTF8ValueOver(maxIDBytes,
			request.ParticipantID, request.EventID, request.ParentTaskID,
			request.ParentAssignmentID, request.DecisionID, request.ChildEventID,
			request.ChildTaskID, request.ChildAssignmentID, request.TargetParticipantID,
		) || anyUTF8ValueOver(maxDetailBytes, request.Detail) ||
			anyUTF8ValueOver(maxReferenceBytes, request.EvidenceRef) ||
			request.ParentAssignmentID == request.ChildAssignmentID ||
			request.ParticipantID == request.TargetParticipantID ||
			(request.DueAt != nil && request.DueAt.IsZero())
	case RequestKindInteractionAppend:
		if operation.interaction == nil {
			return false
		}
		request := operation.interaction
		return anyUTF8ValueOver(maxIDBytes,
			request.ParticipantID, request.EventID, request.InteractionID,
			request.TaskID, request.AssignmentID, request.InReplyTo, request.Supersedes,
		) || anyUTF8ValueOver(maxReferenceBytes, request.ContentRef, request.EvidenceRef) ||
			(request.InReplyTo != "" && request.InReplyTo == request.EventID) ||
			(request.Supersedes != "" && request.Supersedes == request.EventID)
	default:
		return false
	}
}

func anyUTF8ValueOver(limit int, values ...string) bool {
	for _, value := range values {
		if len(value) > limit {
			return true
		}
	}
	return false
}

func canonicalRedTeamDigest(operation operationEnvelope) (Digest, error) {
	switch operation.kind {
	case RequestKindAssignmentOffer:
		return OfferDigest(*operation.offer)
	case RequestKindAssignmentTransition:
		return TransitionDigest(*operation.transition)
	case RequestKindAssignmentDelegation:
		return DelegationDigest(*operation.delegation)
	case RequestKindInteractionAppend:
		return InteractionDigest(*operation.interaction)
	default:
		return Digest{}, ErrUnsupportedOperationKind
	}
}

func TestCanonicalTranscriptUsesExactUnicodeBytes(t *testing.T) {
	t.Parallel()

	nfc := TransitionRequest{
		ParticipantID:    "human:caf\u00e9",
		EventID:          "event:unicode",
		TaskID:           "task:unicode",
		AssignmentID:     "assignment:unicode",
		Operation:        taskcoord.OperationAccept,
		ExpectedRevision: 1,
	}
	nfd := nfc
	nfd.ParticipantID = "human:cafe\u0301"

	nfcDigest, err := TransitionDigest(nfc)
	if err != nil {
		t.Fatalf("NFC request rejected: %v", err)
	}
	nfdDigest, err := TransitionDigest(nfd)
	if err != nil {
		t.Fatalf("NFD request rejected: %v", err)
	}
	if nfcDigest == nfdDigest {
		t.Fatal("canonically equivalent but byte-distinct identifiers produced the same digest")
	}
}

func TestCanonicalRequestKindsSeparateIdenticalPayloads(t *testing.T) {
	t.Parallel()

	kinds := []RequestKind{
		RequestKindAssignmentOffer,
		RequestKindAssignmentTransition,
		RequestKindAssignmentDelegation,
		RequestKindInteractionAppend,
	}
	seen := make(map[Digest]RequestKind, len(kinds))
	for _, kind := range kinds {
		digest, err := newTranscript(kind).digest()
		if err != nil {
			t.Fatalf("empty %s transcript: %v", kind, err)
		}
		if previous, duplicate := seen[digest]; duplicate {
			t.Fatalf("request kinds %s and %s share a transcript digest", previous, kind)
		}
		seen[digest] = kind
	}
}

func TestCanonicalValidationUsesUTF8ByteLimits(t *testing.T) {
	t.Parallel()

	base := TransitionRequest{
		EventID:          "event:byte-limit",
		TaskID:           "task:byte-limit",
		AssignmentID:     "assignment:byte-limit",
		Operation:        taskcoord.OperationAccept,
		ExpectedRevision: 1,
	}

	atIDLimit := base
	atIDLimit.ParticipantID = strings.Repeat("é", maxIDBytes/2)
	if len(atIDLimit.ParticipantID) != maxIDBytes {
		t.Fatalf("test identifier length = %d, want %d", len(atIDLimit.ParticipantID), maxIDBytes)
	}
	if _, err := TransitionDigest(atIDLimit); err != nil {
		t.Fatalf("identifier at byte limit rejected: %v", err)
	}

	overIDLimit := atIDLimit
	overIDLimit.ParticipantID += "é"
	if _, err := TransitionDigest(overIDLimit); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("identifier over byte limit error = %v, want ErrInvalidRequest", err)
	}

	atDetailLimit := base
	atDetailLimit.ParticipantID = "human:byte-limit"
	atDetailLimit.Detail = strings.Repeat("界", maxDetailBytes/3)
	if len(atDetailLimit.Detail) != 1023 {
		t.Fatalf("test detail length = %d, want 1023", len(atDetailLimit.Detail))
	}
	if _, err := TransitionDigest(atDetailLimit); err != nil {
		t.Fatalf("multibyte detail below byte limit rejected: %v", err)
	}

	overDetailLimit := atDetailLimit
	overDetailLimit.Detail += "界"
	if _, err := TransitionDigest(overDetailLimit); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("detail over byte limit error = %v, want ErrInvalidRequest", err)
	}
}

func TestCanonicalTimestampBindsInstantNotLocation(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 9, 2, 1, 2, 3, 456789123, time.UTC)
	offset := instant.In(time.FixedZone("test-offset", 9*60*60))
	request := OfferRequest{
		ParticipantID:       "human:time",
		EventID:             "event:time",
		TaskID:              "task:time",
		AssignmentID:        "assignment:time",
		TargetParticipantID: "agent:time",
		Role:                taskcoord.RoleAssignee,
		AuthorityDigest:     strings.Repeat("a", 64),
		DueAt:               &instant,
	}
	want, err := OfferDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.DueAt = &offset
	got, err := OfferDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("the same timestamp instant encoded differently by location")
	}
}
