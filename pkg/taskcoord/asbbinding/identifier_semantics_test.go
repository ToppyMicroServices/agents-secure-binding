// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/schemas"
)

func TestHumanIngressIdentifierCrossLayerBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		identifier   string
		wantSchema   bool
		wantSemantic bool
	}{
		{"ASCII octet limit", strings.Repeat("a", 256), true, true},
		{"ASCII over limit", strings.Repeat("a", 257), false, false},
		{"multibyte octet limit", strings.Repeat("é", 128), true, true},
		{"schema-only multibyte overflow", strings.Repeat("é", 129), true, false},
		{"NFC", "participant:é", true, true},
		{"NFD", "participant:e\u0301", true, true},
		{"interior whitespace", "participant:human alice", true, true},
		{"deterministic leading-whitespace seed", " 000000000", false, false},
		{"Unicode leading whitespace", "\u00a0participant", false, false},
		{"Unicode trailing whitespace", "participant\u3000", false, false},
		{"C0 control", "participant:\u0001", false, false},
		{"C1 control", "participant:\u0085", false, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := TransitionRequest{
				ParticipantID: test.identifier,
				EventID:       "event:identifier", TaskID: "task:identifier",
				AssignmentID: "assignment:identifier",
				Operation:    taskcoord.OperationAccept, ExpectedRevision: 1,
			}
			requestJSON, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			envelopeJSON, err := json.Marshal(ChallengeRequest{
				Operation: OperationAssignmentTransition,
				Request:   requestJSON,
			})
			if err != nil {
				t.Fatal(err)
			}
			schemaOK := schemas.ValidateHumanIngressChallengeJSON(envelopeJSON) == nil
			if schemaOK != test.wantSchema {
				t.Errorf("schema acceptance = %v, want %v", schemaOK, test.wantSchema)
			}
			_, semanticErr := TransitionDigest(request)
			semanticOK := semanticErr == nil
			if semanticOK != test.wantSemantic {
				t.Errorf("semantic acceptance = %v, want %v (error %v)", semanticOK, test.wantSemantic, semanticErr)
			}
		})
	}
}

func TestHumanIngressIdentifiersRemainByteDistinct(t *testing.T) {
	t.Parallel()
	request := TransitionRequest{
		ParticipantID: "participant:é",
		EventID:       "event:identifier", TaskID: "task:identifier",
		AssignmentID: "assignment:identifier",
		Operation:    taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	nfc, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ParticipantID = "participant:e\u0301"
	nfd, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if nfc == nfd {
		t.Fatal("NFC and NFD identifiers produced the same request digest")
	}

	request.ParticipantID = "Participant:Case"
	upper, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ParticipantID = "participant:case"
	lower, err := TransitionDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if upper == lower {
		t.Fatal("case-distinct identifiers produced the same request digest")
	}
}
