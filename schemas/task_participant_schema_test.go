// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

const taskParticipantSchemaFile = "task-participant-v1.schema.json"

func TestTaskParticipantSchemaCompilesAgainstDraft202012(t *testing.T) {
	t.Parallel()
	compileTaskParticipantSchema(t)
}

func TestTaskParticipantSchemaAcceptsDurableDocuments(t *testing.T) {
	t.Parallel()
	schema := compileTaskParticipantSchema(t)
	at := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	digest := strings.Repeat("a", 64)

	participant := taskcoord.Participant{
		Schema:        taskcoord.ParticipantSchemaV1,
		ParticipantID: "human:1",
		Kind:          taskcoord.ParticipantHuman,
		IdentityRef:   "urn:identity:opaque:human-1",
		Status:        taskcoord.ParticipantActive,
		RegisteredAt:  at,
	}
	transition := taskcoord.TransitionRecord{
		EventID:         "event:offer:1",
		AssignmentID:    "assignment:1",
		TaskID:          "task:1",
		Revision:        1,
		Kind:            taskcoord.OperationOffer,
		To:              taskcoord.AssignmentOffered,
		Reason:          taskcoord.Reason{Code: taskcoord.OperationOffer},
		At:              at,
		ActorID:         "agent:requester",
		ParticipantID:   "agent:requester",
		AuthorizationID: "authorization:offer:1",
		ProofID:         "proof:offer:1",
	}

	documents := map[string]any{
		"participant": participant,
		"assignment": taskcoord.Assignment{
			Schema:                 taskcoord.AssignmentSchemaV1,
			AssignmentID:           "assignment:1",
			TaskID:                 "task:1",
			ParticipantID:          participant.ParticipantID,
			OfferedByParticipantID: "agent:requester",
			Role:                   taskcoord.RoleAssignee,
			AuthorityDigest:        digest,
			Revision:               1,
			Status:                 taskcoord.AssignmentOffered,
			LastTransition:         transition,
			CreatedAt:              at,
			UpdatedAt:              at,
		},
		"dependency": taskcoord.Dependency{
			Schema:       taskcoord.DependencySchemaV1,
			DependencyID: "dependency:1",
			FromTaskID:   "task:1",
			ToTaskID:     "task:2",
			GroupID:      "dependency-group:1",
			Mode:         taskcoord.DependencyAll,
			Active:       true,
		},
		"delegation": taskcoord.DelegationRecord{
			EventID:               "event:delegation:1",
			DecisionID:            "decision:delegation:1",
			ParentAssignmentID:    "assignment:parent",
			ChildAssignmentID:     "assignment:child",
			ParentTaskID:          "task:parent",
			ChildTaskID:           "task:child",
			FromParticipantID:     "agent:delegator",
			ToParticipantID:       participant.ParticipantID,
			ParentAuthorityDigest: digest,
			ChildAuthorityDigest:  digest,
			PolicyRef:             "urn:policy:delegation:1",
			EvidenceRef:           "urn:evidence:delegation:1",
			At:                    at,
		},
		"interaction": taskcoord.InteractionEvent{
			Schema:          taskcoord.InteractionEventSchemaV1,
			EventID:         "event:question:1",
			InteractionID:   "interaction:1",
			TaskID:          "task:1",
			AssignmentID:    "assignment:1",
			Kind:            taskcoord.InteractionQuestion,
			ContentRef:      "urn:content:question:1",
			ContentDigest:   digest,
			At:              at,
			ActorID:         "service:human-gateway",
			ParticipantID:   participant.ParticipantID,
			AuthorizationID: "authorization:question:1",
			ProofID:         "proof:question:1",
		},
		"agent discovery": taskcoord.AgentDiscoveryRecord{
			Schema:        taskcoord.AgentDiscoveryRecordSchemaV1,
			RecordID:      "agent-record:1",
			ParticipantID: "agent:translator",
			Kind:          taskcoord.ParticipantAgent,
			Capability:    "translation",
			InvocationRef: "https://agents.example/invoke/translator-1",
			PublishedAt:   at,
			ExpiresAt:     at.Add(time.Hour),
		},
		"Human match consent": taskcoord.HumanMatchConsent{
			Schema:                 taskcoord.HumanMatchConsentSchemaV1,
			ConsentID:              "human-consent:1",
			HumanParticipantID:     participant.ParticipantID,
			CandidateID:            "candidate:pairwise:1",
			RequesterParticipantID: "agent:requester",
			Purpose:                "task-consultation",
			Capability:             "translation",
			Channel:                taskcoord.ReachabilityEmail,
			ContactRequestRef:      "https://relay.example/contact-requests/opaque-1",
			ActorID:                "service:human-gateway",
			AuthorizationID:        "authorization:consent:1",
			ProofID:                "proof:consent:1",
			GrantedAt:              at,
			ExpiresAt:              at.Add(time.Hour),
		},
		"Human match consent revocation": taskcoord.HumanMatchConsentRevocation{
			Schema:             taskcoord.HumanMatchConsentRevocationSchemaV1,
			EventID:            "event:revoke-consent:1",
			ConsentID:          "human-consent:1",
			HumanParticipantID: participant.ParticipantID,
			ActorID:            "service:human-gateway",
			AuthorizationID:    "authorization:revoke-consent:1",
			ProofID:            "proof:revoke-consent:1",
			At:                 at.Add(time.Minute),
		},
		"Human reachability grant": taskcoord.HumanReachabilityGrant{
			Schema:                 taskcoord.HumanReachabilityGrantSchemaV1,
			GrantID:                "reachability-grant:1",
			CandidateID:            "candidate:pairwise:1",
			RequesterParticipantID: "agent:requester",
			Purpose:                "task-consultation",
			Capability:             "translation",
			Channel:                taskcoord.ReachabilityEmail,
			RelaySessionRef:        "https://relay.example/sessions/opaque-1",
			IssuedAt:               at.Add(time.Minute),
			ExpiresAt:              at.Add(30 * time.Minute),
		},
		"Human reachability revocation": taskcoord.HumanReachabilityRevocation{
			Schema:          taskcoord.HumanReachabilityRevocationSchemaV1,
			EventID:         "event:revoke-grant:1",
			GrantID:         "reachability-grant:1",
			ParticipantID:   participant.ParticipantID,
			ActorID:         "service:human-gateway",
			AuthorizationID: "authorization:revoke-grant:1",
			ProofID:         "proof:revoke-grant:1",
			At:              at.Add(2 * time.Minute),
		},
	}

	for name, document := range documents {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := validateDocument(schema, document); err != nil {
				t.Fatalf("valid document rejected: %v", err)
			}
		})
	}
}

func TestTaskParticipantSchemaRejectsPrivacyAndShapeViolations(t *testing.T) {
	t.Parallel()
	schema := compileTaskParticipantSchema(t)

	tests := map[string]string{
		"Human in Agent discovery": `{
			"schema":"asb.agent-discovery-record/v1",
			"record_id":"agent-record:1",
			"participant_id":"human:1",
			"kind":"HUMAN",
			"capability":"translation",
			"invocation_ref":"https://agents.example/invoke/1",
			"published_at":"2026-08-12T12:00:00Z",
			"expires_at":"2026-08-12T13:00:00Z"
		}`,
		"public Human identity": `{
			"schema":"asb.task-participant/v1",
			"participant_id":"human:1",
			"kind":"HUMAN",
			"identity_ref":"https://social.example/person",
			"status":"ACTIVE",
			"may_delegate":false,
			"registered_at":"2026-08-12T12:00:00Z"
		}`,
		"direct contact relay": `{
			"schema":"asb.human-match-consent/v1",
			"consent_id":"human-consent:1",
			"human_participant_id":"human:1",
			"candidate_id":"candidate:pairwise:1",
			"requester_participant_id":"agent:requester",
			"purpose":"task-consultation",
			"capability":"translation",
			"channel":"TEL",
			"contact_request_ref":"tel:+3585550100",
			"actor_id":"service:human-gateway",
			"authorization_id":"authorization:consent:1",
			"proof_id":"proof:consent:1",
			"granted_at":"2026-08-12T12:00:00Z",
			"expires_at":"2026-08-12T13:00:00Z"
		}`,
		"raw contact added to grant": `{
			"schema":"asb.human-reachability-grant/v1",
			"grant_id":"reachability-grant:1",
			"candidate_id":"candidate:pairwise:1",
			"requester_participant_id":"agent:requester",
			"purpose":"task-consultation",
			"capability":"translation",
			"channel":"EMAIL",
			"relay_session_ref":"https://relay.example/sessions/opaque-1",
			"issued_at":"2026-08-12T12:01:00Z",
			"expires_at":"2026-08-12T12:30:00Z",
			"email":"person@example.com"
		}`,
		"invalid date-time": `{
			"schema":"asb.human-reachability-grant/v1",
			"grant_id":"reachability-grant:1",
			"candidate_id":"candidate:pairwise:1",
			"requester_participant_id":"agent:requester",
			"purpose":"task-consultation",
			"capability":"translation",
			"channel":"EMAIL",
			"relay_session_ref":"https://relay.example/sessions/opaque-1",
			"issued_at":"not-a-date",
			"expires_at":"2026-08-12T12:30:00Z"
		}`,
	}

	for name, document := range tests {
		document := document
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			instance, err := jsonschema.UnmarshalJSON(strings.NewReader(document))
			if err != nil {
				t.Fatalf("invalid test fixture JSON: %v", err)
			}
			if err := schema.Validate(instance); err == nil {
				t.Fatal("invalid document was accepted")
			}
		})
	}
}

func compileTaskParticipantSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	schema, err := compiler.Compile(taskParticipantSchemaFile)
	if err != nil {
		t.Fatalf("compile Draft 2020-12 schema: %v", err)
	}
	return schema
}

func validateDocument(schema *jsonschema.Schema, document any) error {
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	return schema.Validate(instance)
}
