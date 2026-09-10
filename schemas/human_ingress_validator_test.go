// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"testing"
)

func TestHumanIngressSchemaAcceptsSupportedEnvelopes(t *testing.T) {
	tests := []string{
		`{
			"operation":"ASSIGNMENT_OFFER",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:offer:1",
				"task_id":"task:offer:1",
				"assignment_id":"assignment:offer:1",
				"target_participant_id":"agent:reviewer",
				"role":"REVIEWER",
				"authority_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		}`,
		`{
			"operation":"ASSIGNMENT_TRANSITION",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:accept:1",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"operation":"ACCEPT",
				"expected_revision":1
			}
		}`,
		`{
			"challenge_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"operation":"INTERACTION_APPEND",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:question:1",
				"interaction_id":"interaction:1",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"kind":"QUESTION",
				"content_ref":"urn:content:1",
				"content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			"grant_jwt":"signed-grant",
			"session_binding_jwt":"signed-proof"
		}`,
		`{
			"challenge_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"operation":"ASSIGNMENT_DELEGATION",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:delegate:1",
				"parent_task_id":"task:parent:1",
				"parent_assignment_id":"assignment:parent:1",
				"expected_revision":2,
				"decision_id":"decision:1",
				"child_event_id":"event:child:1",
				"child_task_id":"task:child:1",
				"child_assignment_id":"assignment:child:1",
				"target_participant_id":"agent:reviewer",
				"role":"REVIEWER",
				"authority_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
			},
			"grant_jwt":"signed-grant",
			"session_binding_jwt":"signed-proof"
		}`,
	}
	for _, document := range tests {
		if err := ValidateHumanIngressJSON([]byte(document)); err != nil {
			t.Fatalf("valid Human ingress envelope rejected: %v", err)
		}
		var envelope map[string]any
		if err := json.Unmarshal([]byte(document), &envelope); err != nil {
			t.Fatal(err)
		}
		request, ok := envelope["request"].(map[string]any)
		if !ok {
			t.Fatal("valid test envelope has no request object")
		}
		request["assurance"] = map[string]any{
			"profile_id":      "asb.taskcoord-human-request/v1",
			"assurance_level": "gateway-asserted-for-human",
		}
		spoofed, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateHumanIngressJSON(spoofed); err == nil {
			t.Fatalf("caller assurance accepted for supported operation: %s", spoofed)
		}
	}
}

func TestHumanIngressSchemaRejectsUnsupportedOrSensitiveFields(t *testing.T) {
	tests := []string{
		`{
			"operation":"ASSIGNMENT_TRANSITION",
			"assurance_level":"human-held-key-exact-request",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:accept:assurance",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"operation":"ACCEPT",
				"expected_revision":1
			}
		}`,
		`{
			"operation":"ASSIGNMENT_TRANSITION",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:accept:assurance-object",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"operation":"ACCEPT",
				"expected_revision":1,
				"assurance":{
					"profile_id":"asb.taskcoord-human-request/v1",
					"assurance_level":"gateway-asserted-for-human"
				}
			}
		}`,
		`{
			"operation":"ASSIGNMENT_TRANSITION",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:accept:1",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"operation":"ACCEPT",
				"expected_revision":1,
				"actor_id":"self-asserted"
			}
		}`,
		`{
			"operation":"INTERACTION_APPEND",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:question:1",
				"interaction_id":"interaction:1",
				"task_id":"task:1",
				"assignment_id":"assignment:1",
				"kind":"QUESTION",
				"content_ref":"urn:content:1",
				"content_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"email":"person@example.com"
			}
		}`,
		`{
			"operation":"REACHABILITY_APPROVAL",
			"request":{}
		}`,
		`{
			"operation":"ASSIGNMENT_DELEGATION",
			"request":{
				"participant_id":"human:alice",
				"event_id":"event:delegate:1",
				"parent_task_id":"task:parent:1",
				"parent_assignment_id":"assignment:parent:1",
				"expected_revision":2,
				"decision_id":"decision:1",
				"child_event_id":"event:child:1",
				"child_task_id":"task:child:1",
				"child_assignment_id":"assignment:child:1",
				"target_participant_id":"agent:reviewer",
				"role":"REVIEWER",
				"authority_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				"verified_delegation":{"policy_ref":"client:asserted"}
			}
		}`,
	}
	for _, document := range tests {
		if err := ValidateHumanIngressJSON([]byte(document)); err == nil {
			t.Fatalf("invalid Human ingress envelope accepted: %s", document)
		}
	}
}

func TestHumanIngressRouteValidatorsRejectOppositeEnvelope(t *testing.T) {
	challenge := []byte(`{
		"operation":"ASSIGNMENT_TRANSITION",
		"request":{
			"participant_id":"human:alice",
			"event_id":"event:accept:1",
			"task_id":"task:1",
			"assignment_id":"assignment:1",
			"operation":"ACCEPT",
			"expected_revision":1
		}
	}`)
	execute := []byte(`{
		"challenge_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"operation":"ASSIGNMENT_TRANSITION",
		"request":{
			"participant_id":"human:alice",
			"event_id":"event:accept:1",
			"task_id":"task:1",
			"assignment_id":"assignment:1",
			"operation":"ACCEPT",
			"expected_revision":1
		},
		"grant_jwt":"signed-grant",
		"session_binding_jwt":"signed-proof"
	}`)

	if err := ValidateHumanIngressChallengeJSON(challenge); err != nil {
		t.Fatalf("valid challenge envelope rejected: %v", err)
	}
	if err := ValidateHumanIngressExecuteJSON(execute); err != nil {
		t.Fatalf("valid execute envelope rejected: %v", err)
	}
	if err := ValidateHumanIngressChallengeJSON(execute); err == nil {
		t.Fatal("execute envelope accepted by challenge validator")
	}
	if err := ValidateHumanIngressExecuteJSON(challenge); err == nil {
		t.Fatal("challenge envelope accepted by execute validator")
	}

	// The published request schema remains a backward-compatible union.
	if err := ValidateHumanIngressJSON(challenge); err != nil {
		t.Fatalf("combined validator rejected challenge: %v", err)
	}
	if err := ValidateHumanIngressJSON(execute); err != nil {
		t.Fatalf("combined validator rejected execute: %v", err)
	}
}
