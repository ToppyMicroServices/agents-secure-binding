// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import "testing"

func TestHumanIngressSchemaAcceptsSupportedEnvelopes(t *testing.T) {
	tests := []string{
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
	}
	for _, document := range tests {
		if err := ValidateHumanIngressJSON([]byte(document)); err != nil {
			t.Fatalf("valid Human ingress envelope rejected: %v", err)
		}
	}
}

func TestHumanIngressSchemaRejectsUnsupportedOrSensitiveFields(t *testing.T) {
	tests := []string{
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
			"operation":"ASSIGNMENT_OFFER",
			"request":{}
		}`,
	}
	for _, document := range tests {
		if err := ValidateHumanIngressJSON([]byte(document)); err == nil {
			t.Fatalf("invalid Human ingress envelope accepted: %s", document)
		}
	}
}
