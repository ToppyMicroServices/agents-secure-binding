// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const responseRequestID = "asbreq-0123456789abcdef0123456789abcdef"

func TestHumanIngressResponseSchemaCompilesStandalone(t *testing.T) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(humanIngressResponseSchemaBytes))
	if err != nil {
		t.Fatalf("decode response schema: %v", err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	if err := compiler.AddResource(humanIngressResponseSchemaURL, document); err != nil {
		t.Fatalf("add response schema: %v", err)
	}
	if _, err := compiler.Compile(humanIngressResponseSchemaURL); err != nil {
		t.Fatalf("compile response schema without external resources: %v", err)
	}
}

func TestHumanIngressResponseSchemaAcceptsSuccessBodies(t *testing.T) {
	record := validIngressTransition("event:offer:1", "assignment:1", "task:1")
	assignment := validIngressAssignment("assignment:1", "task:1", record)

	tests := map[string]any{
		"challenge": map[string]any{
			"challenge_id":   ingressHex("a"),
			"nonce":          ingressHex("b"),
			"expires_at":     "2026-09-01T12:05:00Z",
			"request_digest": ingressHex("c"),
		},
		"offer": map[string]any{
			"operation":  "ASSIGNMENT_OFFER",
			"assignment": assignment,
			"record":     record,
		},
		"transition": map[string]any{
			"operation":  "ASSIGNMENT_TRANSITION",
			"assignment": assignment,
			"record":     record,
		},
		"delegation": map[string]any{
			"operation":         "ASSIGNMENT_DELEGATION",
			"parent_assignment": assignment,
			"parent_record":     record,
			"child_assignment":  assignment,
			"child_record":      record,
			"delegation":        validHumanIngressDelegation(),
		},
		"interaction": map[string]any{
			"operation": "INTERACTION_APPEND",
			"interaction": map[string]any{
				"schema":           "asb.task-interaction-event/v1",
				"event_id":         "event:question:1",
				"interaction_id":   "interaction:1",
				"task_id":          "task:1",
				"assignment_id":    "assignment:1",
				"kind":             "QUESTION",
				"content_ref":      "urn:content:question:1",
				"content_digest":   ingressHex("f"),
				"at":               "2026-09-01T12:00:00Z",
				"actor_id":         "service:human-gateway",
				"participant_id":   "human:alice",
				"authorization_id": "authorization:1",
				"proof_id":         "proof:1",
				"assurance":        validHumanIngressAssurance(),
			},
		},
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			raw := marshalIngressResponse(t, body)
			if err := ValidateHumanIngressResponseJSON(raw); err != nil {
				t.Fatalf("valid response rejected: %v\n%s", err, raw)
			}
		})
	}
}

func TestHumanIngressResponseSchemaRequiresVerifierDerivedDelegationAssurance(t *testing.T) {
	record := validIngressTransition("event:offer:1", "assignment:1", "task:1")
	assignment := validIngressAssignment("assignment:1", "task:1", record)
	delegation := validHumanIngressDelegation()
	body := map[string]any{
		"operation":         "ASSIGNMENT_DELEGATION",
		"parent_assignment": assignment,
		"parent_record":     record,
		"child_assignment":  assignment,
		"child_record":      record,
		"delegation":        delegation,
	}
	if err := ValidateHumanIngressResponseJSON(marshalIngressResponse(t, body)); err != nil {
		t.Fatalf("valid delegation response rejected: %v", err)
	}

	delete(delegation, "assurance")
	if err := ValidateHumanIngressResponseJSON(marshalIngressResponse(t, body)); err == nil {
		t.Fatal("Human delegation response without assurance was accepted")
	}
	delegation["assurance"] = map[string]any{
		"profile_id":      "asb.taskcoord-human-request/v1",
		"assurance_level": "human-held-key-exact-request",
	}
	if err := ValidateHumanIngressResponseJSON(marshalIngressResponse(t, body)); err == nil {
		t.Fatal("Human delegation response with elevated assurance was accepted")
	}
}

func TestHumanIngressResponseSchemaAcceptsExactPublicErrors(t *testing.T) {
	tests := []struct {
		code      string
		message   string
		retryable bool
	}{
		{"INVALID_REQUEST", "request is invalid", false},
		{"UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json", false},
		{"AUTHENTICATION_REQUIRED", "authenticated TLS client is required", false},
		{"CHALLENGE_REJECTED", "challenge is invalid or unavailable", false},
		{"OPERATION_REJECTED", "operation is not authorized", false},
		{"NOT_FOUND", "resource was not found", false},
		{"STATE_CONFLICT", "operation conflicts with current state", false},
		{"METHOD_NOT_ALLOWED", "method is not allowed", false},
		{"RATE_LIMITED", "too many outstanding challenges", true},
		{"OPERATION_OUTCOME_UNKNOWN", "operation outcome is unknown", false},
		{"INTERNAL_ERROR", "internal service error", false},
	}

	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			raw := marshalIngressResponse(t, map[string]any{
				"error":      test.message,
				"code":       test.code,
				"retryable":  test.retryable,
				"request_id": responseRequestID,
			})
			if err := ValidateHumanIngressResponseJSON(raw); err != nil {
				t.Fatalf("valid public error rejected: %v", err)
			}
		})
	}
}

func TestHumanIngressResponseSchemaRejectsInvalidBodies(t *testing.T) {
	tests := map[string]string{
		"mismatched public message": `{"error":"internal service error","code":"INVALID_REQUEST","retryable":false,"request_id":"` + responseRequestID + `"}`,
		"mismatched retryability":   `{"error":"too many outstanding challenges","code":"RATE_LIMITED","retryable":false,"request_id":"` + responseRequestID + `"}`,
		"uppercase request id":      `{"error":"request is invalid","code":"INVALID_REQUEST","retryable":false,"request_id":"asbreq-0123456789ABCDEF0123456789ABCDEF"}`,
		"missing request id":        `{"error":"request is invalid","code":"INVALID_REQUEST","retryable":false}`,
		"unknown error field":       `{"error":"request is invalid","code":"INVALID_REQUEST","retryable":false,"request_id":"` + responseRequestID + `","detail":"backend leaked"}`,
		"wrong execute shape":       `{"operation":"INTERACTION_APPEND","assignment":{}}`,
		"unknown success field":     `{"challenge_id":"` + ingressHex("a") + `","nonce":"` + ingressHex("b") + `","expires_at":"2026-09-01T12:05:00Z","request_digest":"` + ingressHex("c") + `","request_id":"` + responseRequestID + `"}`,
		"trailing document":         `{"error":"request is invalid","code":"INVALID_REQUEST","retryable":false,"request_id":"` + responseRequestID + `"} {}`,
		"missing Human assurance":   `{"operation":"INTERACTION_APPEND","interaction":{"schema":"asb.task-interaction-event/v1","event_id":"event:question:1","interaction_id":"interaction:1","task_id":"task:1","assignment_id":"assignment:1","kind":"QUESTION","content_ref":"urn:content:question:1","content_digest":"` + ingressHex("f") + `","at":"2026-09-01T12:00:00Z","actor_id":"service:human-gateway","participant_id":"human:alice","authorization_id":"authorization:1","proof_id":"proof:1"}}`,
		"elevated Human assurance":  `{"operation":"INTERACTION_APPEND","interaction":{"schema":"asb.task-interaction-event/v1","event_id":"event:question:1","interaction_id":"interaction:1","task_id":"task:1","assignment_id":"assignment:1","kind":"QUESTION","content_ref":"urn:content:question:1","content_digest":"` + ingressHex("f") + `","at":"2026-09-01T12:00:00Z","actor_id":"service:human-gateway","participant_id":"human:alice","authorization_id":"authorization:1","proof_id":"proof:1","assurance":{"profile_id":"asb.taskcoord-human-request/v1","assurance_level":"human-held-key-exact-request"}}}`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateHumanIngressResponseJSON([]byte(raw)); err == nil {
				t.Fatalf("invalid response accepted: %s", raw)
			}
		})
	}
}

func TestHumanIngressErrorResponsePreservesStringErrorDecoder(t *testing.T) {
	raw := []byte(`{"error":"request is invalid","code":"INVALID_REQUEST","retryable":false,"request_id":"` + responseRequestID + `"}`)
	var legacy struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("legacy error decoder failed: %v", err)
	}
	if legacy.Error != "request is invalid" {
		t.Fatalf("legacy error = %q", legacy.Error)
	}
}

func validIngressTransition(eventID, assignmentID, taskID string) map[string]any {
	return map[string]any{
		"event_id":         eventID,
		"assignment_id":    assignmentID,
		"task_id":          taskID,
		"revision":         1,
		"kind":             "OFFER",
		"to":               "OFFERED",
		"reason":           map[string]any{"code": "OFFER"},
		"at":               "2026-09-01T12:00:00Z",
		"actor_id":         "human:alice",
		"participant_id":   "human:alice",
		"authorization_id": "authorization:1",
		"proof_id":         "proof:1",
		"assurance":        validHumanIngressAssurance(),
	}
}

func validHumanIngressAssurance() map[string]any {
	return map[string]any{
		"profile_id":      "asb.taskcoord-human-request/v1",
		"assurance_level": "gateway-asserted-for-human",
	}
}

func validHumanIngressDelegation() map[string]any {
	return map[string]any{
		"event_id":                "event:delegation:1",
		"decision_id":             "decision:1",
		"parent_assignment_id":    "assignment:parent",
		"child_assignment_id":     "assignment:child",
		"parent_task_id":          "task:parent",
		"child_task_id":           "task:child",
		"from_participant_id":     "human:alice",
		"to_participant_id":       "agent:reviewer",
		"parent_authority_digest": ingressHex("d"),
		"child_authority_digest":  ingressHex("e"),
		"policy_ref":              "urn:policy:delegation:1",
		"evidence_ref":            "urn:evidence:delegation:1",
		"at":                      "2026-09-01T12:00:00Z",
		"assurance":               validHumanIngressAssurance(),
	}
}

func validIngressAssignment(assignmentID, taskID string, record map[string]any) map[string]any {
	return map[string]any{
		"schema":                    "asb.task-assignment/v1",
		"assignment_id":             assignmentID,
		"task_id":                   taskID,
		"participant_id":            "agent:reviewer",
		"offered_by_participant_id": "human:alice",
		"role":                      "REVIEWER",
		"authority_digest":          ingressHex("a"),
		"revision":                  1,
		"status":                    "OFFERED",
		"last_transition":           record,
		"created_at":                "2026-09-01T12:00:00Z",
		"updated_at":                "2026-09-01T12:00:00Z",
	}
}

func ingressHex(character string) string {
	value := ""
	for len(value) < 64 {
		value += character
	}
	return value
}

func marshalIngressResponse(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
