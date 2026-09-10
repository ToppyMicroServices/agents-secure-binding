// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	"strings"
	"testing"
)

const (
	validActionDocument = `{
		"schema":"asb.action-lifecycle/v1",
		"action_id":"action:1",
		"action_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"owner_id":"human:owner",
		"revision":1,
		"state":"ACCEPTED",
		"reason":{"code":"ACCEPTED"},
		"lease_generation":0,
		"recovery_policy":{"mode":"MANUAL","max_attempts":1},
		"recovery_attempts":0,
		"last_transition":{"event_id":"event:accept:1","kind":"ACCEPT","from":"","to":"ACCEPTED","reason":{"code":"ACCEPTED"},"at":"2026-09-01T00:00:00Z","actor_id":"human:owner","authorization_id":"authorization:accept:1","proof_id":"proof:accept:1","mutation_digest":"sha256:b418c48b28848631124245ff916514c4646647635ac463933702b95327225740","acceptance_context_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},
		"created_at":"2026-09-01T00:00:00Z",
		"updated_at":"2026-09-01T00:00:00Z"
	}`
	validBindingDocument = `{
		"schema":"asb.task-action-binding/v1",
		"task_id":"task:1",
		"assignment_id":"assignment:1",
		"action_id":"action:1",
		"created_at":"2026-09-01T00:00:00Z"
	}`
	validRelayDocument = `{
		"schema":"asb.human-relay-receipt/v1",
		"intent_id":"intent:1",
		"grant_id":"grant:1",
		"status":"QUEUED",
		"content_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"queued_at":"2026-09-01T00:00:00Z",
		"updated_at":"2026-09-01T00:00:00Z"
	}`
	validIngressDocument = `{
		"operation":"ASSIGNMENT_OFFER",
		"request":{
			"participant_id":"human:alice",
			"event_id":"event:offer:1",
			"task_id":"task:offer:1",
			"assignment_id":"assignment:offer:1",
			"target_participant_id":"agent:reviewer",
			"role":"REVIEWER",
			"authority_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"due_at":"2026-09-02T00:00:00Z"
		}
	}`
)

func TestNewSchemaValidatorsRejectAmbiguousAndUnboundedJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		valid     string
		duplicate string
		validate  func([]byte) error
	}{
		{
			name: "Action lifecycle", valid: validActionDocument,
			duplicate: strings.Replace(validActionDocument, `"schema":`, `"schema":"shadow","schema":`, 1),
			validate:  ValidateActionLifecycleJSON,
		},
		{
			name: "Task Action binding", valid: validBindingDocument,
			duplicate: strings.Replace(validBindingDocument, `"schema":`, `"schema":"shadow","schema":`, 1),
			validate:  ValidateTaskActionBindingJSON,
		},
		{
			name: "Human relay", valid: validRelayDocument,
			duplicate: strings.Replace(validRelayDocument, `"schema":`, `"schema":"shadow","schema":`, 1),
			validate:  ValidateHumanRelayJSON,
		},
		{
			name: "Human ingress", valid: validIngressDocument,
			duplicate: strings.Replace(validIngressDocument, `"operation":`, `"operation":"ASSIGNMENT_TRANSITION","operation":`, 1),
			validate:  ValidateHumanIngressJSON,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.validate([]byte(test.valid)); err != nil {
				t.Fatalf("valid control rejected: %v", err)
			}
			if err := test.validate([]byte(test.duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate object member") {
				t.Fatalf("duplicate member error = %v", err)
			}
			if err := test.validate([]byte(test.valid + `{}`)); err == nil || !strings.Contains(err.Error(), "trailing JSON value") {
				t.Fatalf("trailing value error = %v", err)
			}
			invalidUTF8 := []byte{'{', '"', 0xff, '"', ':', '1', '}'}
			if err := test.validate(invalidUTF8); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
				t.Fatalf("invalid UTF-8 error = %v", err)
			}
			oversized := append([]byte(test.valid), bytes.Repeat([]byte{' '}, 1<<20)...)
			if err := test.validate(oversized); err == nil || !strings.Contains(err.Error(), "exceeds 1048576 bytes") {
				t.Fatalf("oversized document error = %v", err)
			}
		})
	}
}

func TestNewSchemaValidatorsRejectEscapedAndNestedDuplicates(t *testing.T) {
	t.Parallel()
	escaped := strings.Replace(validActionDocument, `"schema":`, `"schema":"shadow","schem\u0061":`, 1)
	if err := ValidateActionLifecycleJSON([]byte(escaped)); err == nil || !strings.Contains(err.Error(), "duplicate object member") {
		t.Fatalf("escaped duplicate error = %v", err)
	}
	nested := strings.Replace(validIngressDocument, `"participant_id":`, `"participant_id":"shadow","participant_id":`, 1)
	if err := ValidateHumanIngressJSON([]byte(nested)); err == nil || !strings.Contains(err.Error(), "duplicate object member") {
		t.Fatalf("nested duplicate error = %v", err)
	}
}

func TestNewSchemaValidatorsAssertDateTimeFormats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		invalid  string
		validate func([]byte) error
	}{
		{
			name:     "Action lifecycle",
			invalid:  strings.Replace(validActionDocument, `"created_at":"2026-09-01T00:00:00Z"`, `"created_at":"not-a-date"`, 1),
			validate: ValidateActionLifecycleJSON,
		},
		{
			name:     "Task Action binding",
			invalid:  strings.Replace(validBindingDocument, `"created_at":"2026-09-01T00:00:00Z"`, `"created_at":"not-a-date"`, 1),
			validate: ValidateTaskActionBindingJSON,
		},
		{
			name:     "Human relay",
			invalid:  strings.Replace(validRelayDocument, `"queued_at":"2026-09-01T00:00:00Z"`, `"queued_at":"not-a-date"`, 1),
			validate: ValidateHumanRelayJSON,
		},
		{
			name:     "Human ingress",
			invalid:  strings.Replace(validIngressDocument, `"due_at":"2026-09-02T00:00:00Z"`, `"due_at":"not-a-date"`, 1),
			validate: ValidateHumanIngressJSON,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.validate([]byte(test.invalid)); err == nil {
				t.Fatal("invalid date-time accepted")
			}
		})
	}
}
