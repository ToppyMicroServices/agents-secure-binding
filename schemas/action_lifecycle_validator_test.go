// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord/actionbinding"
)

func TestActionLifecycleValidatorsAcceptDurableDocuments(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 15, 0, 0, 0, time.UTC)
	action, err := actionlifecycle.NewSnapshot(actionlifecycle.Definition{
		EventID: "event:accept:1", ActionID: "action:1",
		ActionDigest: "sha256:" + strings.Repeat("a", 64), OwnerID: "human:owner",
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
			IdempotencyKey: "idempotency:action:1",
		},
		AcceptedAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := actionbinding.Binding{
		Schema: actionbinding.BindingSchemaV1, TaskID: "task:1", AssignmentID: "assignment:1",
		ActionID: "action:1", CreatedAt: at,
	}
	wait := actionbinding.DependencyWait{
		Schema: actionbinding.DependencyWaitSchemaV1, TaskID: "task:1", ActionID: "action:1",
		ActionRevision: 3, DependencyIDs: []string{"dependency:1"},
		DependencySetDigest: "sha256:" + strings.Repeat("b", 64), CreatedAt: at.Add(time.Minute),
	}

	tests := []struct {
		name     string
		document any
		validate func([]byte) error
	}{
		{name: "Action snapshot", document: action.Snapshot, validate: ValidateActionLifecycleJSON},
		{name: "Task Action binding", document: binding, validate: ValidateTaskActionBindingJSON},
		{name: "dependency wait", document: wait, validate: ValidateTaskActionBindingJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			raw, err := json.Marshal(test.document)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.validate(raw); err != nil {
				t.Fatalf("valid document rejected: %v", err)
			}
		})
	}
}

func TestActionLifecycleValidatorsRejectUnknownFields(t *testing.T) {
	t.Parallel()
	invalidAction := `{
		"schema":"asb.action-lifecycle/v1",
		"action_id":"action:1",
		"unexpected":true
	}`
	if err := ValidateActionLifecycleJSON([]byte(invalidAction)); err == nil {
		t.Fatal("invalid Action snapshot accepted")
	}
	invalidBinding := `{
		"schema":"asb.task-action-binding/v1",
		"task_id":"task:1",
		"assignment_id":"assignment:1",
		"action_id":"action:1",
		"created_at":"2026-08-14T15:00:00Z",
		"participant_id":"human:owner"
	}`
	if err := ValidateTaskActionBindingJSON([]byte(invalidBinding)); err == nil {
		t.Fatal("identity duplication accepted")
	}
}
