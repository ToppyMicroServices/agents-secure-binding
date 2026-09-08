// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
)

func TestActionLifecycleValidatorsAcceptDurableDocuments(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 15, 0, 0, 0, time.UTC)
	actionDigest := "sha256:" + strings.Repeat("a", 64)
	policy := actionlifecycle.RecoveryPolicy{
		Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
		IdempotencyKey: "idempotency:action:1",
	}
	action, err := actionlifecycle.NewSnapshot(schemaAcceptanceDefinition(t,
		"event:accept:1", "action:1", actionDigest, "human:owner", policy, at,
	))
	if err != nil {
		t.Fatal(err)
	}
	startAt := at.Add(time.Second)
	startEvent := actionlifecycle.Event{
		ID: "event:start:1", Kind: actionlifecycle.EventStart,
		ExpectedRevision: action.Snapshot.Revision, At: startAt,
		Reason: actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted},
		Lease: &actionlifecycle.ExecutorLease{
			LeaseID: "lease:1", ExecutorID: "agent:executor", Generation: 1,
			IssuedAt: startAt, ExpiresAt: startAt.Add(10 * time.Minute),
		},
		Auth: &actionlifecycle.AuthenticatedOperation{
			ActorID: "agent:executor", AuthorizationID: "authorization:start:1",
			ProofID: "proof:start:1", Operation: actionlifecycle.EventStart,
			ActionID: action.Snapshot.ActionID, ActionDigest: action.Snapshot.ActionDigest,
			VerifierNonce: "nonce:start:1", IssuedAt: startAt.Add(-time.Second),
			ExpiresAt: startAt.Add(15 * time.Minute),
		},
	}
	startDigest, err := actionlifecycle.MutationRequestDigest(startEvent)
	if err != nil {
		t.Fatal(err)
	}
	startEvent.Auth.MutationDigest = startDigest
	started, err := actionlifecycle.Apply(action.Snapshot, startEvent)
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
		{name: "authenticated Action snapshot", document: started.Snapshot, validate: ValidateActionLifecycleJSON},
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

func TestActionLifecycleSchemaRequiresMutationDigestOnlyForAuthenticatedTransitions(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 14, 16, 0, 0, 0, time.UTC)
	actionDigest := "sha256:" + strings.Repeat("c", 64)
	policy := actionlifecycle.RecoveryPolicy{
		Mode: actionlifecycle.RecoveryRestartIdempotent, MaxAttempts: 1,
		IdempotencyKey: "idempotency:digest",
	}
	accepted, err := actionlifecycle.NewSnapshot(schemaAcceptanceDefinition(t,
		"event:accept:digest", "action:digest", actionDigest, "agent:owner", policy, at,
	))
	if err != nil {
		t.Fatal(err)
	}
	acceptedRaw, err := json.Marshal(accepted.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var acceptedDocument map[string]any
	if err := json.Unmarshal(acceptedRaw, &acceptedDocument); err != nil {
		t.Fatal(err)
	}
	acceptedTransition := acceptedDocument["last_transition"].(map[string]any)
	delete(acceptedTransition, "mutation_digest")
	invalidAccepted, err := json.Marshal(acceptedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateActionLifecycleJSON(invalidAccepted); err == nil {
		t.Fatal("authenticated ACCEPT transition without mutation_digest accepted")
	}
	acceptedTransition["mutation_digest"] = accepted.Record.MutationDigest
	delete(acceptedTransition, "acceptance_context_digest")
	missingContext, err := json.Marshal(acceptedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateActionLifecycleJSON(missingContext); err == nil {
		t.Fatal("authenticated ACCEPT transition without acceptance_context_digest accepted")
	}

	startAt := at.Add(time.Second)
	startEvent := actionlifecycle.Event{
		ID: "event:start:digest", Kind: actionlifecycle.EventStart,
		ExpectedRevision: accepted.Snapshot.Revision, At: startAt,
		Reason: actionlifecycle.Reason{Code: actionlifecycle.ReasonStarted},
		Lease: &actionlifecycle.ExecutorLease{
			LeaseID: "lease:digest", ExecutorID: "agent:executor", Generation: 1,
			IssuedAt: startAt, ExpiresAt: startAt.Add(10 * time.Minute),
		},
		Auth: &actionlifecycle.AuthenticatedOperation{
			ActorID: "agent:executor", AuthorizationID: "authorization:start:digest",
			ProofID: "proof:start:digest", Operation: actionlifecycle.EventStart,
			ActionID: accepted.Snapshot.ActionID, ActionDigest: accepted.Snapshot.ActionDigest,
			VerifierNonce: "nonce:start:digest", IssuedAt: startAt.Add(-time.Second),
			ExpiresAt: startAt.Add(15 * time.Minute),
		},
	}
	digest, err := actionlifecycle.MutationRequestDigest(startEvent)
	if err != nil {
		t.Fatal(err)
	}
	startEvent.Auth.MutationDigest = digest
	started, err := actionlifecycle.Apply(accepted.Snapshot, startEvent)
	if err != nil {
		t.Fatal(err)
	}
	startedRaw, err := json.Marshal(started.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var startedDocument map[string]any
	if err := json.Unmarshal(startedRaw, &startedDocument); err != nil {
		t.Fatal(err)
	}
	startedTransition := startedDocument["last_transition"].(map[string]any)
	delete(startedTransition, "actor_id")
	missingActor, err := json.Marshal(startedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateActionLifecycleJSON(missingActor); err == nil {
		t.Fatal("authenticated transition without actor_id accepted")
	}
	startedTransition["actor_id"] = started.Record.ActorID
	delete(startedTransition, "mutation_digest")
	invalidStarted, err := json.Marshal(startedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateActionLifecycleJSON(invalidStarted); err == nil {
		t.Fatal("authenticated transition without mutation_digest accepted")
	}
}

func schemaAcceptanceDefinition(
	t *testing.T,
	eventID string,
	actionID string,
	actionDigest string,
	ownerID string,
	policy actionlifecycle.RecoveryPolicy,
	at time.Time,
) actionlifecycle.Definition {
	t.Helper()
	definition := actionlifecycle.Definition{
		EventID: eventID, ActionID: actionID, ActionDigest: actionDigest, OwnerID: ownerID,
		RecoveryPolicy: policy, AcceptanceContextDigest: "sha256:" + strings.Repeat("e", 64), AcceptedAt: at,
	}
	definition.Auth = &actionlifecycle.AuthenticatedOperation{
		ActorID: "agent:acceptor", AuthorizationID: "authorization:accept:" + actionID,
		ProofID: "proof:accept:" + actionID, Operation: actionlifecycle.EventAccept,
		ActionID: actionID, ActionDigest: actionDigest,
		VerifierNonce: "nonce:accept:" + actionID,
		IssuedAt:      at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
	}
	digest, err := actionlifecycle.AcceptanceRequestDigest(definition)
	if err != nil {
		t.Fatal(err)
	}
	definition.Auth.MutationDigest = digest
	return definition
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
