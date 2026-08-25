// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestPolicyV2SeparatesD6TargetFromD7Authorization(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
	}

	policy := PolicyV2{
		SetMode: SetModeContainsAll,
		Require: RequirementsV2{D6: true, D7: true},
		ExpectedTarget: TargetV2{
			Resource:  "document-api",
			Operation: "summarize",
		},
		ExpectedAuthorization: AuthorizationV2{
			CapabilityRef:        "cap:summarize",
			OntologyID:           "ontology:documents",
			Scopes:               []string{"document:read"},
			Resources:            []string{"document-records"},
			AuthorizationDetails: []string{"summarize"},
		},
	}
	if err := ValidateAssertionV2(policy, assertion, statement.Binding, now); err != nil {
		t.Fatalf("ValidateAssertionV2() error = %v", err)
	}

	effective, err := EffectiveAuthorization(policy, assertion)
	if err != nil {
		t.Fatalf("EffectiveAuthorization() error = %v", err)
	}
	if !reflect.DeepEqual(effective, policy.ExpectedAuthorization) {
		t.Fatalf("EffectiveAuthorization() = %#v, want locally bounded %#v", effective, policy.ExpectedAuthorization)
	}
	if reflect.DeepEqual(effective, assertion.ObservedAuthorization) {
		t.Fatal("EffectiveAuthorization() retained surplus observed grant authorization")
	}

	wrongTarget := assertion
	wrongTarget.Target.Resource = "audit-log"
	err = ValidateAssertionV2(policy, wrongTarget, statement.Binding, now)
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("ValidateAssertionV2() target error = %v, want %v", err, ErrMismatch)
	}
	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) || !validationErrs.Has(LayerD6, FieldTargetResource, ErrMismatch) {
		t.Fatalf("ValidateAssertionV2() errors do not include D6 target mismatch: %v", err)
	}
}

func TestPolicyV2RejectsPeerOnlyD3Expectation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
	}
	policy := PolicyV2{Require: RequirementsV2{D3: true}}

	err = ValidateAssertionV2(policy, assertion, statement.Binding, now)
	if !errors.Is(err, ErrMissingExpected) {
		t.Fatalf("ValidateAssertionV2() error = %v, want %v", err, ErrMissingExpected)
	}
	var validationErrs ValidationErrors
	if !errors.As(err, &validationErrs) || !validationErrs.Has(LayerD3, FieldAll, ErrMissingExpected) {
		t.Fatalf("ValidateAssertionV2() errors do not include D3 missing local expectation: %v", err)
	}
}

func TestPolicyV2CreatorIsolationFailsClosedWithoutEvidence(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
	}
	policy := PolicyV2{
		Require:                   RequirementsV2{D4: true},
		Expected:                  Values{Agent: "agent-a"},
		RequireCreatorIsolatedKey: true,
	}

	err = ValidateAssertionV2(policy, assertion, statement.Binding, now)
	if !errors.Is(err, ErrCreatorIsolationUnverified) {
		t.Fatalf("ValidateAssertionV2() error = %v, want %v", err, ErrCreatorIsolationUnverified)
	}
}

func TestEffectiveAuthorizationReturnsEmptyWhenD7NotRequired(t *testing.T) {
	policy := PolicyV2{
		Require:  RequirementsV2{D3: true},
		Expected: Values{Service: "document-service"},
	}
	assertion := AssertionV2{
		ObservedValues:        Values{Service: "document-service"},
		ObservedAuthorization: AuthorizationV2{Scopes: []string{"surplus:scope"}},
	}

	effective, err := EffectiveAuthorization(policy, assertion)
	if err != nil {
		t.Fatalf("EffectiveAuthorization() error = %v", err)
	}
	if !reflect.DeepEqual(effective, AuthorizationV2{}) {
		t.Fatalf("EffectiveAuthorization() = %#v, want empty authorization", effective)
	}
}

func TestAcceptedAssertionV2ProjectsOnlyLocalValuesAndFinalizesAfterReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
	}
	policy := PolicyV2{
		SetMode:  SetModeContainsAll,
		Require:  RequirementsV2{D3: true, D4: true, D5: true, D6: true, D7: true},
		Expected: Values{Service: "document-service", Agent: "agent-a", TaskID: "task-1"},
		ExpectedTarget: TargetV2{
			Resource:  "document-api",
			Operation: "summarize",
		},
		ExpectedAuthorization: AuthorizationV2{
			CapabilityRef: "cap:summarize",
			Scopes:        []string{"document:read"},
			Resources:     []string{"document-records"},
		},
	}

	prepared, err := PrepareAssertionV2(policy, assertion, statement.Binding, now, testAcceptanceInputsV2(now, nil))
	if err != nil {
		t.Fatalf("PrepareAssertionV2() error = %v", err)
	}
	cache := &v2RecordingReplayCache{seen: make(map[string]struct{})}
	accepted, err := CommitPreparedAssertionV2(cache, prepared, func() time.Time { return now })
	if err != nil {
		t.Fatalf("CommitPreparedAssertionV2() error = %v", err)
	}
	if accepted.AcceptedInteraction.Service != policy.Expected.Service ||
		accepted.AcceptedActor.ID != policy.Expected.Agent ||
		accepted.AcceptedInteraction.TaskID != policy.Expected.TaskID ||
		accepted.AcceptedInteraction.ThreadID != "" {
		t.Fatalf("Accepted interaction = %#v, actor = %#v", accepted.AcceptedInteraction, accepted.AcceptedActor)
	}
	if accepted.AcceptedTarget == nil || accepted.AcceptedTarget.Resource != policy.ExpectedTarget.Resource || accepted.AcceptedTarget.Operation != policy.ExpectedTarget.Operation {
		t.Fatalf("Accepted Target = %#v, want %#v", accepted.AcceptedTarget, policy.ExpectedTarget)
	}
	if !reflect.DeepEqual(accepted.EffectiveAuthorization, policy.ExpectedAuthorization) {
		t.Fatalf("EffectiveAuthorization = %#v, want %#v", accepted.EffectiveAuthorization, policy.ExpectedAuthorization)
	}
	if accepted.Scope.BindingContextSHA256 != statement.Binding.BindingContextSHA256 || accepted.Scope.Audience != assertion.Audience {
		t.Fatalf("Accepted scope = %#v", accepted.Scope)
	}
	if !accepted.Expiry.Equal(statement.Binding.ExpiresAt) {
		t.Fatalf("Accepted expiry = %v, want %v", accepted.Expiry, statement.Binding.ExpiresAt)
	}
	wantReplayRetention := testAcceptanceInputsV2(now, nil).Freshness.EvidenceChallengeExpiresAt
	if accepted.ReplayCommit.State != ReplayCommitStateCommittedV2 || !accepted.ReplayCommit.RetainUntil.Equal(wantReplayRetention) || !cache.expiresAt.Equal(wantReplayRetention) {
		t.Fatalf("Replay commit = %#v", accepted.ReplayCommit)
	}
}

func TestAcceptAssertionV2RejectsNonCanonicalLocalDecisionValue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	grant.Values.Service = "document\ufffdservice"
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(testVerifiedGrantV2(now), statement, now)
	if err != nil {
		t.Fatal(err)
	}
	assertion.ObservedValues.Service = grant.Values.Service
	policy := PolicyV2{
		Require:  RequirementsV2{D3: true, D4: true, D5: true},
		Expected: Values{Service: grant.Values.Service, Agent: "agent-a", TaskID: "task-1"},
	}

	_, err = PrepareAssertionV2(policy, assertion, statement.Binding, now, testAcceptanceInputsV2(now, nil))
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("PrepareAssertionV2() error = %v, want %v", err, ErrUnsafeValue)
	}
}

func testAcceptanceInputsV2(now time.Time, attestation *VerifiedAttestationResultV2) AcceptanceInputsV2 {
	return AcceptanceInputsV2{
		Profile: ProfileSelectionV2{
			ProfileType: "sbaip.session-binding", ProfileVersion: "2",
			BindingProfile: "draft06-v2", ProtocolID: "urn:test:a2a:v2",
		},
		Freshness: FreshnessInputsV2{
			EndpointCredentialExpiresAt: now.Add(10 * time.Minute),
			EvidenceChallengeExpiresAt:  now.Add(2 * time.Minute),
			LocalPolicyExpiresAt:        now.Add(3 * time.Minute),
		},
		AttestationResult: attestation,
	}
}
