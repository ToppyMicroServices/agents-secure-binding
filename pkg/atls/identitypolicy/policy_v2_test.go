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

func TestAcceptAssertionV2ProjectsOnlyLocalValuesAndBoundsExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	statement := testSessionBindingStatementV2(now)
	assertion, err := NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		t.Fatalf("NewAssertionFromSessionBindingV2() error = %v", err)
	}
	policy := PolicyV2{
		SetMode:  SetModeContainsAll,
		Require:  RequirementsV2{D3: true, D6: true, D7: true},
		Expected: Values{Service: "document-service"},
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

	accepted, err := AcceptAssertionV2(policy, assertion, statement.Binding, now)
	if err != nil {
		t.Fatalf("AcceptAssertionV2() error = %v", err)
	}
	if accepted.Values.Service != policy.Expected.Service || accepted.Values.Agent != "" || accepted.Values.TaskID != "" {
		t.Fatalf("Accepted Values = %#v, want only verifier-selected D3 values", accepted.Values)
	}
	if !reflect.DeepEqual(accepted.Target, policy.ExpectedTarget) {
		t.Fatalf("Accepted Target = %#v, want %#v", accepted.Target, policy.ExpectedTarget)
	}
	if !reflect.DeepEqual(accepted.EffectiveAuthorization, policy.ExpectedAuthorization) {
		t.Fatalf("EffectiveAuthorization = %#v, want %#v", accepted.EffectiveAuthorization, policy.ExpectedAuthorization)
	}
	if !accepted.ExpiresAt.Equal(statement.Binding.ExpiresAt) || !accepted.Binding.ExpiresAt.Equal(accepted.ExpiresAt) {
		t.Fatalf("Accepted expiry = %v, binding expiry = %v, want proof-bounded %v", accepted.ExpiresAt, accepted.Binding.ExpiresAt, statement.Binding.ExpiresAt)
	}
}

func TestAcceptAssertionV2RejectsNonCanonicalLocalDecisionValue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	grant := testVerifiedGrantV2(now)
	grant.Values.Service = "document\ufffdservice"
	statement := testSessionBindingStatementV2(now)
	assertion := AssertionV2{
		Issuer:             grant.Issuer,
		ObservedValues:     grant.Values,
		Binding:            statement.Binding,
		AuthorityExpiresAt: grant.ExpiresAt,
	}
	policy := PolicyV2{
		Require:  RequirementsV2{D3: true},
		Expected: Values{Service: grant.Values.Service},
	}

	_, err := AcceptAssertionV2(policy, assertion, statement.Binding, now)
	if !errors.Is(err, ErrUnsafeValue) {
		t.Fatalf("AcceptAssertionV2() error = %v, want %v", err, ErrUnsafeValue)
	}
}
