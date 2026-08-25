// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"time"
)

const (
	LayerD3 = "D3"
	LayerD4 = "D4"
	LayerD5 = "D5"
	LayerD6 = "D6"
	LayerD7 = "D7"

	FieldEndpointRole             = "endpoint_role"
	FieldInteractionType          = "interaction_type"
	FieldAcceptedEndpointSPKIHash = "accepted_endpoint_spki_sha256"
	FieldBindingContextHash       = "binding_context_sha256"
	FieldVerifierNonce            = "verifier_nonce"
	FieldAttemptID                = "attempt_id"
	FieldTargetResource           = "target_resource"
	FieldTargetOperation          = "target_operation"
	FieldCreatorIsolatedKey       = "creator_isolated_key"
)

var ErrCreatorIsolationUnverified = errors.New("identitypolicy: creator isolation is not verified")

// RequirementsV2 selects the verifier-local policy dimensions that must be
// checked for a draft-06 v2 assertion.
type RequirementsV2 struct {
	D3 bool `json:"d3" yaml:"d3"`
	D4 bool `json:"d4" yaml:"d4"`
	D5 bool `json:"d5" yaml:"d5"`
	D6 bool `json:"d6" yaml:"d6"`
	D7 bool `json:"d7" yaml:"d7"`
}

// Enabled reports whether at least one D3-D7 dimension is required.
func (r RequirementsV2) Enabled() bool {
	return r.D3 || r.D4 || r.D5 || r.D6 || r.D7
}

// TargetV2 is the D6 target identity. It is deliberately separate from the
// D7 resource authorization set.
type TargetV2 struct {
	Resource  string `json:"resource,omitempty" yaml:"resource,omitempty"`
	Operation string `json:"operation,omitempty" yaml:"operation,omitempty"`
}

// AuthorizationV2 contains only D7 authorization values.
type AuthorizationV2 struct {
	CapabilityRef        string   `json:"capability_ref,omitempty" yaml:"capability_ref,omitempty"`
	OntologyID           string   `json:"ontology_id,omitempty" yaml:"ontology_id,omitempty"`
	Scopes               []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Resources            []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty" yaml:"authorization_details,omitempty"`
}

// PolicyV2 separates verifier-local expectations from authenticated observed
// values. D6 and D7 are represented independently by ExpectedTarget and
// ExpectedAuthorization. Accepted channel values are supplied separately to
// ValidateAssertionV2 so there is only one local source for binding state.
type PolicyV2 struct {
	Mode                      Mode            `json:"mode,omitempty" yaml:"mode,omitempty"`
	SetMode                   SetMode         `json:"set_mode,omitempty" yaml:"set_mode,omitempty"`
	Require                   RequirementsV2  `json:"require" yaml:"require"`
	Expected                  Values          `json:"expected" yaml:"expected"`
	ExpectedTarget            TargetV2        `json:"expected_target" yaml:"expected_target"`
	ExpectedAuthorization     AuthorizationV2 `json:"expected_authorization" yaml:"expected_authorization"`
	RequireCreatorIsolatedKey bool            `json:"require_creator_isolated_key,omitempty" yaml:"require_creator_isolated_key,omitempty"`
}

// Enabled reports whether this v2 policy should be enforced.
func (p PolicyV2) Enabled() bool {
	switch p.Mode {
	case ModeDisabled:
		return false
	case ModeRequired:
		return true
	case ModeDefault:
	default:
		return false
	}
	return p.Require.Enabled() || p.RequireCreatorIsolatedKey
}

// ValidateMode checks whether the v2 policy uses supported modes.
func (p PolicyV2) ValidateMode() error {
	switch p.Mode {
	case ModeDefault, ModeDisabled, ModeRequired:
	default:
		return ErrInvalidMode
	}
	switch p.SetMode {
	case SetModeDefault, SetModeContainsAll, SetModeExact:
	default:
		return ErrInvalidMode
	}
	return nil
}

// ValidateAssertionV2 validates the accepted binding and the D3-D7 observed
// values against verifier-local policy. AssertionV2 must first be constructed
// from authenticated material with NewAssertionFromSessionBindingV2.
func ValidateAssertionV2(policy PolicyV2, assertion AssertionV2, expectedBinding BindingV2, now time.Time) error {
	var errs ValidationErrors
	if err := policy.ValidateMode(); err != nil {
		errs = append(errs, validationError("policy", "mode", err))
	}
	if policy.Mode == ModeRequired && !policy.Require.Enabled() && !policy.RequireCreatorIsolatedKey {
		errs = append(errs, validationError("policy", FieldAll, ErrMissingExpected))
	}
	if err := ValidateAcceptedBindingV2(assertion.Binding, expectedBinding, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}

	if policy.Require.D3 {
		if err := validateExactLayerV2(LayerD3, policy.Expected, assertion.ObservedValues, []field{
			{FieldService, func(v Values) string { return v.Service }},
			{FieldTenant, func(v Values) string { return v.Tenant }},
			{FieldDeployment, func(v Values) string { return v.Deployment }},
			{FieldEnvironment, func(v Values) string { return v.Environment }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if policy.Require.D4 {
		if err := validateExactLayerV2(LayerD4, policy.Expected, assertion.ObservedValues, []field{
			{FieldWorkload, func(v Values) string { return v.Workload }},
			{FieldAgent, func(v Values) string { return v.Agent }},
			{FieldAgentPublicKey, func(v Values) string { return v.AgentPublicKey }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if policy.RequireCreatorIsolatedKey {
		// V2 carries no authenticated creator-isolation result. A key ID and
		// holder-of-key proof alone cannot establish this property.
		errs = append(errs, validationError(LayerD4, FieldCreatorIsolatedKey, ErrCreatorIsolationUnverified))
	}
	if policy.Require.D5 {
		if err := validateExactLayerV2(LayerD5, policy.Expected, assertion.ObservedValues, []field{
			{FieldComputationID, func(v Values) string { return v.ComputationID }},
			{FieldTaskID, func(v Values) string { return v.TaskID }},
			{FieldThreadID, func(v Values) string { return v.ThreadID }},
			{FieldDelegationID, func(v Values) string { return v.DelegationID }},
			{FieldIntentRef, func(v Values) string { return v.IntentRef }},
		}); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if policy.Require.D6 {
		if err := validateTargetV2(policy.ExpectedTarget, assertion.Target); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if policy.Require.D7 {
		if err := validateAuthorizationV2(policy.ExpectedAuthorization, assertion.ObservedAuthorization, policy.setMode()); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// EffectiveAuthorization returns the locally bounded D7 authorization after
// verifying that the authenticated grant authorization satisfies the local
// policy. Surplus observed authorization is never returned and therefore
// cannot expand the application's effective authorization.
func EffectiveAuthorization(policy PolicyV2, assertion AssertionV2) (AuthorizationV2, error) {
	if err := policy.ValidateMode(); err != nil {
		return AuthorizationV2{}, validationError("policy", "mode", err)
	}
	if !policy.Enabled() {
		return AuthorizationV2{}, validationError(LayerD7, FieldAll, ErrMissingExpected)
	}
	if !policy.Require.D7 {
		return AuthorizationV2{}, nil
	}
	if err := validateAuthorizationV2(policy.ExpectedAuthorization, assertion.ObservedAuthorization, policy.setMode()); err != nil {
		return AuthorizationV2{}, err
	}
	return AuthorizationV2{
		CapabilityRef:        policy.ExpectedAuthorization.CapabilityRef,
		OntologyID:           policy.ExpectedAuthorization.OntologyID,
		Scopes:               uniqueNonEmpty(policy.ExpectedAuthorization.Scopes),
		Resources:            uniqueNonEmpty(policy.ExpectedAuthorization.Resources),
		AuthorizationDetails: uniqueNonEmpty(policy.ExpectedAuthorization.AuthorizationDetails),
	}, nil
}

func (p PolicyV2) setMode() SetMode {
	if p.SetMode == SetModeDefault {
		return SetModeExact
	}
	return p.SetMode
}

func validateTargetV2(expected, observed TargetV2) error {
	var errs ValidationErrors
	hasExpected := false
	for _, item := range []struct {
		field string
		want  string
		got   string
	}{
		{FieldTargetResource, expected.Resource, observed.Resource},
		{FieldTargetOperation, expected.Operation, observed.Operation},
	} {
		if isEmpty(item.want) {
			continue
		}
		hasExpected = true
		if err := validateDecisionValueV2(item.want); err != nil {
			errs = append(errs, validationError(LayerD6, item.field, err))
			continue
		}
		if isEmpty(item.got) {
			errs = append(errs, validationError(LayerD6, item.field, ErrMissingObserved))
			continue
		}
		if err := validateDecisionValueV2(item.got); err != nil {
			errs = append(errs, validationError(LayerD6, item.field, err))
			continue
		}
		if item.got != item.want {
			errs = append(errs, validationError(LayerD6, item.field, ErrMismatch))
		}
	}
	if !hasExpected {
		errs = append(errs, validationError(LayerD6, FieldAll, ErrMissingExpected))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateAuthorizationV2(expected, observed AuthorizationV2, setMode SetMode) error {
	var errs ValidationErrors
	hasExpected := false
	for _, item := range []struct {
		field string
		want  string
		got   string
	}{
		{FieldCapabilityRef, expected.CapabilityRef, observed.CapabilityRef},
		{FieldOntologyID, expected.OntologyID, observed.OntologyID},
	} {
		if isEmpty(item.want) {
			continue
		}
		hasExpected = true
		if err := validateDecisionValueV2(item.want); err != nil {
			errs = append(errs, validationError(LayerD7, item.field, err))
			continue
		}
		if err := validateReferenceValue(item.want); err != nil {
			errs = append(errs, validationError(LayerD7, item.field, err))
			continue
		}
		if isEmpty(item.got) {
			errs = append(errs, validationError(LayerD7, item.field, ErrMissingObserved))
			continue
		}
		if err := validateDecisionValueV2(item.got); err != nil {
			errs = append(errs, validationError(LayerD7, item.field, err))
			continue
		}
		if err := validateReferenceValue(item.got); err != nil {
			errs = append(errs, validationError(LayerD7, item.field, err))
			continue
		}
		if item.got != item.want {
			errs = append(errs, validationError(LayerD7, item.field, ErrMismatch))
		}
	}
	for _, item := range []struct {
		field string
		want  []string
		got   []string
	}{
		{FieldScopes, expected.Scopes, observed.Scopes},
		{FieldResources, expected.Resources, observed.Resources},
		{FieldAuthorizationDetails, expected.AuthorizationDetails, observed.AuthorizationDetails},
	} {
		if len(item.want) == 0 {
			continue
		}
		hasExpected = true
		for _, value := range append(append([]string(nil), item.want...), item.got...) {
			if isEmpty(value) {
				continue
			}
			if err := validateDecisionValueV2(value); err != nil {
				errs = append(errs, validationError(LayerD7, item.field, err))
			}
		}
		if err := validateSet(LayerD7, item.field, item.want, item.got, setMode); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if !hasExpected {
		errs = append(errs, validationError(LayerD7, FieldAll, ErrMissingExpected))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateExactLayerV2(layer string, expected, observed Values, fields []field) error {
	var errs ValidationErrors
	for _, f := range fields {
		want := f.get(expected)
		if isEmpty(want) {
			continue
		}
		if err := validateDecisionValueV2(want); err != nil {
			errs = append(errs, validationError(layer, f.name, err))
		}
		got := f.get(observed)
		if !isEmpty(got) {
			if err := validateDecisionValueV2(got); err != nil {
				errs = append(errs, validationError(layer, f.name, err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return validateExactLayer(layer, expected, observed, fields)
}

func acceptedValuesV2(policy PolicyV2) Values {
	var accepted Values
	if policy.Require.D3 {
		accepted.Service = policy.Expected.Service
		accepted.Tenant = policy.Expected.Tenant
		accepted.Deployment = policy.Expected.Deployment
		accepted.Environment = policy.Expected.Environment
	}
	if policy.Require.D4 {
		accepted.Workload = policy.Expected.Workload
		accepted.Agent = policy.Expected.Agent
		accepted.AgentPublicKey = policy.Expected.AgentPublicKey
	}
	if policy.Require.D5 {
		accepted.ComputationID = policy.Expected.ComputationID
		accepted.TaskID = policy.Expected.TaskID
		accepted.ThreadID = policy.Expected.ThreadID
		accepted.DelegationID = policy.Expected.DelegationID
		accepted.IntentRef = policy.Expected.IntentRef
	}
	return accepted
}

func uniqueNonEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if isEmpty(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
