// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"time"
)

var (
	ErrUnauthorizedBindingKey = errors.New("identitypolicy: unauthorized session binding key")
	ErrReplayDetected         = errors.New("identitypolicy: replay detected")
	ErrReplayUnavailable      = errors.New("identitypolicy: replay state unavailable")
)

const (
	LayerIdentityGrant  = "identity_grant"
	LayerSessionBinding = "session_binding"

	FieldIssuer          = "issuer"
	FieldIssuerKey       = "issuer_key"
	FieldAudience        = "aud"
	FieldGrantHash       = "grant_hash"
	FieldSignerKey       = "signer_key"
	FieldConfirmationKey = "confirmation_key"
	FieldEndpointKey     = "authorized_endpoint_key"
)

// ReplayCache records one-shot use of a session-binding nonce.
type ReplayCache interface {
	MarkUsed(key string, expiresAt time.Time) error
}

// SessionBindingOptions carries optional validation integrations that are not
// part of the wire-token format.
type SessionBindingOptions struct {
	Now         time.Time
	ReplayCache ReplayCache
}

// VerifiedGrant is an already-authenticated identity grant.
//
// This type is not a wire-token format and does not verify signatures. Callers
// should construct it only after authenticating a deployment-specific grant
// from a trusted manager or policy authority.
type VerifiedGrant struct {
	JWTID                  string
	Issuer                 string
	IssuerKey              string
	Audience               string
	GrantHash              string
	Values                 Values
	ConfirmationKey        string
	AuthorizedEndpointKeys []string
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

// VerifiedSessionBindingStatement is an already-verified holder-of-key proof
// that binds a grant to the accepted TLS session.
//
// The signature check, statement type check, and wire-token parsing are
// deployment-specific. This helper only enforces the source-of-authority
// relationship between the verified grant, the signer key, and the session
// binding fields.
type VerifiedSessionBindingStatement struct {
	JWTID     string
	GrantHash string
	Audience  string
	SignerKey string
	Binding   Binding
}

// NewAssertionFromSessionBinding builds an Assertion from a verified grant and
// a verified session-binding statement.
func NewAssertionFromSessionBinding(grant VerifiedGrant, statement VerifiedSessionBindingStatement, now time.Time) (Assertion, error) {
	return NewAssertionFromSessionBindingWithOptions(grant, statement, SessionBindingOptions{Now: now})
}

// NewAssertionFromSessionBindingWithOptions builds an Assertion from a verified
// grant and a verified session-binding statement, with optional replay-cache
// integration for one-shot binding nonces. Use the replay-cache option only
// when this validation is the final acceptance gate; otherwise call
// MarkSessionBindingUsed after the resulting assertion passes local policy.
func NewAssertionFromSessionBindingWithOptions(grant VerifiedGrant, statement VerifiedSessionBindingStatement, opts SessionBindingOptions) (Assertion, error) {
	if err := ValidateSessionBindingStatementWithOptions(grant, statement, opts); err != nil {
		return Assertion{}, err
	}
	return Assertion{
		Issuer:  grant.Issuer,
		Values:  grant.Values,
		Binding: statement.Binding,
	}, nil
}

// ValidateSessionBindingStatement checks that the statement is authorized by
// the grant and contains the minimum session-binding fields needed before
// ValidateAssertion compares it with the accepted TLS session.
func ValidateSessionBindingStatement(grant VerifiedGrant, statement VerifiedSessionBindingStatement, now time.Time) error {
	return ValidateSessionBindingStatementWithOptions(grant, statement, SessionBindingOptions{Now: now})
}

// ValidateSessionBindingStatementWithOptions checks that the statement is
// authorized by the grant and optionally records one-shot nonce use. Use the
// replay-cache option only when this validation is the final acceptance gate.
func ValidateSessionBindingStatementWithOptions(grant VerifiedGrant, statement VerifiedSessionBindingStatement, opts SessionBindingOptions) error {
	var errs ValidationErrors

	if err := validateExpectedString(LayerIdentityGrant, FieldIssuer, grant.Issuer); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedString(LayerIdentityGrant, FieldAudience, grant.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedString(LayerIdentityGrant, FieldGrantHash, grant.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateObservedString(LayerSessionBinding, FieldGrantHash, statement.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.GrantHash != statement.GrantHash {
		errs = append(errs, validationError(LayerSessionBinding, FieldGrantHash, ErrMismatch))
	}
	if err := validateObservedString(LayerSessionBinding, FieldAudience, statement.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.Audience != statement.Audience {
		errs = append(errs, validationError(LayerSessionBinding, FieldAudience, ErrMismatch))
	}
	if err := validateObservedString(LayerSessionBinding, FieldSignerKey, statement.SignerKey); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if !grant.allowsBindingKey(statement.SignerKey) {
		errs = append(errs, validationError(LayerSessionBinding, FieldSignerKey, ErrUnauthorizedBindingKey))
	} else if grant.IssuerKey != "" && statement.SignerKey == grant.IssuerKey {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuerKey, ErrUnauthorizedBindingKey))
	}
	if !grant.hasBindingKey() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldConfirmationKey, ErrMissingExpected))
	}
	if err := validateGrantValues(grant.Values); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateAuthorizedEndpointKeys(grant.AuthorizedEndpointKeys); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateGrantLifetime(grant, opts.Now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateStatementBinding(statement.Binding, opts.Now); err != nil {
		errs = appendValidationErrors(errs, err)
	}

	if len(errs) > 0 {
		return errs
	}
	if err := MarkSessionBindingUsed(opts.ReplayCache, statement); err != nil {
		return err
	}
	return nil
}

func validateGrantValues(values Values) error {
	var errs ValidationErrors
	for _, f := range []field{
		{FieldService, func(v Values) string { return v.Service }},
		{FieldTenant, func(v Values) string { return v.Tenant }},
		{FieldDeployment, func(v Values) string { return v.Deployment }},
		{FieldEnvironment, func(v Values) string { return v.Environment }},
		{FieldWorkload, func(v Values) string { return v.Workload }},
		{FieldAgent, func(v Values) string { return v.Agent }},
		{FieldAgentPublicKey, func(v Values) string { return v.AgentPublicKey }},
		{FieldComputationID, func(v Values) string { return v.ComputationID }},
		{FieldTaskID, func(v Values) string { return v.TaskID }},
		{FieldThreadID, func(v Values) string { return v.ThreadID }},
		{FieldDelegationID, func(v Values) string { return v.DelegationID }},
		{FieldIntentRef, func(v Values) string { return v.IntentRef }},
		{FieldCapabilityRef, func(v Values) string { return v.CapabilityRef }},
		{FieldOntologyID, func(v Values) string { return v.OntologyID }},
	} {
		value := f.get(values)
		if isEmpty(value) {
			continue
		}
		if err := validateFieldValue(f.name, value); err != nil {
			errs = append(errs, validationError(LayerIdentityGrant, f.name, err))
		}
	}
	for _, set := range []struct {
		field  string
		values []string
	}{
		{FieldScopes, values.Scopes},
		{FieldResources, values.Resources},
		{FieldAuthorizationDetails, values.AuthorizationDetails},
	} {
		if len(set.values) > MaxSetValues {
			errs = append(errs, validationError(LayerIdentityGrant, set.field, ErrTooManyValues))
			continue
		}
		for _, value := range set.values {
			if isEmpty(value) {
				continue
			}
			if err := validateValue(value); err != nil {
				errs = append(errs, validationError(LayerIdentityGrant, set.field, err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateAuthorizedEndpointKeys(keys []string) error {
	var errs ValidationErrors
	if len(keys) > MaxSetValues {
		return validationError(LayerIdentityGrant, FieldEndpointKey, ErrTooManyValues)
	}
	for _, key := range keys {
		if isEmpty(key) {
			continue
		}
		if err := validateValue(key); err != nil {
			errs = append(errs, validationError(LayerIdentityGrant, FieldEndpointKey, err))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// MarkSessionBindingUsed records one-shot use of a validated session-binding
// statement. Callers that also compare the resulting assertion against a local
// policy should call this after the policy comparison succeeds.
func MarkSessionBindingUsed(cache ReplayCache, statement VerifiedSessionBindingStatement) error {
	if cache == nil {
		return nil
	}
	key := statement.GrantHash + "\x00" +
		statement.Audience + "\x00" +
		statement.Binding.TLSExporterSHA256 + "\x00" +
		statement.Binding.RequestContextSHA256 + "\x00" +
		statement.Binding.Nonce
	if err := cache.MarkUsed(key, statement.Binding.ExpiresAt); err != nil {
		return validationError(LayerSessionBinding, FieldNonce, err)
	}
	return nil
}

func validateGrantLifetime(grant VerifiedGrant, now time.Time) error {
	var errs ValidationErrors
	if grant.ExpiresAt.IsZero() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrMissingExpected))
	} else if !now.IsZero() && now.After(grant.ExpiresAt) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrExpiredAssertion))
	}
	if !grant.IssuedAt.IsZero() && !now.IsZero() && grant.IssuedAt.After(now) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldIssuedAt, ErrFutureAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateStatementBinding(binding Binding, now time.Time) error {
	var errs ValidationErrors
	for _, f := range []struct {
		name  string
		value string
	}{
		{FieldLeafPublicKeyHash, binding.LeafPublicKeySHA256},
		{FieldTLSExporterHash, binding.TLSExporterSHA256},
		{FieldRequestContextHash, binding.RequestContextSHA256},
		{FieldNonce, binding.Nonce},
	} {
		if err := validateBindingString(f.name, f.value); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if binding.AttestationBinderSHA256 != "" {
		if err := validateBindingString(FieldAttestationBinderHash, binding.AttestationBinderSHA256); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if binding.ExpiresAt.IsZero() {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding))
	} else if !now.IsZero() && now.After(binding.ExpiresAt) {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion))
	}
	if !binding.IssuedAt.IsZero() && !now.IsZero() && binding.IssuedAt.After(now) {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuedAt, ErrFutureAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateExpectedString(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingExpected)
	}
	if err := validateValue(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateObservedString(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingObserved)
	}
	if err := validateValue(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateBindingString(field, value string) error {
	if isEmpty(value) {
		return validationError(LayerSessionBinding, field, ErrMissingBinding)
	}
	if err := validateValue(value); err != nil {
		return validationError(LayerSessionBinding, field, err)
	}
	return nil
}

func (g VerifiedGrant) hasBindingKey() bool {
	if !isEmpty(g.ConfirmationKey) || !isEmpty(g.Values.AgentPublicKey) {
		return true
	}
	for _, key := range g.AuthorizedEndpointKeys {
		if !isEmpty(key) {
			return true
		}
	}
	return false
}

func (g VerifiedGrant) allowsBindingKey(key string) bool {
	if isEmpty(key) {
		return false
	}
	if key == g.ConfirmationKey || key == g.Values.AgentPublicKey {
		return true
	}
	for _, allowed := range g.AuthorizedEndpointKeys {
		if key == allowed {
			return true
		}
	}
	return false
}
