// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidLifetimeV2     = errors.New("identitypolicy: invalid v2 assertion lifetime")
	ErrMissingCurrentTimeV2  = errors.New("identitypolicy: current time unavailable for v2 validation")
	ErrMissingReplayCacheV2  = ErrReplayUnavailable
	ErrReplayKeyInputTooLong = errors.New("identitypolicy: v2 replay key input too long")
)

const replayKeyDomainV2 = "SBAIP-REPLAY-v2"

// BindingV2 carries the draft-06 v2 session-proof binding values. Endpoint
// role, interaction type, endpoint key, exporter, context, and nonce are
// mandatory. AttestationBinderSHA256 and AttemptID are profile-optional, but
// their presence must match verifier-local ExpectedBinding exactly.
type BindingV2 struct {
	EndpointRole               string    `json:"endpoint_role,omitempty" yaml:"endpoint_role,omitempty"`
	InteractionType            string    `json:"interaction_type,omitempty" yaml:"interaction_type,omitempty"`
	AcceptedEndpointSPKISHA256 string    `json:"accepted_endpoint_spki_sha256,omitempty" yaml:"accepted_endpoint_spki_sha256,omitempty"`
	TLSExporterSHA256          string    `json:"tls_exporter_sha256,omitempty" yaml:"tls_exporter_sha256,omitempty"`
	BindingContextSHA256       string    `json:"binding_context_sha256,omitempty" yaml:"binding_context_sha256,omitempty"`
	AttestationBinderSHA256    string    `json:"attestation_binder_sha256,omitempty" yaml:"attestation_binder_sha256,omitempty"`
	VerifierNonce              string    `json:"verifier_nonce,omitempty" yaml:"verifier_nonce,omitempty"`
	AttemptID                  string    `json:"attempt_id,omitempty" yaml:"attempt_id,omitempty"`
	IssuedAt                   time.Time `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	ExpiresAt                  time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// VerifiedGrantV2 extends an authenticated v1-shaped grant view with a
// separate D6 target. This repository profile authorizes only ConfirmationKey
// to sign the v2 proof; legacy AgentPublicKey and role-agnostic endpoint-key
// lists remain observed grant fields and do not authorize proof signing. D7
// values are copied into typed accepted output only after policy validation.
type VerifiedGrantV2 struct {
	VerifiedGrant
	Target TargetV2
}

// VerifiedSessionBindingStatementV2 is an already signature-verified v2
// holder-of-key proof.
type VerifiedSessionBindingStatementV2 struct {
	JWTID     string
	GrantHash string
	Audience  string
	SignerKey string
	Binding   BindingV2
}

// AssertionV2 contains only authenticated observed inputs. It is compared
// with verifier-local PolicyV2 before any value is accepted by an application.
type AssertionV2 struct {
	Issuer                 string
	AuthorityGrantID       string
	AuthorityKeyID         string
	Audience               string
	GrantHash              string
	ActorConfirmationKeyID string
	SessionProofID         string
	ObservedValues         Values
	Target                 TargetV2
	ObservedAuthorization  AuthorizationV2
	Binding                BindingV2
	AuthorityIssuedAt      time.Time
	AuthorityExpiresAt     time.Time
}

// NewAssertionFromSessionBindingV2 validates grant-to-proof authority and
// freshness, then builds an observed assertion. Replay is intentionally not
// committed here. Complete acceptance paths should use PrepareAssertionV2 and
// CommitPreparedAssertionV2 so replay retention includes the trusted challenge
// expiry. MarkSessionBindingUsedV2 is a lower-level alternative for callers
// that already completed binding, attestation, policy, and authorization checks.
func NewAssertionFromSessionBindingV2(grant VerifiedGrantV2, statement VerifiedSessionBindingStatementV2, now time.Time) (AssertionV2, error) {
	if err := ValidateSessionBindingStatementV2(grant, statement, now); err != nil {
		return AssertionV2{}, err
	}
	return AssertionV2{
		Issuer:                 grant.Issuer,
		AuthorityGrantID:       grant.JWTID,
		AuthorityKeyID:         grant.IssuerKey,
		Audience:               grant.Audience,
		GrantHash:              grant.GrantHash,
		ActorConfirmationKeyID: grant.ConfirmationKey,
		SessionProofID:         statement.JWTID,
		ObservedValues:         grant.Values,
		Target:                 grant.Target,
		ObservedAuthorization:  authorizationFromValuesV2(grant.Values),
		Binding:                statement.Binding,
		AuthorityIssuedAt:      grant.IssuedAt,
		AuthorityExpiresAt:     grant.ExpiresAt,
	}, nil
}

// ValidateSessionBindingStatementV2 checks that the proof signer is the grant's
// confirmation key and that grant, proof, and lifetime values describe one
// interaction. Endpoint-key proof signing needs a separate role-aware profile;
// the legacy role-agnostic endpoint-key list is not authorization here. This
// function does not commit replay state.
func ValidateSessionBindingStatementV2(grant VerifiedGrantV2, statement VerifiedSessionBindingStatementV2, now time.Time) error {
	var errs ValidationErrors

	if err := validateExpectedStringV2(LayerIdentityGrant, FieldIssuer, grant.Issuer); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedStringV2(LayerIdentityGrant, FieldAudience, grant.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedStringV2(LayerIdentityGrant, FieldGrantHash, grant.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateExpectedStringV2(LayerIdentityGrant, "grant_id", grant.JWTID); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateObservedStringV2(LayerSessionBinding, "proof_id", statement.JWTID); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateObservedStringV2(LayerSessionBinding, FieldGrantHash, statement.GrantHash); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.GrantHash != statement.GrantHash {
		errs = append(errs, validationError(LayerSessionBinding, FieldGrantHash, ErrMismatch))
	}
	if err := validateObservedStringV2(LayerSessionBinding, FieldAudience, statement.Audience); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if grant.Audience != statement.Audience {
		errs = append(errs, validationError(LayerSessionBinding, FieldAudience, ErrMismatch))
	}
	if err := validateObservedStringV2(LayerSessionBinding, FieldSignerKey, statement.SignerKey); err != nil {
		errs = appendValidationErrors(errs, err)
	} else if isEmpty(grant.ConfirmationKey) || statement.SignerKey != grant.ConfirmationKey {
		errs = append(errs, validationError(LayerSessionBinding, FieldSignerKey, ErrUnauthorizedBindingKey))
	} else if grant.IssuerKey != "" && statement.SignerKey == grant.IssuerKey {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuerKey, ErrUnauthorizedBindingKey))
	}
	if isEmpty(grant.ConfirmationKey) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldConfirmationKey, ErrMissingExpected))
	} else if err := validateDecisionValueV2(grant.ConfirmationKey); err != nil {
		errs = append(errs, validationError(LayerIdentityGrant, FieldConfirmationKey, err))
	}
	if err := validateGrantValuesV2(grant.Values); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateAuthorizedEndpointKeysV2(grant.AuthorizedEndpointKeys); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateOptionalTargetV2(grant.Target); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateGrantLifetimeV2(grant.VerifiedGrant, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if err := validateStatementBindingV2(statement.Binding, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if !grant.ExpiresAt.IsZero() && !statement.Binding.ExpiresAt.IsZero() && statement.Binding.ExpiresAt.After(grant.ExpiresAt) {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrInvalidLifetimeV2))
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// ValidateAcceptedBindingV2 compares every v2 binding input with local
// expected state. The six mandatory expected values cannot be omitted.
// Optional binder and attempt ID use exact presence semantics: an unexpected
// value is rejected just as a missing expected value is rejected.
func ValidateAcceptedBindingV2(observed, expected BindingV2, now time.Time) error {
	var errs ValidationErrors
	for _, item := range []struct {
		field string
		want  string
		got   string
	}{
		{FieldEndpointRole, expected.EndpointRole, observed.EndpointRole},
		{FieldInteractionType, expected.InteractionType, observed.InteractionType},
		{FieldAcceptedEndpointSPKIHash, expected.AcceptedEndpointSPKISHA256, observed.AcceptedEndpointSPKISHA256},
		{FieldTLSExporterHash, expected.TLSExporterSHA256, observed.TLSExporterSHA256},
		{FieldBindingContextHash, expected.BindingContextSHA256, observed.BindingContextSHA256},
		{FieldVerifierNonce, expected.VerifierNonce, observed.VerifierNonce},
	} {
		if err := compareMandatoryBindingV2(item.field, item.want, item.got); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	for _, item := range []struct {
		field string
		want  string
		got   string
	}{
		{FieldAttestationBinderHash, expected.AttestationBinderSHA256, observed.AttestationBinderSHA256},
		{FieldAttemptID, expected.AttemptID, observed.AttemptID},
	} {
		if err := compareOptionalBindingV2(item.field, item.want, item.got); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	if err := validateBindingLifetimeV2(observed.IssuedAt, observed.ExpiresAt, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// SessionReplayKeyV2 derives the nonce-reservation key for the verifier
// audience. Proof, context, and attestation identifiers are deliberately not
// part of this key: changing them must not make one verifier nonce reusable.
func SessionReplayKeyV2(statement VerifiedSessionBindingStatementV2) (string, error) {
	return replayNonceKeyV2(statement.Audience, statement.Binding.VerifierNonce)
}

func replayNonceKeyV2(audience, verifierNonce string) (string, error) {
	for _, item := range []struct {
		field string
		value string
	}{
		{FieldAudience, audience},
		{FieldVerifierNonce, verifierNonce},
	} {
		if err := validateBindingStringV2(item.field, item.value); err != nil {
			return "", err
		}
	}

	encoded := make([]byte, 0, 192)
	encoded = append(encoded, replayKeyDomainV2...)
	encoded = append(encoded, 0)
	var err error
	for _, item := range []struct {
		name  string
		value string
	}{
		{"aud", audience},
		{"verifier_nonce", verifierNonce},
	} {
		encoded, err = appendReplayFieldV2(encoded, item.name, item.value)
		if err != nil {
			return "", err
		}
	}
	digest := sha256.Sum256(encoded)
	return "sbaip-replay-v2:" + hex.EncodeToString(digest[:]), nil
}

// MarkSessionBindingUsedV2 atomically commits the v2 replay key through the
// later of the proof and trusted verifier-challenge expiries. Unlike the legacy
// helper, v2 fails closed when the cache, or either retention bound, is absent.
func MarkSessionBindingUsedV2(cache ReplayCache, statement VerifiedSessionBindingStatementV2, verifierChallengeExpiresAt time.Time) error {
	key, err := SessionReplayKeyV2(statement)
	if err != nil {
		return err
	}
	if statement.Binding.ExpiresAt.IsZero() {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding)
	}
	if verifierChallengeExpiresAt.IsZero() {
		return validationError(LayerSessionBinding, "evidence_challenge_expires_at", ErrMissingAcceptanceInputV2)
	}
	return commitReplayKeyV2(cache, key, latestTimeV2(statement.Binding.ExpiresAt, verifierChallengeExpiresAt))
}

func commitReplayKeyV2(cache ReplayCache, key string, retainUntil time.Time) error {
	if isNilReplayCacheV2(cache) {
		return validationError(LayerSessionBinding, FieldVerifierNonce, ErrMissingReplayCacheV2)
	}
	if isEmpty(key) {
		return validationError(LayerSessionBinding, FieldVerifierNonce, ErrMissingBinding)
	}
	if retainUntil.IsZero() {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding)
	}
	if err := cache.MarkUsed(key, retainUntil); err != nil {
		if errors.Is(err, ErrReplayDetected) {
			return validationError(LayerSessionBinding, FieldVerifierNonce, err)
		}
		return validationError(LayerSessionBinding, FieldVerifierNonce, errors.Join(ErrReplayUnavailable, err))
	}
	return nil
}

func compareMandatoryBindingV2(field, expected, observed string) error {
	if isEmpty(expected) {
		return validationError("binding", field, ErrMissingExpected)
	}
	if err := validateDecisionValueV2(expected); err != nil {
		return validationError("binding", field, err)
	}
	if isEmpty(observed) {
		return validationError("binding", field, ErrMissingBinding)
	}
	if err := validateDecisionValueV2(observed); err != nil {
		return validationError("binding", field, err)
	}
	if observed != expected {
		return validationError("binding", field, ErrMismatch)
	}
	return nil
}

func compareOptionalBindingV2(field, expected, observed string) error {
	expectedPresent := !isEmpty(expected)
	observedPresent := !isEmpty(observed)
	if expectedPresent != observedPresent {
		if expectedPresent {
			return validationError("binding", field, ErrMissingBinding)
		}
		return validationError("binding", field, ErrMismatch)
	}
	if !expectedPresent {
		return nil
	}
	if err := validateDecisionValueV2(expected); err != nil {
		return validationError("binding", field, err)
	}
	if err := validateDecisionValueV2(observed); err != nil {
		return validationError("binding", field, err)
	}
	if observed != expected {
		return validationError("binding", field, ErrMismatch)
	}
	return nil
}

func validateStatementBindingV2(binding BindingV2, now time.Time) error {
	var errs ValidationErrors
	for _, item := range []struct {
		field string
		value string
	}{
		{FieldEndpointRole, binding.EndpointRole},
		{FieldInteractionType, binding.InteractionType},
		{FieldAcceptedEndpointSPKIHash, binding.AcceptedEndpointSPKISHA256},
		{FieldTLSExporterHash, binding.TLSExporterSHA256},
		{FieldBindingContextHash, binding.BindingContextSHA256},
		{FieldVerifierNonce, binding.VerifierNonce},
	} {
		if err := validateBindingStringV2(item.field, item.value); err != nil {
			errs = appendValidationErrors(errs, err)
		}
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{FieldAttestationBinderHash, binding.AttestationBinderSHA256},
		{FieldAttemptID, binding.AttemptID},
	} {
		if !isEmpty(item.value) {
			if err := validateBindingStringV2(item.field, item.value); err != nil {
				errs = appendValidationErrors(errs, err)
			}
		}
	}
	if err := validateBindingLifetimeV2(binding.IssuedAt, binding.ExpiresAt, now); err != nil {
		errs = appendValidationErrors(errs, err)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateGrantLifetimeV2(grant VerifiedGrant, now time.Time) error {
	var errs ValidationErrors
	if now.IsZero() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrMissingCurrentTimeV2))
	}
	if grant.IssuedAt.IsZero() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldIssuedAt, ErrMissingExpected))
	}
	if grant.ExpiresAt.IsZero() {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrMissingExpected))
	}
	if !grant.IssuedAt.IsZero() && !grant.ExpiresAt.IsZero() && !grant.IssuedAt.Before(grant.ExpiresAt) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrInvalidLifetimeV2))
	}
	if !now.IsZero() && !grant.IssuedAt.IsZero() && grant.IssuedAt.After(now) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldIssuedAt, ErrFutureAssertion))
	}
	if !now.IsZero() && !grant.ExpiresAt.IsZero() && !now.Before(grant.ExpiresAt) {
		errs = append(errs, validationError(LayerIdentityGrant, FieldExpiresAt, ErrExpiredAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateBindingLifetimeV2(issuedAt, expiresAt, now time.Time) error {
	var errs ValidationErrors
	if now.IsZero() {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingCurrentTimeV2))
	}
	if issuedAt.IsZero() {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuedAt, ErrMissingBinding))
	}
	if expiresAt.IsZero() {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingBinding))
	}
	if !issuedAt.IsZero() && !expiresAt.IsZero() && !issuedAt.Before(expiresAt) {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrInvalidLifetimeV2))
	}
	if !now.IsZero() && !issuedAt.IsZero() && issuedAt.After(now) {
		errs = append(errs, validationError(LayerSessionBinding, FieldIssuedAt, ErrFutureAssertion))
	}
	if !now.IsZero() && !expiresAt.IsZero() && !now.Before(expiresAt) {
		errs = append(errs, validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateOptionalTargetV2(target TargetV2) error {
	var errs ValidationErrors
	for _, item := range []struct {
		field string
		value string
	}{
		{FieldTargetResource, target.Resource},
		{FieldTargetOperation, target.Operation},
	} {
		if isEmpty(item.value) {
			continue
		}
		if err := validateDecisionValueV2(item.value); err != nil {
			errs = append(errs, validationError(LayerIdentityGrant, item.field, err))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func authorizationFromValuesV2(values Values) AuthorizationV2 {
	return AuthorizationV2{
		CapabilityRef:        values.CapabilityRef,
		OntologyID:           values.OntologyID,
		Scopes:               append([]string(nil), values.Scopes...),
		Resources:            append([]string(nil), values.Resources...),
		AuthorizationDetails: append([]string(nil), values.AuthorizationDetails...),
	}
}

func validateExpectedStringV2(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingExpected)
	}
	if err := validateDecisionValueV2(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateObservedStringV2(layer, field, value string) error {
	if isEmpty(value) {
		return validationError(layer, field, ErrMissingObserved)
	}
	if err := validateDecisionValueV2(value); err != nil {
		return validationError(layer, field, err)
	}
	return nil
}

func validateBindingStringV2(field, value string) error {
	if isEmpty(value) {
		return validationError(LayerSessionBinding, field, ErrMissingBinding)
	}
	if err := validateDecisionValueV2(value); err != nil {
		return validationError(LayerSessionBinding, field, err)
	}
	return nil
}

func validateDecisionValueV2(value string) error {
	if len(value) > MaxValueLength {
		return ErrValueTooLong
	}
	if !utf8.ValidString(value) {
		return ErrUnsafeValue
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError || r == '<' || r == '>' {
			return ErrUnsafeValue
		}
	}
	return nil
}

func validateGrantValuesV2(values Values) error {
	var errs ValidationErrors
	for _, item := range []struct {
		field string
		value string
	}{
		{FieldService, values.Service},
		{FieldTenant, values.Tenant},
		{FieldDeployment, values.Deployment},
		{FieldEnvironment, values.Environment},
		{FieldWorkload, values.Workload},
		{FieldAgent, values.Agent},
		{FieldAgentPublicKey, values.AgentPublicKey},
		{FieldComputationID, values.ComputationID},
		{FieldTaskID, values.TaskID},
		{FieldThreadID, values.ThreadID},
		{FieldDelegationID, values.DelegationID},
		{FieldIntentRef, values.IntentRef},
		{FieldCapabilityRef, values.CapabilityRef},
		{FieldOntologyID, values.OntologyID},
	} {
		if isEmpty(item.value) {
			continue
		}
		if err := validateDecisionValueV2(item.value); err != nil {
			errs = append(errs, validationError(LayerIdentityGrant, item.field, err))
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
				errs = append(errs, validationError(LayerIdentityGrant, set.field, ErrMissingObserved))
				continue
			}
			if err := validateDecisionValueV2(value); err != nil {
				errs = append(errs, validationError(LayerIdentityGrant, set.field, err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func validateAuthorizedEndpointKeysV2(keys []string) error {
	if len(keys) > MaxSetValues {
		return validationError(LayerIdentityGrant, FieldEndpointKey, ErrTooManyValues)
	}
	var errs ValidationErrors
	for _, key := range keys {
		if isEmpty(key) {
			errs = append(errs, validationError(LayerIdentityGrant, FieldEndpointKey, ErrMissingObserved))
			continue
		}
		if err := validateDecisionValueV2(key); err != nil {
			errs = append(errs, validationError(LayerIdentityGrant, FieldEndpointKey, err))
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func appendReplayFieldV2(dst []byte, name, value string) ([]byte, error) {
	if len(name) > math.MaxUint16 || uint64(len(value)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %s", ErrReplayKeyInputTooLong, name)
	}
	var lengths [4]byte
	binary.BigEndian.PutUint16(lengths[:2], uint16(len(name)))
	dst = append(dst, lengths[:2]...)
	dst = append(dst, name...)
	binary.BigEndian.PutUint32(lengths[:], uint32(len(value)))
	dst = append(dst, lengths[:]...)
	dst = append(dst, value...)
	return dst, nil
}

func isNilReplayCacheV2(cache ReplayCache) bool {
	if cache == nil {
		return true
	}
	value := reflect.ValueOf(cache)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
