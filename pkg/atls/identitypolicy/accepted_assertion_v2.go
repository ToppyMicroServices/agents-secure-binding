// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package identitypolicy

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrMissingAcceptanceInputV2 = errors.New("identitypolicy: missing v2 acceptance input")
	ErrInvalidAttestationV2     = errors.New("identitypolicy: invalid v2 attestation result")
)

const ReplayCommitStateCommittedV2 = "committed"

// ProfileSelectionV2 is selected by verifier-local policy. It is not read
// from peer metadata.
type ProfileSelectionV2 struct {
	ProfileType    string `json:"profile_type" yaml:"profile_type"`
	ProfileVersion string `json:"profile_version" yaml:"profile_version"`
	BindingProfile string `json:"binding_profile" yaml:"binding_profile"`
	ProtocolID     string `json:"protocol_id" yaml:"protocol_id"`
}

// FreshnessInputsV2 contains verifier-side expiry limits that are not carried
// by the authority grant or session proof. The Direct-Agent v2 profile requires
// endpoint credential, evidence challenge, and local-policy limits. The other
// limits are included only when the selected profile uses them.
type FreshnessInputsV2 struct {
	EndpointCredentialExpiresAt    time.Time `json:"endpoint_credential_expires_at" yaml:"endpoint_credential_expires_at"`
	EvidenceChallengeExpiresAt     time.Time `json:"evidence_challenge_expires_at" yaml:"evidence_challenge_expires_at"`
	LocalPolicyExpiresAt           time.Time `json:"local_policy_expires_at" yaml:"local_policy_expires_at"`
	ExportedAuthenticatorExpiresAt time.Time `json:"exported_authenticator_expires_at,omitempty" yaml:"exported_authenticator_expires_at,omitempty"`
	AttestationCollateralExpiresAt time.Time `json:"attestation_collateral_expires_at,omitempty" yaml:"attestation_collateral_expires_at,omitempty"`
}

// VerifiedAttestationResultV2 is returned by a verifier-selected attestation
// adapter only after signature, audience, freshness, appraisal-policy, and
// channel-binder checks succeed.
type VerifiedAttestationResultV2 struct {
	ProfileType       string
	ProfileVersion    string
	ResultID          string
	Issuer            string
	Subject           string
	SignerKeyID       string
	Audience          string
	AppraisalPolicyID string
	BinderSHA256      string
	IssuedAt          time.Time
	ExpiresAt         time.Time
}

// AcceptanceInputsV2 is trusted verifier context used to prepare a final v2
// assertion. AttestationResult is nil only for an explicitly attestation-free
// binding.
type AcceptanceInputsV2 struct {
	Profile           ProfileSelectionV2
	Freshness         FreshnessInputsV2
	AttestationResult *VerifiedAttestationResultV2
}

// AcceptedScopeV2 applies to every sub-result in one accepted assertion.
// Sub-results are not independently portable outside this scope.
type AcceptedScopeV2 struct {
	Audience             string `json:"audience" yaml:"audience"`
	BindingContextSHA256 string `json:"binding_context_sha256" yaml:"binding_context_sha256"`
}

type AcceptedChannelV2 struct {
	EndpointRole               string `json:"endpoint_role" yaml:"endpoint_role"`
	AcceptedEndpointSPKISHA256 string `json:"accepted_endpoint_spki_sha256" yaml:"accepted_endpoint_spki_sha256"`
	TLSExporterSHA256          string `json:"tls_exporter_sha256" yaml:"tls_exporter_sha256"`
}

type AcceptedActorV2 struct {
	ID string `json:"id" yaml:"id"`
}

type AcceptedAuthorityV2 struct {
	Issuer string `json:"issuer" yaml:"issuer"`
}

type AcceptedInteractionV2 struct {
	Type          string `json:"type" yaml:"type"`
	Service       string `json:"service,omitempty" yaml:"service,omitempty"`
	Tenant        string `json:"tenant,omitempty" yaml:"tenant,omitempty"`
	Deployment    string `json:"deployment,omitempty" yaml:"deployment,omitempty"`
	Environment   string `json:"environment,omitempty" yaml:"environment,omitempty"`
	ComputationID string `json:"computation_id,omitempty" yaml:"computation_id,omitempty"`
	TaskID        string `json:"task_id,omitempty" yaml:"task_id,omitempty"`
	ThreadID      string `json:"thread_id,omitempty" yaml:"thread_id,omitempty"`
	IntentRef     string `json:"intent_ref,omitempty" yaml:"intent_ref,omitempty"`
}

type AcceptedDelegationV2 struct {
	DelegationID string `json:"delegation_id" yaml:"delegation_id"`
}

type AcceptedTargetV2 struct {
	Resource  string `json:"resource" yaml:"resource"`
	Operation string `json:"operation" yaml:"operation"`
}

type AcceptedAttestationResultV2 struct {
	ProfileType       string `json:"profile_type" yaml:"profile_type"`
	ProfileVersion    string `json:"profile_version" yaml:"profile_version"`
	Subject           string `json:"subject" yaml:"subject"`
	AppraisalPolicyID string `json:"appraisal_policy_id" yaml:"appraisal_policy_id"`
}

// ReplayCommitV2 is created only after the receiver-side replay store accepts
// the nonce reservation. The application learns the retention boundary but
// not the nonce-derived store key.
type ReplayCommitV2 struct {
	State       string    `json:"state" yaml:"state"`
	RetainUntil time.Time `json:"retain_until" yaml:"retain_until"`
}

// AcceptedAssertionV2 is the only v2 value exposed after the complete
// verifier path. Optional dimensions use pointers so absence cannot serialize
// as an empty accepted object.
type AcceptedAssertionV2 struct {
	Scope                  AcceptedScopeV2              `json:"scope" yaml:"scope"`
	AcceptedProfile        ProfileSelectionV2           `json:"accepted_profile" yaml:"accepted_profile"`
	AcceptedChannel        AcceptedChannelV2            `json:"accepted_channel" yaml:"accepted_channel"`
	AcceptedActor          AcceptedActorV2              `json:"accepted_actor" yaml:"accepted_actor"`
	AcceptedAuthority      AcceptedAuthorityV2          `json:"accepted_authority" yaml:"accepted_authority"`
	AcceptedInteraction    AcceptedInteractionV2        `json:"accepted_interaction" yaml:"accepted_interaction"`
	AcceptedDelegation     *AcceptedDelegationV2        `json:"accepted_delegation,omitempty" yaml:"accepted_delegation,omitempty"`
	AcceptedTarget         *AcceptedTargetV2            `json:"accepted_target,omitempty" yaml:"accepted_target,omitempty"`
	AttestationResult      *AcceptedAttestationResultV2 `json:"attestation_result,omitempty" yaml:"attestation_result,omitempty"`
	ReplayCommit           ReplayCommitV2               `json:"replay_commit" yaml:"replay_commit"`
	EffectiveAuthorization AuthorizationV2              `json:"effective_authorization" yaml:"effective_authorization"`
	Expiry                 time.Time                    `json:"expiry" yaml:"expiry"`
}

// PreparedAssertionV2 is deliberately opaque outside this package. It has
// passed authentication, attestation, and policy checks, but is not accepted
// until CommitPreparedAssertionV2 reserves its verifier nonce.
type PreparedAssertionV2 struct {
	assertion         AcceptedAssertionV2
	replayKey         string
	replayRetainUntil time.Time
}

// Expiry returns the application-facing acceptance deadline. Replay storage
// uses ReplayRetainUntil, which can be later.
func (p PreparedAssertionV2) Expiry() time.Time {
	return p.assertion.Expiry
}

// ReplayRetainUntil returns the minimum retention boundary required for the
// verifier nonce. It can be later than the application assertion expiry.
func (p PreparedAssertionV2) ReplayRetainUntil() time.Time {
	return p.replayRetainUntil
}

// PrepareAssertionV2 validates policy-selected values and builds an opaque
// pre-replay projection. It never returns AcceptedAssertionV2.
func PrepareAssertionV2(policy PolicyV2, assertion AssertionV2, expectedBinding BindingV2, now time.Time, inputs AcceptanceInputsV2) (PreparedAssertionV2, error) {
	if err := ValidateAssertionV2(policy, assertion, expectedBinding, now); err != nil {
		return PreparedAssertionV2{}, err
	}
	if now.IsZero() {
		return PreparedAssertionV2{}, validationError(LayerIdentityGrant, FieldExpiresAt, ErrMissingCurrentTimeV2)
	}
	if err := validateAcceptanceIdentityV2(policy, assertion); err != nil {
		return PreparedAssertionV2{}, err
	}
	if err := validateProfileSelectionV2(inputs.Profile); err != nil {
		return PreparedAssertionV2{}, err
	}
	if err := validateFreshnessInputsV2(inputs.Freshness, now); err != nil {
		return PreparedAssertionV2{}, err
	}
	attestation, err := acceptedAttestationResultV2(assertion, inputs.AttestationResult, now)
	if err != nil {
		return PreparedAssertionV2{}, err
	}

	effectiveAuthorization, err := EffectiveAuthorization(policy, assertion)
	if err != nil {
		return PreparedAssertionV2{}, err
	}
	expiry, err := earliestAcceptedExpiryV2(assertion, inputs, now)
	if err != nil {
		return PreparedAssertionV2{}, err
	}
	acceptedValues := acceptedValuesV2(policy)
	replayKey, err := replayNonceKeyV2(assertion.Audience, expectedBinding.VerifierNonce)
	if err != nil {
		return PreparedAssertionV2{}, err
	}
	replayRetainUntil := latestTimeV2(assertion.Binding.ExpiresAt, inputs.Freshness.EvidenceChallengeExpiresAt)

	prepared := AcceptedAssertionV2{
		Scope: AcceptedScopeV2{
			Audience:             assertion.Audience,
			BindingContextSHA256: expectedBinding.BindingContextSHA256,
		},
		AcceptedProfile: inputs.Profile,
		AcceptedChannel: AcceptedChannelV2{
			EndpointRole:               expectedBinding.EndpointRole,
			AcceptedEndpointSPKISHA256: expectedBinding.AcceptedEndpointSPKISHA256,
			TLSExporterSHA256:          expectedBinding.TLSExporterSHA256,
		},
		AcceptedActor: AcceptedActorV2{
			ID: acceptedValues.Agent,
		},
		AcceptedAuthority: AcceptedAuthorityV2{
			Issuer: assertion.Issuer,
		},
		AcceptedInteraction: AcceptedInteractionV2{
			Type:          expectedBinding.InteractionType,
			Service:       acceptedValues.Service,
			Tenant:        acceptedValues.Tenant,
			Deployment:    acceptedValues.Deployment,
			Environment:   acceptedValues.Environment,
			ComputationID: acceptedValues.ComputationID,
			TaskID:        acceptedValues.TaskID,
			ThreadID:      acceptedValues.ThreadID,
			IntentRef:     acceptedValues.IntentRef,
		},
		AttestationResult:      attestation,
		EffectiveAuthorization: effectiveAuthorization,
		Expiry:                 expiry,
	}
	if policy.Require.D5 && acceptedValues.DelegationID != "" {
		prepared.AcceptedDelegation = &AcceptedDelegationV2{DelegationID: acceptedValues.DelegationID}
	}
	if policy.Require.D6 {
		prepared.AcceptedTarget = &AcceptedTargetV2{
			Resource:  policy.ExpectedTarget.Resource,
			Operation: policy.ExpectedTarget.Operation,
		}
	}
	return PreparedAssertionV2{assertion: prepared, replayKey: replayKey, replayRetainUntil: replayRetainUntil}, nil
}

// CommitPreparedAssertionV2 reserves the verifier nonce and returns the
// application-facing assertion only after the replay store accepts it. The
// replay inputs are carried inside the opaque prepared value, so a receipt from
// another request cannot be combined with this assertion. clock is evaluated
// before and after the store call because a slow commit can cross the assertion
// expiry. In that case replay remains consumed, but no accepted result escapes.
func CommitPreparedAssertionV2(cache ReplayCache, prepared PreparedAssertionV2, clock func() time.Time) (AcceptedAssertionV2, error) {
	if prepared.replayKey == "" || prepared.replayRetainUntil.IsZero() || prepared.assertion.Expiry.IsZero() {
		return AcceptedAssertionV2{}, ErrMissingAcceptanceInputV2
	}
	if err := validatePreparedCommitTimeV2(prepared, clock); err != nil {
		return AcceptedAssertionV2{}, err
	}
	if err := commitReplayKeyV2(cache, prepared.replayKey, prepared.replayRetainUntil); err != nil {
		return AcceptedAssertionV2{}, err
	}
	if err := validatePreparedCommitTimeV2(prepared, clock); err != nil {
		return AcceptedAssertionV2{}, err
	}
	accepted := prepared.assertion
	accepted.ReplayCommit = ReplayCommitV2{
		State:       ReplayCommitStateCommittedV2,
		RetainUntil: prepared.replayRetainUntil,
	}
	return accepted, nil
}

func validatePreparedCommitTimeV2(prepared PreparedAssertionV2, clock func() time.Time) error {
	if clock == nil {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingCurrentTimeV2)
	}
	now := clock()
	if now.IsZero() {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrMissingCurrentTimeV2)
	}
	if !now.Before(prepared.assertion.Expiry) {
		return validationError(LayerSessionBinding, FieldExpiresAt, ErrExpiredAssertion)
	}
	return nil
}

func validateAcceptanceIdentityV2(policy PolicyV2, assertion AssertionV2) error {
	for field, value := range map[string]string{
		FieldIssuer:          assertion.Issuer,
		FieldAudience:        assertion.Audience,
		FieldGrantHash:       assertion.GrantHash,
		FieldIssuerKey:       assertion.AuthorityKeyID,
		FieldConfirmationKey: assertion.ActorConfirmationKeyID,
		"grant_id":           assertion.AuthorityGrantID,
		"proof_id":           assertion.SessionProofID,
	} {
		if isEmpty(value) {
			return validationError(LayerIdentityGrant, field, ErrMissingObserved)
		}
		if err := validateDecisionValueV2(value); err != nil {
			return validationError(LayerIdentityGrant, field, err)
		}
	}
	if !policy.Require.D4 || isEmpty(policy.Expected.Agent) {
		return validationError(LayerD4, FieldAgent, ErrMissingExpected)
	}
	if !policy.Require.D5 {
		return validationError(LayerD5, FieldAll, ErrMissingExpected)
	}
	return nil
}

func validateProfileSelectionV2(profile ProfileSelectionV2) error {
	for field, value := range map[string]string{
		"profile_type":    profile.ProfileType,
		"profile_version": profile.ProfileVersion,
		"binding_profile": profile.BindingProfile,
		"protocol_id":     profile.ProtocolID,
	} {
		if isEmpty(value) {
			return fmt.Errorf("%w: %s", ErrMissingAcceptanceInputV2, field)
		}
		if err := validateDecisionValueV2(value); err != nil {
			return validationError("accepted_profile", field, err)
		}
	}
	return nil
}

func validateFreshnessInputsV2(inputs FreshnessInputsV2, now time.Time) error {
	for field, value := range map[string]time.Time{
		"endpoint_credential_expires_at": inputs.EndpointCredentialExpiresAt,
		"evidence_challenge_expires_at":  inputs.EvidenceChallengeExpiresAt,
		"local_policy_expires_at":        inputs.LocalPolicyExpiresAt,
	} {
		if value.IsZero() {
			return fmt.Errorf("%w: %s", ErrMissingAcceptanceInputV2, field)
		}
		if !now.Before(value) {
			return validationError("freshness", field, ErrExpiredAssertion)
		}
	}
	for field, value := range map[string]time.Time{
		"exported_authenticator_expires_at": inputs.ExportedAuthenticatorExpiresAt,
		"attestation_collateral_expires_at": inputs.AttestationCollateralExpiresAt,
	} {
		if !value.IsZero() && !now.Before(value) {
			return validationError("freshness", field, ErrExpiredAssertion)
		}
	}
	return nil
}

func acceptedAttestationResultV2(assertion AssertionV2, result *VerifiedAttestationResultV2, now time.Time) (*AcceptedAttestationResultV2, error) {
	selected := assertion.Binding.AttestationBinderSHA256 != ""
	if !selected {
		if result != nil {
			return nil, fmt.Errorf("%w: unexpected attestation result", ErrInvalidAttestationV2)
		}
		return nil, nil
	}
	if result == nil {
		return nil, fmt.Errorf("%w: missing attestation result", ErrInvalidAttestationV2)
	}
	for field, value := range map[string]string{
		"profile_type":             result.ProfileType,
		"profile_version":          result.ProfileVersion,
		"result_id":                result.ResultID,
		FieldIssuer:                result.Issuer,
		"subject":                  result.Subject,
		"signer_key_id":            result.SignerKeyID,
		FieldAudience:              result.Audience,
		"appraisal_policy_id":      result.AppraisalPolicyID,
		FieldAttestationBinderHash: result.BinderSHA256,
	} {
		if isEmpty(value) {
			return nil, fmt.Errorf("%w: missing %s", ErrInvalidAttestationV2, field)
		}
		if err := validateDecisionValueV2(value); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrInvalidAttestationV2, field, err)
		}
	}
	if result.Subject != assertion.ObservedValues.Agent || result.Audience != assertion.Audience || result.BinderSHA256 != assertion.Binding.AttestationBinderSHA256 {
		return nil, fmt.Errorf("%w: subject, audience, or binder mismatch", ErrInvalidAttestationV2)
	}
	if result.IssuedAt.IsZero() || result.ExpiresAt.IsZero() || result.IssuedAt.After(now) || !now.Before(result.ExpiresAt) || !result.IssuedAt.Before(result.ExpiresAt) {
		return nil, fmt.Errorf("%w: invalid lifetime", ErrInvalidAttestationV2)
	}
	return &AcceptedAttestationResultV2{
		ProfileType:       result.ProfileType,
		ProfileVersion:    result.ProfileVersion,
		Subject:           result.Subject,
		AppraisalPolicyID: result.AppraisalPolicyID,
	}, nil
}

func latestTimeV2(first, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}

func earliestAcceptedExpiryV2(assertion AssertionV2, inputs AcceptanceInputsV2, now time.Time) (time.Time, error) {
	bounds := []time.Time{
		assertion.AuthorityExpiresAt,
		assertion.Binding.ExpiresAt,
		inputs.Freshness.EndpointCredentialExpiresAt,
		inputs.Freshness.EvidenceChallengeExpiresAt,
		inputs.Freshness.LocalPolicyExpiresAt,
	}
	for _, optional := range []time.Time{
		inputs.Freshness.ExportedAuthenticatorExpiresAt,
		inputs.Freshness.AttestationCollateralExpiresAt,
	} {
		if !optional.IsZero() {
			bounds = append(bounds, optional)
		}
	}
	if inputs.AttestationResult != nil {
		bounds = append(bounds, inputs.AttestationResult.ExpiresAt)
	}

	earliest := time.Time{}
	for _, bound := range bounds {
		if bound.IsZero() {
			return time.Time{}, ErrMissingAcceptanceInputV2
		}
		if !now.Before(bound) {
			return time.Time{}, ErrExpiredAssertion
		}
		if earliest.IsZero() || bound.Before(earliest) {
			earliest = bound
		}
	}
	return earliest, nil
}
