// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingKeyFunc          = errors.New("binding jwt: missing key function")
	ErrMissingLocalKey         = errors.New("binding jwt: missing local key")
	ErrMissingValidMethods     = errors.New("binding jwt: missing allowed signing methods")
	ErrMissingExpectedIssuer   = errors.New("binding jwt: missing expected issuer")
	ErrMissingExpectedAudience = errors.New("binding jwt: missing expected audience")
	ErrMissingConfirmationKey  = errors.New("binding jwt: missing confirmation key")
	ErrMissingKeyID            = errors.New("binding jwt: missing key id")
	ErrUnknownKeyID            = errors.New("binding jwt: unknown key id")
	ErrDisabledKeyID           = errors.New("binding jwt: disabled key id")
	ErrDuplicateKeyID          = errors.New("binding jwt: duplicate key id")
	ErrAmbiguousKeySource      = errors.New("binding jwt: ambiguous key source")
	ErrMissingJWTID            = errors.New("binding jwt: missing jwt id")
	ErrRevokedJWTID            = errors.New("binding jwt: revoked jwt id")
	ErrMissingSubject          = errors.New("binding jwt: missing subject")
	ErrMissingGrantHash        = errors.New("binding jwt: missing grant hash")
	ErrMissingBindingField     = errors.New("binding jwt: missing session binding field")
	ErrMissingIdentityPolicy   = errors.New("binding jwt: missing identity policy")
	ErrMissingReplayCache      = errors.New("binding jwt: missing replay cache")
	ErrInvalidTokenType        = errors.New("binding jwt: invalid token type")
	ErrUnsupportedVersion      = errors.New("binding jwt: unsupported profile version")
	ErrUnsafeSigningMethod     = errors.New("binding jwt: unsafe signing method")
	ErrDuplicateJWTMember      = errors.New("binding jwt: duplicate json member")
	ErrInvalidClockSkew        = errors.New("binding jwt: invalid clock skew")
)

var (
	ErrInvalidJWTEncoding         = errors.New("binding jwt v2: invalid compact jwt encoding")
	ErrInvalidProtectedHeader     = errors.New("binding jwt v2: invalid protected header")
	ErrInvalidJWTMember           = errors.New("binding jwt v2: invalid json member")
	ErrInvalidAudience            = errors.New("binding jwt v2: audience must be one exact string")
	ErrInvalidClaimEncoding       = errors.New("binding jwt v2: invalid claim encoding")
	ErrMissingIssuedAt            = errors.New("binding jwt v2: missing issued-at time")
	ErrMissingTargetField         = errors.New("binding jwt v2: missing target field")
	ErrMissingAttestationBinder   = errors.New("binding jwt v2: missing locally expected attestation binder")
	ErrMissingAttestationVerifier = errors.New("attestation verifier is required")
)

const (
	ClaimTokenType      = "profile_type"
	ClaimProfileVersion = "profile_version"

	LegacyClaimTokenType      = "agtp_type"
	LegacyClaimProfileVersion = "agtp_version"

	TokenTypeIdentityGrant  = "sbaip.identity-grant"
	TokenTypeSessionBinding = "sbaip.session-binding"

	LegacyTokenTypeIdentityGrant  = "agtp.identity-grant"
	LegacyTokenTypeSessionBinding = "agtp.session-binding"

	ProfileVersion           = "1"
	identityGrantJWTHashSeed = "sbaip.identity-grant.jwt.v1\x00"

	// ProfileVersionV2 is used only by the draft-06 session proof. The
	// authority grant remains the exact v1 compact-JWS profile.
	ProfileVersionV2 = "2"

	// IdentityGrantJWTTypeV2 and SessionBindingJWTTypeV2 are the exact
	// protected typ values selected by the repository-local draft-06 profile.
	IdentityGrantJWTTypeV2  = "JWT"
	SessionBindingJWTTypeV2 = "sbaip-session-binding+jwt"
)

// KeyFunc resolves a JWT verification key by protected-header key id.
type KeyFunc func(keyID string) (interface{}, error)

// LocalKey is a locally configured JWT verification key.
type LocalKey struct {
	KeyID    string
	Key      interface{}
	Disabled bool
}

// JWTVerifyOptions contains local verification policy for Direct-Agent binding
// JWTs. ClockSkew is optional; production profiles set a bounded value through
// AuthorityPolicy.
type JWTVerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ValidMethods     []string
	KeyFunc          KeyFunc
	LocalKeys        []LocalKey
	DisabledKeyIDs   []string
	RevokedJWTIDs    []string
	Now              time.Time
	ClockSkew        time.Duration
}

// SessionIdentityJWTOptions contains the local policy needed to accept a
// manager grant and an agent session-binding statement in one step.
type SessionIdentityJWTOptions struct {
	Grant           JWTVerifyOptions
	SessionBinding  JWTVerifyOptions
	Policy          identitypolicy.Policy
	ExpectedBinding identitypolicy.Binding
	ReplayCache     identitypolicy.ReplayCache
	Now             time.Time
}

// SessionIdentityJWTResult contains the verified identity material accepted by
// VerifySessionIdentityJWT.
type SessionIdentityJWTResult struct {
	Grant     identitypolicy.VerifiedGrant
	Statement identitypolicy.VerifiedSessionBindingStatement
	Assertion identitypolicy.Assertion
}

// AttestationVerifierV2 authenticates the attestation result selected for the
// accepted v2 binding. Configuring this callback requires a locally expected
// and proof-carried attestation binder; it cannot silently select a channel-
// binding-only path. The callback runs before D3-D7 policy or replay commit.
type AttestationVerifierV2 func(
	grant identitypolicy.VerifiedGrantV2,
	statement identitypolicy.VerifiedSessionBindingStatementV2,
	expected identitypolicy.BindingV2,
) (identitypolicy.VerifiedAttestationResultV2, error)

// SessionIdentityJWTOptionsV2 contains the verifier-local inputs for the
// repository's experimental draft-06 profile. It is intentionally separate
// from SessionIdentityJWTOptions so the v1 API and validation path are stable.
type SessionIdentityJWTOptionsV2 struct {
	Grant               JWTVerifyOptions
	SessionBinding      JWTVerifyOptions
	Policy              identitypolicy.PolicyV2
	ExpectedBinding     identitypolicy.BindingV2
	AcceptedProfile     identitypolicy.ProfileSelectionV2
	Freshness           identitypolicy.FreshnessInputsV2
	ReplayCache         identitypolicy.ReplayCache
	AttestationVerifier AttestationVerifierV2
	// Clock is read at replay commit as well as at initial verification. It
	// defaults to time.Now. Now can fix the initial verification instant, but
	// does not freeze commit-time expiry checks.
	Clock func() time.Time
	Now   time.Time
}

// SessionIdentityJWTResultV2 exposes only the verifier-local projection
// accepted through the complete v2 path. Raw grant and proof material remains
// internal to verification so applications cannot mistake surplus observed
// fields for accepted identity or authorization.
type SessionIdentityJWTResultV2 struct {
	Accepted identitypolicy.AcceptedAssertionV2
}

type bindingJWTClaims struct {
	jwt.RegisteredClaims

	ProfileType     string   `json:"profile_type,omitempty"`
	ProfileVersion  string   `json:"profile_version,omitempty"`
	LegacyType      string   `json:"agtp_type,omitempty"`
	LegacyVersion   string   `json:"agtp_version,omitempty"`
	Confirmation    cnf      `json:"cnf,omitempty"`
	EndpointKeyIDs  []string `json:"authorized_endpoint_keys,omitempty"`
	GrantHash       string   `json:"grant_hash,omitempty"`
	LeafKeySHA256   string   `json:"leaf_public_key_sha256,omitempty"`
	TLSExporter     string   `json:"tls_exporter_sha256,omitempty"`
	RequestContext  string   `json:"request_context_sha256,omitempty"`
	AttestationBind string   `json:"attestation_binder_sha256,omitempty"`
	Nonce           string   `json:"nonce,omitempty"`

	EndpointRole               string `json:"endpoint_role,omitempty"`
	InteractionType            string `json:"interaction_type,omitempty"`
	AcceptedEndpointSPKISHA256 string `json:"accepted_endpoint_spki_sha256,omitempty"`
	BindingContextSHA256       string `json:"binding_context_sha256,omitempty"`
	VerifierNonce              string `json:"verifier_nonce,omitempty"`
	AttemptID                  string `json:"attempt_id,omitempty"`

	Service              string   `json:"service,omitempty"`
	Tenant               string   `json:"tenant,omitempty"`
	Deployment           string   `json:"deployment,omitempty"`
	Environment          string   `json:"environment,omitempty"`
	Workload             string   `json:"workload,omitempty"`
	Agent                string   `json:"agent,omitempty"`
	AgentPublicKey       string   `json:"agent_public_key,omitempty"`
	ComputationID        string   `json:"computation_id,omitempty"`
	TaskID               string   `json:"task_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty"`
	DelegationID         string   `json:"delegation_id,omitempty"`
	IntentRef            string   `json:"intent_ref,omitempty"`
	CapabilityRef        string   `json:"capability_ref,omitempty"`
	OntologyID           string   `json:"ontology_id,omitempty"`
	Scope                string   `json:"scope,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	Resources            []string `json:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty"`
	TargetResource       string   `json:"target_resource,omitempty"`
	TargetOperation      string   `json:"target_operation,omitempty"`
}

type cnf struct {
	KeyID string `json:"kid,omitempty"`
}

// ValidateJWTVerifyOptions checks local JWT verification policy before a
// connection attempt uses it.
func ValidateJWTVerifyOptions(opts JWTVerifyOptions) error {
	if _, err := jwtParserOptions(opts); err != nil {
		return err
	}
	_, err := verificationKeyFunc(opts)
	return err
}

// IdentityGrantHash returns the domain-separated hash of the exact signed grant
// bytes. The session-binding statement carries this value.
func IdentityGrantHash(tokenString string) string {
	sum := IdentityGrantDigest(tokenString)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// IdentityGrantDigest returns the raw domain-separated digest of the exact
// compact-JWS grant bytes. IdentityGrantHash retains the v1 text encoding.
func IdentityGrantDigest(tokenString string) [sha256.Size]byte {
	return sha256.Sum256([]byte(identityGrantJWTHashSeed + tokenString))
}

// VerifyIdentityGrantJWT verifies a manager-issued identity grant JWT.
func VerifyIdentityGrantJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedGrant, error) {
	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if err := claims.requireProfile(TokenTypeIdentityGrant); err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingJWTID
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingSubject
	}
	if strings.TrimSpace(claims.Confirmation.KeyID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingConfirmationKey
	}

	values := identitypolicy.Values{
		Service:              claims.Service,
		Tenant:               claims.Tenant,
		Deployment:           claims.Deployment,
		Environment:          claims.Environment,
		Workload:             claims.Workload,
		Agent:                claims.Agent,
		AgentPublicKey:       claims.AgentPublicKey,
		ComputationID:        claims.ComputationID,
		TaskID:               claims.TaskID,
		ThreadID:             claims.ThreadID,
		DelegationID:         claims.DelegationID,
		IntentRef:            claims.IntentRef,
		CapabilityRef:        claims.CapabilityRef,
		OntologyID:           claims.OntologyID,
		Scopes:               withSpaceSeparatedValues(claims.Scopes, claims.Scope),
		Resources:            withSpaceSeparatedValues(claims.Resources, claims.Resource),
		AuthorizationDetails: claims.AuthorizationDetails,
	}
	if values.Agent == "" {
		values.Agent = claims.Subject
	}

	return identitypolicy.VerifiedGrant{
		JWTID:                  claims.ID,
		Issuer:                 claims.Issuer,
		IssuerKey:              signerKey,
		Audience:               opts.ExpectedAudience,
		GrantHash:              IdentityGrantHash(tokenString),
		Values:                 values,
		ConfirmationKey:        claims.Confirmation.KeyID,
		AuthorizedEndpointKeys: claims.EndpointKeyIDs,
		IssuedAt:               claimTime(claims.IssuedAt),
		ExpiresAt:              claimTime(claims.ExpiresAt),
	}, nil
}

// VerifySessionBindingJWT verifies an agent-issued session-binding JWT.
func VerifySessionBindingJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedSessionBindingStatement, error) {
	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if err := claims.requireProfile(TokenTypeSessionBinding); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedSessionBindingStatement{}, ErrMissingJWTID
	}
	if err := claims.requireSessionBindingFields(); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}

	return identitypolicy.VerifiedSessionBindingStatement{
		JWTID:     claims.ID,
		GrantHash: claims.GrantHash,
		Audience:  opts.ExpectedAudience,
		SignerKey: signerKey,
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:     claims.LeafKeySHA256,
			TLSExporterSHA256:       claims.TLSExporter,
			RequestContextSHA256:    claims.RequestContext,
			AttestationBinderSHA256: claims.AttestationBind,
			Nonce:                   claims.Nonce,
			IssuedAt:                claimTime(claims.IssuedAt),
			ExpiresAt:               claimTime(claims.ExpiresAt),
		},
	}, nil
}

// VerifySessionIdentityJWT verifies the Direct-Agent binding profile used by
// AttestedClientConfig.
func VerifySessionIdentityJWT(grantToken, bindingToken string, opts SessionIdentityJWTOptions) (SessionIdentityJWTResult, error) {
	if !opts.Policy.Enabled() {
		return SessionIdentityJWTResult{}, ErrMissingIdentityPolicy
	}
	if opts.ReplayCache == nil {
		return SessionIdentityJWTResult{}, ErrMissingReplayCache
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	grantOpts := opts.Grant
	grantOpts.Now = now
	grant, err := VerifyIdentityGrantJWT(grantToken, grantOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}

	bindingOpts := opts.SessionBinding
	bindingOpts.Now = now
	statement, err := VerifySessionBindingJWT(bindingToken, bindingOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if err := opts.Policy.ValidateAssertion(assertion, opts.ExpectedBinding, now); err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if err := identitypolicy.MarkSessionBindingUsed(opts.ReplayCache, statement); err != nil {
		return SessionIdentityJWTResult{}, err
	}

	return SessionIdentityJWTResult{
		Grant:     grant,
		Statement: statement,
		Assertion: assertion,
	}, nil
}

// VerifyIdentityGrantJWTV2 verifies the exact compact-JWS authority-grant
// profile selected by the experimental draft-06 path. The signed grant format
// remains profile version 1; legacy AGTP claim aliases are not accepted here.
func VerifyIdentityGrantJWTV2(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedGrantV2, error) {
	if err := ValidateJWTVerifyOptions(opts); err != nil {
		return identitypolicy.VerifiedGrantV2{}, err
	}
	if err := validateJWTV2Wire(tokenString, opts, IdentityGrantJWTTypeV2, v2GrantPayloadMembers, true); err != nil {
		return identitypolicy.VerifiedGrantV2{}, err
	}

	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedGrantV2{}, err
	}
	if claims.ProfileType != TokenTypeIdentityGrant {
		return identitypolicy.VerifiedGrantV2{}, ErrInvalidTokenType
	}
	if claims.ProfileVersion != ProfileVersion {
		return identitypolicy.VerifiedGrantV2{}, ErrUnsupportedVersion
	}
	if claims.LegacyType != "" || claims.LegacyVersion != "" {
		return identitypolicy.VerifiedGrantV2{}, ErrInvalidTokenType
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedGrantV2{}, ErrMissingJWTID
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return identitypolicy.VerifiedGrantV2{}, ErrMissingSubject
	}
	if strings.TrimSpace(claims.Confirmation.KeyID) == "" {
		return identitypolicy.VerifiedGrantV2{}, ErrMissingConfirmationKey
	}
	if claims.IssuedAt == nil {
		return identitypolicy.VerifiedGrantV2{}, ErrMissingIssuedAt
	}
	if err := claims.validateIdentityGrantDecisionStringsV2(); err != nil {
		return identitypolicy.VerifiedGrantV2{}, err
	}
	for _, value := range []string{claims.TargetResource, claims.TargetOperation} {
		if err := requireGrantTargetV2(value); err != nil {
			return identitypolicy.VerifiedGrantV2{}, err
		}
	}

	values := identitypolicy.Values{
		Service:              claims.Service,
		Tenant:               claims.Tenant,
		Deployment:           claims.Deployment,
		Environment:          claims.Environment,
		Workload:             claims.Workload,
		Agent:                claims.Agent,
		AgentPublicKey:       claims.AgentPublicKey,
		ComputationID:        claims.ComputationID,
		TaskID:               claims.TaskID,
		ThreadID:             claims.ThreadID,
		DelegationID:         claims.DelegationID,
		IntentRef:            claims.IntentRef,
		CapabilityRef:        claims.CapabilityRef,
		OntologyID:           claims.OntologyID,
		Scopes:               grantScopesV2(claims.Scopes, claims.Scope),
		Resources:            grantResourcesV2(claims.Resources, claims.Resource),
		AuthorizationDetails: claims.AuthorizationDetails,
	}
	if values.Agent == "" {
		values.Agent = claims.Subject
	}

	return identitypolicy.VerifiedGrantV2{
		VerifiedGrant: identitypolicy.VerifiedGrant{
			JWTID:                  claims.ID,
			Issuer:                 claims.Issuer,
			IssuerKey:              signerKey,
			Audience:               opts.ExpectedAudience,
			GrantHash:              IdentityGrantHash(tokenString),
			Values:                 values,
			ConfirmationKey:        claims.Confirmation.KeyID,
			AuthorizedEndpointKeys: claims.EndpointKeyIDs,
			IssuedAt:               claimTime(claims.IssuedAt),
			ExpiresAt:              claimTime(claims.ExpiresAt),
		},
		Target: identitypolicy.TargetV2{
			Resource:  claims.TargetResource,
			Operation: claims.TargetOperation,
		},
	}, nil
}

// VerifySessionBindingJWTV2 verifies the exact protected-header, payload, and
// canonical claim encodings selected by the experimental draft-06 profile.
func VerifySessionBindingJWTV2(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedSessionBindingStatementV2, error) {
	if err := ValidateJWTVerifyOptions(opts); err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}
	if err := validateJWTV2Wire(tokenString, opts, SessionBindingJWTTypeV2, v2ProofPayloadMembers, false); err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}

	claims, signerKey, err := parseBindingJWT(tokenString, opts)
	if err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}
	if claims.ProfileType != TokenTypeSessionBinding {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, ErrInvalidTokenType
	}
	if claims.ProfileVersion != ProfileVersionV2 {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, ErrUnsupportedVersion
	}
	if claims.LegacyType != "" || claims.LegacyVersion != "" {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, ErrInvalidTokenType
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, ErrMissingJWTID
	}
	if claims.IssuedAt == nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, ErrMissingIssuedAt
	}
	if err := claims.requireSessionBindingFieldsV2(); err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}
	if err := claims.validateSessionProofDecisionStringsV2(); err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}
	for _, value := range []string{
		claims.GrantHash,
		claims.AcceptedEndpointSPKISHA256,
		claims.TLSExporter,
		claims.BindingContextSHA256,
	} {
		if err := requireCanonicalSHA256(value); err != nil {
			return identitypolicy.VerifiedSessionBindingStatementV2{}, err
		}
	}
	if claims.AttestationBind != "" {
		if err := requireCanonicalSHA256(claims.AttestationBind); err != nil {
			return identitypolicy.VerifiedSessionBindingStatementV2{}, err
		}
	}
	if err := requireCanonicalBase64URL(claims.VerifierNonce, 16); err != nil {
		return identitypolicy.VerifiedSessionBindingStatementV2{}, err
	}
	if claims.AttemptID != "" {
		if err := requireCanonicalBase64URL(claims.AttemptID, 1); err != nil {
			return identitypolicy.VerifiedSessionBindingStatementV2{}, err
		}
	}

	return identitypolicy.VerifiedSessionBindingStatementV2{
		JWTID:     claims.ID,
		GrantHash: claims.GrantHash,
		Audience:  opts.ExpectedAudience,
		SignerKey: signerKey,
		Binding: identitypolicy.BindingV2{
			EndpointRole:               claims.EndpointRole,
			InteractionType:            claims.InteractionType,
			AcceptedEndpointSPKISHA256: claims.AcceptedEndpointSPKISHA256,
			TLSExporterSHA256:          claims.TLSExporter,
			BindingContextSHA256:       claims.BindingContextSHA256,
			AttestationBinderSHA256:    claims.AttestationBind,
			VerifierNonce:              claims.VerifierNonce,
			AttemptID:                  claims.AttemptID,
			IssuedAt:                   claimTime(claims.IssuedAt),
			ExpiresAt:                  claimTime(claims.ExpiresAt),
		},
	}, nil
}

// VerifySessionIdentityJWTV2 verifies the authority grant and session proof,
// compares the accepted binding, authenticates an attestation result when one
// is selected, evaluates D3-D7, and commits replay state last.
func VerifySessionIdentityJWTV2(grantToken, bindingToken string, opts SessionIdentityJWTOptionsV2) (SessionIdentityJWTResultV2, error) {
	if !opts.Policy.Enabled() {
		return SessionIdentityJWTResultV2{}, ErrMissingIdentityPolicy
	}
	if opts.ReplayCache == nil {
		return SessionIdentityJWTResultV2{}, ErrMissingReplayCache
	}

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	now := opts.Now
	if now.IsZero() {
		now = clock()
	}

	grantOpts := opts.Grant
	grantOpts.Now = now
	grant, err := VerifyIdentityGrantJWTV2(grantToken, grantOpts)
	if err != nil {
		return SessionIdentityJWTResultV2{}, err
	}

	bindingOpts := opts.SessionBinding
	bindingOpts.Now = now
	statement, err := VerifySessionBindingJWTV2(bindingToken, bindingOpts)
	if err != nil {
		return SessionIdentityJWTResultV2{}, err
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBindingV2(grant, statement, now)
	if err != nil {
		return SessionIdentityJWTResultV2{}, err
	}
	if err := identitypolicy.ValidateAcceptedBindingV2(statement.Binding, opts.ExpectedBinding, now); err != nil {
		return SessionIdentityJWTResultV2{}, err
	}
	attestationSelected := opts.AttestationVerifier != nil || opts.ExpectedBinding.AttestationBinderSHA256 != ""
	var attestationResult *identitypolicy.VerifiedAttestationResultV2
	if attestationSelected {
		if opts.ExpectedBinding.AttestationBinderSHA256 == "" || statement.Binding.AttestationBinderSHA256 == "" {
			return SessionIdentityJWTResultV2{}, ErrMissingAttestationBinder
		}
		if opts.AttestationVerifier == nil {
			return SessionIdentityJWTResultV2{}, ErrMissingAttestationVerifier
		}
		verifiedResult, err := opts.AttestationVerifier(grant, statement, opts.ExpectedBinding)
		if err != nil {
			return SessionIdentityJWTResultV2{}, fmt.Errorf("binding jwt v2: verify attestation: %w", err)
		}
		attestationResult = &verifiedResult
	}
	if opts.AcceptedProfile.ProfileType != TokenTypeSessionBinding || opts.AcceptedProfile.ProfileVersion != ProfileVersionV2 {
		return SessionIdentityJWTResultV2{}, ErrUnsupportedVersion
	}
	prepared, err := identitypolicy.PrepareAssertionV2(opts.Policy, assertion, opts.ExpectedBinding, now, identitypolicy.AcceptanceInputsV2{
		Profile:           opts.AcceptedProfile,
		Freshness:         opts.Freshness,
		AttestationResult: attestationResult,
	})
	if err != nil {
		return SessionIdentityJWTResultV2{}, err
	}
	accepted, err := identitypolicy.CommitPreparedAssertionV2(opts.ReplayCache, prepared, clock)
	if err != nil {
		return SessionIdentityJWTResultV2{}, err
	}

	return SessionIdentityJWTResultV2{
		Accepted: accepted,
	}, nil
}

var v2GrantPayloadMembers = stringSet(
	"iss", "sub", "aud", "jti", "iat", "exp", "nbf",
	ClaimTokenType, ClaimProfileVersion, "cnf", "authorized_endpoint_keys",
	"service", "tenant", "deployment", "environment", "workload", "agent",
	"agent_public_key", "computation_id", "task_id", "thread_id", "delegation_id",
	"intent_ref", "capability_ref", "ontology_id", "scope", "scopes", "resource",
	"resources", "authorization_details", "target_resource", "target_operation",
)

var v2ProofPayloadMembers = stringSet(
	"iss", "aud", "jti", "iat", "exp", ClaimTokenType, ClaimProfileVersion,
	"grant_hash", "endpoint_role", "interaction_type",
	"accepted_endpoint_spki_sha256", "tls_exporter_sha256",
	"binding_context_sha256", "verifier_nonce", "attempt_id",
	"attestation_binder_sha256",
)

var v2LegacyProfileMembers = stringSet(LegacyClaimTokenType, LegacyClaimProfileVersion)

func validateJWTV2Wire(tokenString string, opts JWTVerifyOptions, expectedType string, allowedPayload map[string]struct{}, allowUnknownPayload bool) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ErrInvalidJWTEncoding
	}
	decoded := make([][]byte, len(parts))
	for i, part := range parts {
		if part == "" || strings.Contains(part, "=") {
			return ErrInvalidJWTEncoding
		}
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != part {
			return ErrInvalidJWTEncoding
		}
		decoded[i] = raw
	}

	header, err := strictJSONObject(decoded[0])
	if err != nil {
		if errors.Is(err, ErrDuplicateJWTMember) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrInvalidProtectedHeader, err)
	}
	if len(header) != 3 {
		return ErrInvalidProtectedHeader
	}
	for name := range header {
		if name != "alg" && name != "kid" && name != "typ" {
			return ErrInvalidProtectedHeader
		}
	}
	alg, err := exactJSONString(header["alg"])
	if err != nil || alg == "" || alg != strings.TrimSpace(alg) {
		return ErrInvalidProtectedHeader
	}
	kid, err := exactJSONString(header["kid"])
	if err != nil || kid == "" || kid != strings.TrimSpace(kid) {
		return ErrInvalidProtectedHeader
	}
	typ, err := exactJSONString(header["typ"])
	if err != nil || typ != expectedType {
		return ErrInvalidProtectedHeader
	}
	if !listed(alg, opts.ValidMethods) {
		return ErrInvalidProtectedHeader
	}
	if err := requireDecisionStringV2(kid); err != nil {
		return ErrInvalidProtectedHeader
	}

	payload, err := strictJSONObject(decoded[1])
	if err != nil {
		if errors.Is(err, ErrDuplicateJWTMember) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrInvalidJWTMember, err)
	}
	for name := range payload {
		if _, forbidden := v2LegacyProfileMembers[name]; forbidden {
			return ErrInvalidJWTMember
		}
		if _, ok := allowedPayload[name]; ok {
			continue
		}
		if caseAliasesAny(name, allowedPayload) || caseAliasesAny(name, v2LegacyProfileMembers) || !allowUnknownPayload {
			return ErrInvalidJWTMember
		}
	}
	audience, err := exactJSONString(payload["aud"])
	if err != nil || audience == "" || audience != opts.ExpectedAudience {
		return ErrInvalidAudience
	}
	if err := requireDecisionStringV2(audience); err != nil {
		return ErrInvalidAudience
	}
	if allowUnknownPayload {
		if err := validateGrantAuthorizationWireV2(payload); err != nil {
			return err
		}
	}
	if cnfRaw, ok := payload["cnf"]; ok {
		confirmation, err := strictJSONObject(cnfRaw)
		if err != nil {
			return ErrInvalidJWTMember
		}
		for name := range confirmation {
			if name != "kid" && strings.EqualFold(name, "kid") {
				return ErrInvalidJWTMember
			}
		}
	}
	for _, name := range []string{"attempt_id", "attestation_binder_sha256"} {
		if raw, ok := payload[name]; ok {
			value, err := exactJSONString(raw)
			if err != nil || value == "" {
				return ErrInvalidClaimEncoding
			}
		}
	}
	return nil
}

func strictJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidJWTEncoding
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return nil, err
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, ErrInvalidJWTEncoding
	}
	return value, nil
}

func exactJSONString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", ErrInvalidClaimEncoding
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func caseAliasesAny(value string, allowed map[string]struct{}) bool {
	for candidate := range allowed {
		if value != candidate && strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func stringSet(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func requireCanonicalSHA256(value string) error {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return ErrInvalidClaimEncoding
	}
	hexValue := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(hexValue) != hexValue {
		return ErrInvalidClaimEncoding
	}
	decoded, err := hex.DecodeString(hexValue)
	if err != nil || len(decoded) != sha256.Size {
		return ErrInvalidClaimEncoding
	}
	return nil
}

func requireCanonicalBase64URL(value string, minimumBytes int) error {
	if value == "" || strings.Contains(value, "=") {
		return ErrInvalidClaimEncoding
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimumBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ErrInvalidClaimEncoding
	}
	return nil
}

func requireGrantTargetV2(value string) error {
	if strings.TrimSpace(value) == "" {
		return ErrMissingTargetField
	}
	return requireDecisionStringV2(value)
}

func (c bindingJWTClaims) validateIdentityGrantDecisionStringsV2() error {
	for _, value := range []string{
		c.Issuer, c.Subject, c.ID, c.Confirmation.KeyID,
		c.Service, c.Tenant, c.Deployment, c.Environment, c.Workload, c.Agent,
		c.AgentPublicKey, c.ComputationID, c.TaskID, c.ThreadID, c.DelegationID,
		c.IntentRef, c.CapabilityRef, c.OntologyID, c.TargetResource, c.TargetOperation,
	} {
		if value == "" {
			continue
		}
		if err := requireDecisionStringV2(value); err != nil {
			return err
		}
	}
	for _, values := range [][]string{c.EndpointKeyIDs, c.Scopes, c.Resources, c.AuthorizationDetails} {
		for _, value := range values {
			if value == "" {
				return ErrInvalidClaimEncoding
			}
			if err := requireDecisionStringV2(value); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c bindingJWTClaims) validateSessionProofDecisionStringsV2() error {
	for _, value := range []string{c.Issuer, c.ID, c.EndpointRole, c.InteractionType} {
		if err := requireDecisionStringV2(value); err != nil {
			return err
		}
	}
	return nil
}

func validateGrantAuthorizationWireV2(payload map[string]json.RawMessage) error {
	for _, pair := range [][2]string{{"scope", "scopes"}, {"resource", "resources"}} {
		_, singular := payload[pair[0]]
		_, plural := payload[pair[1]]
		if singular && plural {
			return ErrInvalidClaimEncoding
		}
	}
	if raw, ok := payload["scope"]; ok {
		value, err := exactJSONString(raw)
		if err != nil || value == "" {
			return ErrInvalidClaimEncoding
		}
		parts := strings.Split(value, " ")
		for _, part := range parts {
			if part == "" {
				return ErrInvalidClaimEncoding
			}
			for _, r := range part {
				if unicode.IsSpace(r) {
					return ErrInvalidClaimEncoding
				}
			}
			if err := requireDecisionStringV2(part); err != nil {
				return err
			}
		}
	}
	if raw, ok := payload["resource"]; ok {
		value, err := exactJSONString(raw)
		if err != nil || value == "" {
			return ErrInvalidClaimEncoding
		}
		if err := requireDecisionStringV2(value); err != nil {
			return err
		}
	}
	return nil
}

func grantScopesV2(values []string, scope string) []string {
	if scope != "" {
		return strings.Split(scope, " ")
	}
	return append([]string(nil), values...)
}

func grantResourcesV2(values []string, resource string) []string {
	if resource != "" {
		return []string{resource}
	}
	return append([]string(nil), values...)
}

func requireDecisionStringV2(value string) error {
	if value == "" || len(value) > identitypolicy.MaxValueLength || !utf8.ValidString(value) {
		return ErrInvalidClaimEncoding
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError || r == '<' || r == '>' {
			return ErrInvalidClaimEncoding
		}
	}
	return nil
}

func (c bindingJWTClaims) requireSessionBindingFieldsV2() error {
	if c.GrantHash == "" {
		return ErrMissingGrantHash
	}
	for _, value := range []string{
		c.EndpointRole,
		c.InteractionType,
		c.AcceptedEndpointSPKISHA256,
		c.TLSExporter,
		c.BindingContextSHA256,
		c.VerifierNonce,
	} {
		if value == "" {
			return ErrMissingBindingField
		}
	}
	return nil
}

func parseBindingJWT(tokenString string, opts JWTVerifyOptions) (*bindingJWTClaims, string, error) {
	if err := rejectDuplicateJWTMembers(tokenString); err != nil {
		return nil, "", err
	}

	parserOpts, err := jwtParserOptions(opts)
	if err != nil {
		return nil, "", err
	}
	keyFunc, err := verificationKeyFunc(opts)
	if err != nil {
		return nil, "", err
	}

	var signerKey string
	claims := &bindingJWTClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		keyID, err := tokenKeyID(token)
		if err != nil {
			return nil, err
		}
		signerKey = keyID
		return keyFunc(keyID)
	}, parserOpts...)
	if err != nil {
		return nil, "", fmt.Errorf("binding jwt: verify: %w", err)
	}
	if !token.Valid {
		return nil, "", errors.New("binding jwt: invalid token")
	}
	if listed(claims.ID, opts.RevokedJWTIDs) {
		return nil, "", ErrRevokedJWTID
	}
	return claims, signerKey, nil
}

func jwtParserOptions(opts JWTVerifyOptions) ([]jwt.ParserOption, error) {
	if opts.KeyFunc == nil && len(opts.LocalKeys) == 0 {
		return nil, ErrMissingKeyFunc
	}
	if opts.KeyFunc != nil && len(opts.LocalKeys) > 0 {
		return nil, ErrAmbiguousKeySource
	}
	if len(opts.ValidMethods) == 0 {
		return nil, ErrMissingValidMethods
	}
	for _, method := range opts.ValidMethods {
		method = strings.TrimSpace(method)
		if method == "" || strings.EqualFold(method, jwt.SigningMethodNone.Alg()) {
			return nil, ErrUnsafeSigningMethod
		}
	}
	if strings.TrimSpace(opts.ExpectedIssuer) == "" {
		return nil, ErrMissingExpectedIssuer
	}
	if strings.TrimSpace(opts.ExpectedAudience) == "" {
		return nil, ErrMissingExpectedAudience
	}
	if opts.ClockSkew < 0 {
		return nil, ErrInvalidClockSkew
	}

	out := []jwt.ParserOption{
		jwt.WithValidMethods(opts.ValidMethods),
		jwt.WithIssuer(opts.ExpectedIssuer),
		jwt.WithAudience(opts.ExpectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if opts.ClockSkew > 0 {
		out = append(out, jwt.WithLeeway(opts.ClockSkew))
	}
	if !opts.Now.IsZero() {
		out = append(out, jwt.WithTimeFunc(func() time.Time {
			return opts.Now
		}))
	}
	return out, nil
}

func verificationKeyFunc(opts JWTVerifyOptions) (KeyFunc, error) {
	disabled := set(opts.DisabledKeyIDs)
	if opts.KeyFunc != nil {
		return func(keyID string) (interface{}, error) {
			keyID = strings.TrimSpace(keyID)
			if disabled[keyID] {
				return nil, ErrDisabledKeyID
			}
			return opts.KeyFunc(keyID)
		}, nil
	}

	keys := make(map[string]interface{}, len(opts.LocalKeys))
	for _, localKey := range opts.LocalKeys {
		keyID := strings.TrimSpace(localKey.KeyID)
		if keyID == "" {
			return nil, ErrMissingKeyID
		}
		if _, exists := keys[keyID]; exists {
			return nil, ErrDuplicateKeyID
		}
		if localKey.Key == nil {
			return nil, ErrMissingLocalKey
		}
		if localKey.Disabled {
			disabled[keyID] = true
		}
		keys[keyID] = localKey.Key
	}

	return func(keyID string) (interface{}, error) {
		keyID = strings.TrimSpace(keyID)
		if disabled[keyID] {
			return nil, ErrDisabledKeyID
		}
		key, ok := keys[keyID]
		if !ok {
			return nil, ErrUnknownKeyID
		}
		return key, nil
	}, nil
}

func tokenKeyID(token *jwt.Token) (string, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return "", ErrMissingKeyID
	}
	return strings.TrimSpace(keyID), nil
}

func (c bindingJWTClaims) requireProfile(expected string) error {
	if !profileValueMatches(c.ProfileType, expected) {
		return ErrInvalidTokenType
	}
	if !legacyProfileValueMatches(c.LegacyType, expected) {
		return ErrInvalidTokenType
	}
	if !profileVersionMatches(c.ProfileVersion) || !profileVersionMatches(c.LegacyVersion) {
		return ErrUnsupportedVersion
	}
	if strings.TrimSpace(c.ProfileType) == "" && strings.TrimSpace(c.LegacyType) == "" {
		return ErrInvalidTokenType
	}
	if strings.TrimSpace(c.ProfileVersion) == "" && strings.TrimSpace(c.LegacyVersion) == "" {
		return ErrUnsupportedVersion
	}
	return nil
}

func (c bindingJWTClaims) requireSessionBindingFields() error {
	if strings.TrimSpace(c.GrantHash) == "" {
		return ErrMissingGrantHash
	}
	required := []string{
		c.LeafKeySHA256,
		c.TLSExporter,
		c.RequestContext,
		c.Nonce,
	}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return ErrMissingBindingField
		}
	}
	return nil
}

func profileValueMatches(value, expected string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == expected
}

func legacyProfileValueMatches(value, expected string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if value == expected {
		return true
	}
	switch expected {
	case TokenTypeIdentityGrant:
		return value == LegacyTokenTypeIdentityGrant
	case TokenTypeSessionBinding:
		return value == LegacyTokenTypeSessionBinding
	default:
		return false
	}
}

func profileVersionMatches(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || value == ProfileVersion
}

func claimTime(value *jwt.NumericDate) time.Time {
	if value == nil {
		return time.Time{}
	}
	return value.Time
}

func withSpaceSeparatedValues(values []string, spaceSeparated string) []string {
	if strings.TrimSpace(spaceSeparated) == "" {
		return values
	}
	out := append([]string{}, values...)
	out = append(out, strings.Fields(spaceSeparated)...)
	return out
}

func listed(value string, values []string) bool {
	return set(values)[strings.TrimSpace(value)]
}

func set(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func rejectDuplicateJWTMembers(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	for _, part := range parts[:2] {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil
		}
		if err := rejectDuplicateJSONMembers(raw); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONMembers(raw []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("binding jwt: trailing json data")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONObjectMembers(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			member, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := member.(string)
			if !ok {
				return errors.New("binding jwt: non-string json object key")
			}
			if _, ok := seen[name]; ok {
				return ErrDuplicateJWTMember
			}
			seen[name] = struct{}{}
			if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectDuplicateJSONObjectMembers(dec); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token()
	return err
}
