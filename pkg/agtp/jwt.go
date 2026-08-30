// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package agtp contains experimental reference adapters for legacy AGTP-named
// JWT/JWS and CWT/COSE wire-token experiments.
//
// Direct-Agent runtime clients do not depend on this package. Production
// verifier code should treat these helpers as reference adapters around the
// core identity-policy acceptance rules, not as the repository's core runtime
// binding implementation.
package agtp

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

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingKeyFunc          = errors.New("agtp: missing JWT key function")
	ErrMissingLocalKey         = errors.New("agtp: missing local JWT key")
	ErrMissingValidMethods     = errors.New("agtp: missing allowed JWT signing methods")
	ErrMissingExpectedIssuer   = errors.New("agtp: missing expected issuer")
	ErrMissingExpectedAudience = errors.New("agtp: missing expected audience")
	ErrMissingConfirmationKey  = errors.New("agtp: missing confirmation key")
	ErrMissingKeyID            = errors.New("agtp: missing JWT key id")
	ErrUnknownKeyID            = errors.New("agtp: unknown JWT key id")
	ErrDisabledKeyID           = errors.New("agtp: disabled JWT key id")
	ErrDuplicateKeyID          = errors.New("agtp: duplicate JWT key id")
	ErrAmbiguousKeySource      = errors.New("agtp: ambiguous JWT key source")
	ErrMissingJWTID            = errors.New("agtp: missing JWT id")
	ErrRevokedJWTID            = errors.New("agtp: revoked JWT id")
	ErrMissingSubject          = errors.New("agtp: missing subject")
	ErrMissingIdentityGrant    = errors.New("agtp: missing identity grant")
	ErrMissingGrantHash        = errors.New("agtp: missing grant hash")
	ErrMissingBindingField     = errors.New("agtp: missing session binding field")
	ErrMissingIdentityPolicy   = errors.New("agtp: missing identity policy")
	ErrMissingReplayCache      = errors.New("agtp: missing replay cache")
	ErrInvalidTokenType        = errors.New("agtp: invalid token type")
	ErrUnsupportedVersion      = errors.New("agtp: unsupported profile version")
	ErrUnsafeSigningMethod     = errors.New("agtp: unsafe JWT signing method")
	ErrDuplicateJWTMember      = errors.New("agtp: duplicate JWT JSON member")
)

const (
	ClaimTokenType      = "profile_type"
	ClaimProfileVersion = "profile_version"

	LegacyClaimTokenType      = "agtp_type"
	LegacyClaimProfileVersion = "agtp_version"

	TokenTypeIdentityGrant   = "sbaip.identity-grant"
	TokenTypeSessionBinding  = "sbaip.session-binding"
	TokenTypeSessionEnvelope = "sbaip.session-envelope"

	LegacyTokenTypeIdentityGrant   = "agtp.identity-grant"
	LegacyTokenTypeSessionBinding  = "agtp.session-binding"
	LegacyTokenTypeSessionEnvelope = "agtp.session-envelope"

	ProfileVersion           = "1"
	identityGrantJWTHashSeed = "sbaip.identity-grant.jwt.v1\x00"
)

// KeyFunc resolves a JWT verification key by protected-header key id. Callers
// that use KeyFunc own the key namespace: issuer, audience, key use, algorithm,
// key status, and public-key identity must be enforced outside the bare kid.
type KeyFunc func(keyID string) (interface{}, error)

// LocalKey is a locally configured JWT verification key.
type LocalKey struct {
	KeyID    string
	Key      interface{}
	Disabled bool
}

// JWTVerifyOptions contains local verification policy for AGTP JWT/JWS tokens.
type JWTVerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ValidMethods     []string
	KeyFunc          KeyFunc
	LocalKeys        []LocalKey
	DisabledKeyIDs   []string
	RevokedJWTIDs    []string
	Now              time.Time
}

// SessionIdentityJWTOptions contains all local policy needed to verify a
// Manager-issued grant, an Agent-issued session binding, and the local expected
// identity policy in one acceptance step.
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

// ValidateJWTVerifyOptions checks local JWT verification policy before a
// connection attempt uses it.
func ValidateJWTVerifyOptions(opts JWTVerifyOptions) error {
	if _, err := parserOptions(opts); err != nil {
		return err
	}
	_, err := keyFuncForOptions(opts)
	return err
}

type confirmationClaim struct {
	KeyID string `json:"kid,omitempty"`
}

type profileClaims struct {
	TokenType            string `json:"profile_type,omitempty"`
	ProfileVersion       string `json:"profile_version,omitempty"`
	LegacyTokenType      string `json:"agtp_type,omitempty"`
	LegacyProfileVersion string `json:"agtp_version,omitempty"`
}

type identityGrantClaims struct {
	jwt.RegisteredClaims
	profileClaims

	ConfirmationKey        confirmationClaim `json:"cnf,omitempty"`
	AuthorizedEndpointKeys []string          `json:"authorized_endpoint_keys,omitempty"`

	Service     string `json:"service,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
	Deployment  string `json:"deployment,omitempty"`
	Environment string `json:"environment,omitempty"`

	Workload       string `json:"workload,omitempty"`
	Agent          string `json:"agent,omitempty"`
	AgentPublicKey string `json:"agent_public_key,omitempty"`

	ComputationID string `json:"computation_id,omitempty"`
	TaskID        string `json:"task_id,omitempty"`
	ThreadID      string `json:"thread_id,omitempty"`
	DelegationID  string `json:"delegation_id,omitempty"`
	IntentRef     string `json:"intent_ref,omitempty"`
	CapabilityRef string `json:"capability_ref,omitempty"`
	OntologyID    string `json:"ontology_id,omitempty"`

	Scope                string   `json:"scope,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	Resources            []string `json:"resources,omitempty"`
	AuthorizationDetails []string `json:"authorization_details,omitempty"`
}

type sessionBindingClaims struct {
	jwt.RegisteredClaims
	profileClaims

	GrantHash               string `json:"grant_hash,omitempty"`
	LeafPublicKeySHA256     string `json:"leaf_public_key_sha256,omitempty"`
	TLSExporterSHA256       string `json:"tls_exporter_sha256,omitempty"`
	RequestContextSHA256    string `json:"request_context_sha256,omitempty"`
	AttestationBinderSHA256 string `json:"attestation_binder_sha256,omitempty"`
	Nonce                   string `json:"nonce,omitempty"`
}

type sessionEnvelopeClaims struct {
	jwt.RegisteredClaims
	profileClaims

	IdentityGrantJWT string `json:"identity_grant_jwt,omitempty"`

	GrantHash               string `json:"grant_hash,omitempty"`
	LeafPublicKeySHA256     string `json:"leaf_public_key_sha256,omitempty"`
	TLSExporterSHA256       string `json:"tls_exporter_sha256,omitempty"`
	RequestContextSHA256    string `json:"request_context_sha256,omitempty"`
	AttestationBinderSHA256 string `json:"attestation_binder_sha256,omitempty"`
	Nonce                   string `json:"nonce,omitempty"`
}

// IdentityGrantHash returns the domain-separated hash of the exact signed grant
// bytes. The same value is carried by the session binding statement.
func IdentityGrantHash(tokenString string) string {
	sum := sha256.Sum256([]byte(identityGrantJWTHashSeed + tokenString))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyIdentityGrantJWT verifies an AGTP Identity Grant encoded as JWT/JWS and
// converts it into the internal identitypolicy grant type.
func VerifyIdentityGrantJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedGrant, error) {
	claims := &identityGrantClaims{}
	_, signerKey, err := parseJWT(tokenString, claims, opts)
	if err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if err := validateProfileClaims(claims.profileClaims, TokenTypeIdentityGrant); err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingJWTID
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingSubject
	}

	confirmationKey := claims.ConfirmationKey.KeyID
	if strings.TrimSpace(confirmationKey) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingConfirmationKey
	}

	audience := opts.ExpectedAudience
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
		Scopes:               appendScopeValues(claims.Scopes, claims.Scope),
		Resources:            appendScopeValues(claims.Resources, claims.Resource),
		AuthorizationDetails: claims.AuthorizationDetails,
	}
	if values.Agent == "" {
		values.Agent = claims.Subject
	}

	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}

	return identitypolicy.VerifiedGrant{
		Issuer:                 claims.Issuer,
		IssuerKey:              signerKey,
		Audience:               audience,
		GrantHash:              IdentityGrantHash(tokenString),
		Values:                 values,
		ConfirmationKey:        confirmationKey,
		AuthorizedEndpointKeys: claims.AuthorizedEndpointKeys,
		IssuedAt:               issuedAt,
		ExpiresAt:              claims.ExpiresAt.Time,
	}, nil
}

// VerifySessionBindingJWT verifies an AGTP Session Binding Statement encoded as
// JWT/JWS and converts it into the internal identitypolicy statement type.
func VerifySessionBindingJWT(tokenString string, opts JWTVerifyOptions) (identitypolicy.VerifiedSessionBindingStatement, error) {
	claims := &sessionBindingClaims{}
	_, signerKey, err := parseJWT(tokenString, claims, opts)
	if err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if err := validateProfileClaims(claims.profileClaims, TokenTypeSessionBinding); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return identitypolicy.VerifiedSessionBindingStatement{}, ErrMissingJWTID
	}
	if err := validateSessionBindingClaims(claims); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}

	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}

	return identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: claims.GrantHash,
		Audience:  opts.ExpectedAudience,
		SignerKey: signerKey,
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:     claims.LeafPublicKeySHA256,
			TLSExporterSHA256:       claims.TLSExporterSHA256,
			RequestContextSHA256:    claims.RequestContextSHA256,
			AttestationBinderSHA256: claims.AttestationBinderSHA256,
			Nonce:                   claims.Nonce,
			IssuedAt:                issuedAt,
			ExpiresAt:               claims.ExpiresAt.Time,
		},
	}, nil
}

// VerifySessionIdentityJWTEnvelope verifies a single-envelope JWT/JWS transport
// profile. The outer envelope is signed by the Agent binding key and carries
// the exact inner Manager-signed Identity Grant JWT plus the session-binding
// fields for that grant. Both signatures and the grant_hash link are required.
func VerifySessionIdentityJWTEnvelope(envelopeToken string, opts SessionIdentityJWTOptions) (SessionIdentityJWTResult, error) {
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

	bindingOpts := opts.SessionBinding
	bindingOpts.Now = now
	claims := &sessionEnvelopeClaims{}
	_, signerKey, err := parseJWT(envelopeToken, claims, bindingOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if err := validateProfileClaims(claims.profileClaims, TokenTypeSessionEnvelope); err != nil {
		return SessionIdentityJWTResult{}, err
	}
	if strings.TrimSpace(claims.ID) == "" {
		return SessionIdentityJWTResult{}, ErrMissingJWTID
	}
	if strings.TrimSpace(claims.IdentityGrantJWT) == "" {
		return SessionIdentityJWTResult{}, ErrMissingIdentityGrant
	}
	if err := validateSessionBindingClaims(claims.sessionBindingClaims()); err != nil {
		return SessionIdentityJWTResult{}, err
	}

	grantOpts := opts.Grant
	grantOpts.Now = now
	grant, err := VerifyIdentityGrantJWT(claims.IdentityGrantJWT, grantOpts)
	if err != nil {
		return SessionIdentityJWTResult{}, err
	}

	statement := claims.verifiedStatement(signerKey, bindingOpts.ExpectedAudience)
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

// VerifySessionIdentityJWT verifies the complete initial AGTP JWT/JWS profile:
// a locally trusted Identity Grant, a session-binding statement authorized by
// that grant, the accepted TLS session binding, and local expected policy.
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

func parseJWT(tokenString string, claims jwt.Claims, opts JWTVerifyOptions) (*jwt.Token, string, error) {
	parserOpts, err := parserOptions(opts)
	if err != nil {
		return nil, "", err
	}
	keyFunc, err := keyFuncForOptions(opts)
	if err != nil {
		return nil, "", err
	}
	if err := rejectDuplicateJWTJSONMembers(tokenString); err != nil {
		return nil, "", err
	}

	var signerKey string
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		keyID, err := keyIDFromToken(token)
		if err != nil {
			return nil, err
		}
		signerKey = keyID
		return keyFunc(keyID)
	}, parserOpts...)
	if err != nil {
		return nil, "", fmt.Errorf("agtp: verify JWT: %w", err)
	}
	if !token.Valid {
		return nil, "", errors.New("agtp: invalid JWT")
	}
	if isListed(jwtIDFromClaims(claims), opts.RevokedJWTIDs) {
		return nil, "", ErrRevokedJWTID
	}
	return token, signerKey, nil
}

func rejectDuplicateJWTJSONMembers(tokenString string) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	for _, part := range parts[:2] {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil
		}
		if err := rejectDuplicateJSONMembers(data); err != nil {
			return err
		}
	}
	return nil
}

func rejectDuplicateJSONMembers(data []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := rejectDuplicateJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("agtp: trailing JWT JSON data")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("agtp: invalid JWT JSON object key")
			}
			if _, ok := seen[key]; ok {
				return ErrDuplicateJWTMember
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateJSONValue(dec); err != nil {
				return err
			}
		}
	case '[':
		for dec.More() {
			if err := rejectDuplicateJSONValue(dec); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = dec.Token()
	return err
}

func parserOptions(opts JWTVerifyOptions) ([]jwt.ParserOption, error) {
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
		if strings.TrimSpace(method) == "" || strings.EqualFold(method, jwt.SigningMethodNone.Alg()) {
			return nil, ErrUnsafeSigningMethod
		}
	}
	if strings.TrimSpace(opts.ExpectedIssuer) == "" {
		return nil, ErrMissingExpectedIssuer
	}
	if strings.TrimSpace(opts.ExpectedAudience) == "" {
		return nil, ErrMissingExpectedAudience
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(opts.ValidMethods),
		jwt.WithIssuer(opts.ExpectedIssuer),
		jwt.WithAudience(opts.ExpectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}
	if !opts.Now.IsZero() {
		parserOpts = append(parserOpts, jwt.WithTimeFunc(func() time.Time {
			return opts.Now
		}))
	}
	return parserOpts, nil
}

func keyFuncForOptions(opts JWTVerifyOptions) (KeyFunc, error) {
	disabled := stringSet(opts.DisabledKeyIDs)
	if opts.KeyFunc != nil {
		return func(keyID string) (interface{}, error) {
			if disabled[strings.TrimSpace(keyID)] {
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
		if _, ok := keys[keyID]; ok {
			return nil, ErrDuplicateKeyID
		}
		if localKey.Disabled {
			disabled[keyID] = true
		}
		if localKey.Key == nil {
			return nil, ErrMissingLocalKey
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

func validateProfileClaims(claims profileClaims, expectedType string) error {
	if !profileTypeMatches(strings.TrimSpace(claims.TokenType), expectedType, false) {
		return ErrInvalidTokenType
	}
	if !profileVersionMatches(strings.TrimSpace(claims.ProfileVersion)) {
		return ErrUnsupportedVersion
	}
	if !profileTypeMatches(strings.TrimSpace(claims.LegacyTokenType), expectedType, true) {
		return ErrInvalidTokenType
	}
	if !profileVersionMatches(strings.TrimSpace(claims.LegacyProfileVersion)) {
		return ErrUnsupportedVersion
	}
	if strings.TrimSpace(claims.TokenType) == "" && strings.TrimSpace(claims.LegacyTokenType) == "" {
		return ErrInvalidTokenType
	}
	if strings.TrimSpace(claims.ProfileVersion) == "" && strings.TrimSpace(claims.LegacyProfileVersion) == "" {
		return ErrUnsupportedVersion
	}
	return nil
}

func profileTypeMatches(value, expectedType string, allowLegacyValue bool) bool {
	if value == "" {
		return true
	}
	if value == expectedType {
		return true
	}
	return allowLegacyValue && value == legacyTokenType(expectedType)
}

func profileVersionMatches(value string) bool {
	return value == "" || value == ProfileVersion
}

func legacyTokenType(tokenType string) string {
	switch tokenType {
	case TokenTypeIdentityGrant:
		return LegacyTokenTypeIdentityGrant
	case TokenTypeSessionBinding:
		return LegacyTokenTypeSessionBinding
	case TokenTypeSessionEnvelope:
		return LegacyTokenTypeSessionEnvelope
	default:
		return ""
	}
}

func validateSessionBindingClaims(claims *sessionBindingClaims) error {
	if strings.TrimSpace(claims.GrantHash) == "" {
		return ErrMissingGrantHash
	}
	for _, value := range []string{
		claims.LeafPublicKeySHA256,
		claims.TLSExporterSHA256,
		claims.RequestContextSHA256,
		claims.Nonce,
	} {
		if strings.TrimSpace(value) == "" {
			return ErrMissingBindingField
		}
	}
	return nil
}

func keyIDFromToken(token *jwt.Token) (string, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok || strings.TrimSpace(keyID) == "" {
		return "", ErrMissingKeyID
	}
	return keyID, nil
}

func jwtIDFromClaims(claims jwt.Claims) string {
	switch c := claims.(type) {
	case *identityGrantClaims:
		return c.ID
	case *sessionBindingClaims:
		return c.ID
	case *sessionEnvelopeClaims:
		return c.ID
	case *gatewayRouteAssertionClaims:
		return c.ID
	default:
		return ""
	}
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func isListed(value string, values []string) bool {
	return stringSet(values)[strings.TrimSpace(value)]
}

func appendScopeValues(values []string, spaceSeparated string) []string {
	if strings.TrimSpace(spaceSeparated) == "" {
		return values
	}
	out := append([]string{}, values...)
	out = append(out, strings.Fields(spaceSeparated)...)
	return out
}

func (c *sessionEnvelopeClaims) sessionBindingClaims() *sessionBindingClaims {
	return &sessionBindingClaims{
		GrantHash:               c.GrantHash,
		LeafPublicKeySHA256:     c.LeafPublicKeySHA256,
		TLSExporterSHA256:       c.TLSExporterSHA256,
		RequestContextSHA256:    c.RequestContextSHA256,
		AttestationBinderSHA256: c.AttestationBinderSHA256,
		Nonce:                   c.Nonce,
	}
}

func (c *sessionEnvelopeClaims) verifiedStatement(signerKey, audience string) identitypolicy.VerifiedSessionBindingStatement {
	var issuedAt time.Time
	if c.IssuedAt != nil {
		issuedAt = c.IssuedAt.Time
	}
	return identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: c.GrantHash,
		Audience:  audience,
		SignerKey: signerKey,
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:     c.LeafPublicKeySHA256,
			TLSExporterSHA256:       c.TLSExporterSHA256,
			RequestContextSHA256:    c.RequestContextSHA256,
			AttestationBinderSHA256: c.AttestationBinderSHA256,
			Nonce:                   c.Nonce,
			IssuedAt:                issuedAt,
			ExpiresAt:               c.ExpiresAt.Time,
		},
	}
}
