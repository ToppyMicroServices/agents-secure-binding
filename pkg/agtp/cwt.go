// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrMissingCOSEAlgorithms = errors.New("agtp: missing allowed COSE algorithms")
	ErrUnsafeCOSEAlgorithm   = errors.New("agtp: unsafe COSE algorithm")
	ErrUnprotectedKeyID      = errors.New("agtp: COSE key id must be protected")
	ErrMissingCWTID          = errors.New("agtp: missing CWT id")
	ErrRevokedCWTID          = errors.New("agtp: revoked CWT id")
	ErrInvalidIssuer         = errors.New("agtp: invalid issuer")
	ErrInvalidAudience       = errors.New("agtp: invalid audience")
	ErrMissingExpiration     = errors.New("agtp: missing expiration time")
	ErrMissingIssuedAt       = errors.New("agtp: missing issued-at time")
	ErrExpiredToken          = errors.New("agtp: expired token")
	ErrFutureToken           = errors.New("agtp: token issued in the future")
)

const identityGrantCWTHashSeed = "sbaip.identity-grant.cwt.v1\x00"

// CWTKeyFunc resolves a COSE verification key by protected-header key id.
// Callers that use CWTKeyFunc own the key namespace: issuer, audience, key use,
// algorithm, key status, and public-key identity must be enforced outside the
// bare kid.
type CWTKeyFunc func(keyID string) (interface{}, error)

// CWTLocalKey is a locally configured COSE verification key.
type CWTLocalKey struct {
	KeyID    string
	Key      interface{}
	Disabled bool
}

// CWTVerifyOptions contains local verification policy for AGTP CWT/COSE
// tokens.
type CWTVerifyOptions struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ValidAlgorithms  []cose.Algorithm
	KeyFunc          CWTKeyFunc
	LocalKeys        []CWTLocalKey
	DisabledKeyIDs   []string
	RevokedCWTIDs    []string
	Now              time.Time
}

// SessionIdentityCWTOptions contains all local policy needed to verify a
// Manager-issued CWT grant, an Agent-issued COSE session binding, and the local
// expected identity policy in one acceptance step.
type SessionIdentityCWTOptions struct {
	Grant           CWTVerifyOptions
	SessionBinding  CWTVerifyOptions
	Policy          identitypolicy.Policy
	ExpectedBinding identitypolicy.Binding
	ReplayCache     identitypolicy.ReplayCache
	Now             time.Time
}

// SessionIdentityCWTResult contains the verified identity material accepted by
// VerifySessionIdentityCWT.
type SessionIdentityCWTResult struct {
	Grant     identitypolicy.VerifiedGrant
	Statement identitypolicy.VerifiedSessionBindingStatement
	Assertion identitypolicy.Assertion
}

// ValidateCWTVerifyOptions checks local CWT/COSE verification policy before a
// connection attempt uses it.
func ValidateCWTVerifyOptions(opts CWTVerifyOptions) error {
	if err := validateCWTVerifyOptions(opts); err != nil {
		return err
	}
	_, err := cwtKeyFuncForOptions(opts)
	return err
}

// IdentityGrantCWTHash returns the domain-separated hash of the exact signed
// CWT/COSE grant bytes. The same value is carried by the session binding
// statement.
func IdentityGrantCWTHash(token []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(identityGrantCWTHashSeed))
	_, _ = h.Write(token)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// VerifyIdentityGrantCWT verifies an AGTP Identity Grant encoded as CWT/COSE
// and converts it into the internal identitypolicy grant type.
func VerifyIdentityGrantCWT(token []byte, opts CWTVerifyOptions) (identitypolicy.VerifiedGrant, error) {
	claims, signerKey, err := parseCWT(token, opts)
	if err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}
	if err := validateProfileClaims(cwtProfileClaims(claims), TokenTypeIdentityGrant); err != nil {
		return identitypolicy.VerifiedGrant{}, err
	}

	cwtID := cwtIDFromClaims(claims)
	if strings.TrimSpace(cwtID) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingCWTID
	}
	if isListed(cwtID, opts.RevokedCWTIDs) {
		return identitypolicy.VerifiedGrant{}, ErrRevokedCWTID
	}

	subject, _ := cwtStringClaim(claims, cose.CWTClaimSubject)
	if strings.TrimSpace(subject) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingSubject
	}

	confirmationKey := cwtConfirmationKey(claims)
	if strings.TrimSpace(confirmationKey) == "" {
		return identitypolicy.VerifiedGrant{}, ErrMissingConfirmationKey
	}

	issuedAt, _ := cwtTimeClaim(claims, cose.CWTClaimIssuedAt)
	expiresAt, _ := cwtTimeClaim(claims, cose.CWTClaimExpirationTime)
	issuer, _ := cwtStringClaim(claims, cose.CWTClaimIssuer)

	values := identitypolicy.Values{
		Service:              cwtStringClaimOrEmpty(claims, "service"),
		Tenant:               cwtStringClaimOrEmpty(claims, "tenant"),
		Deployment:           cwtStringClaimOrEmpty(claims, "deployment"),
		Environment:          cwtStringClaimOrEmpty(claims, "environment"),
		Workload:             cwtStringClaimOrEmpty(claims, "workload"),
		Agent:                cwtStringClaimOrEmpty(claims, "agent"),
		AgentPublicKey:       cwtStringClaimOrEmpty(claims, "agent_public_key"),
		ComputationID:        cwtStringClaimOrEmpty(claims, "computation_id"),
		TaskID:               cwtStringClaimOrEmpty(claims, "task_id"),
		ThreadID:             cwtStringClaimOrEmpty(claims, "thread_id"),
		DelegationID:         cwtStringClaimOrEmpty(claims, "delegation_id"),
		IntentRef:            cwtStringClaimOrEmpty(claims, "intent_ref"),
		CapabilityRef:        cwtStringClaimOrEmpty(claims, "capability_ref"),
		OntologyID:           cwtStringClaimOrEmpty(claims, "ontology_id"),
		Scopes:               appendScopeValues(cwtStringSliceClaim(claims, "scopes"), cwtStringClaimOrEmpty(claims, "scope")),
		Resources:            appendScopeValues(cwtStringSliceClaim(claims, "resources"), cwtStringClaimOrEmpty(claims, "resource")),
		AuthorizationDetails: cwtStringSliceClaim(claims, "authorization_details"),
	}
	if values.Agent == "" {
		values.Agent = subject
	}

	return identitypolicy.VerifiedGrant{
		Issuer:                 issuer,
		IssuerKey:              signerKey,
		Audience:               opts.ExpectedAudience,
		GrantHash:              IdentityGrantCWTHash(token),
		Values:                 values,
		ConfirmationKey:        confirmationKey,
		AuthorizedEndpointKeys: cwtStringSliceClaim(claims, "authorized_endpoint_keys"),
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt,
	}, nil
}

// VerifySessionBindingCWT verifies an AGTP Session Binding Statement encoded
// as CWT/COSE and converts it into the internal identitypolicy statement type.
func VerifySessionBindingCWT(token []byte, opts CWTVerifyOptions) (identitypolicy.VerifiedSessionBindingStatement, error) {
	claims, signerKey, err := parseCWT(token, opts)
	if err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}
	if err := validateProfileClaims(cwtProfileClaims(claims), TokenTypeSessionBinding); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}

	cwtID := cwtIDFromClaims(claims)
	if strings.TrimSpace(cwtID) == "" {
		return identitypolicy.VerifiedSessionBindingStatement{}, ErrMissingCWTID
	}
	if isListed(cwtID, opts.RevokedCWTIDs) {
		return identitypolicy.VerifiedSessionBindingStatement{}, ErrRevokedCWTID
	}

	issuedAt, _ := cwtTimeClaim(claims, cose.CWTClaimIssuedAt)
	expiresAt, _ := cwtTimeClaim(claims, cose.CWTClaimExpirationTime)
	bindingClaims := &sessionBindingClaims{
		GrantHash:               cwtStringClaimOrEmpty(claims, "grant_hash"),
		LeafPublicKeySHA256:     cwtStringClaimOrEmpty(claims, "leaf_public_key_sha256"),
		TLSExporterSHA256:       cwtStringClaimOrEmpty(claims, "tls_exporter_sha256"),
		RequestContextSHA256:    cwtStringClaimOrEmpty(claims, "request_context_sha256"),
		AttestationBinderSHA256: cwtStringClaimOrEmpty(claims, "attestation_binder_sha256"),
		Nonce:                   cwtStringClaimOrEmpty(claims, "nonce"),
	}
	if err := validateSessionBindingClaims(bindingClaims); err != nil {
		return identitypolicy.VerifiedSessionBindingStatement{}, err
	}

	return identitypolicy.VerifiedSessionBindingStatement{
		GrantHash: bindingClaims.GrantHash,
		Audience:  opts.ExpectedAudience,
		SignerKey: signerKey,
		Binding: identitypolicy.Binding{
			LeafPublicKeySHA256:     bindingClaims.LeafPublicKeySHA256,
			TLSExporterSHA256:       bindingClaims.TLSExporterSHA256,
			RequestContextSHA256:    bindingClaims.RequestContextSHA256,
			AttestationBinderSHA256: bindingClaims.AttestationBinderSHA256,
			Nonce:                   bindingClaims.Nonce,
			IssuedAt:                issuedAt,
			ExpiresAt:               expiresAt,
		},
	}, nil
}

// VerifySessionIdentityCWT verifies the complete initial AGTP CWT/COSE profile:
// a locally trusted Identity Grant, a session-binding statement authorized by
// that grant, the accepted TLS session binding, and local expected policy.
func VerifySessionIdentityCWT(grantToken, bindingToken []byte, opts SessionIdentityCWTOptions) (SessionIdentityCWTResult, error) {
	if !opts.Policy.Enabled() {
		return SessionIdentityCWTResult{}, ErrMissingIdentityPolicy
	}
	if opts.ReplayCache == nil {
		return SessionIdentityCWTResult{}, ErrMissingReplayCache
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	grantOpts := opts.Grant
	grantOpts.Now = now
	grant, err := VerifyIdentityGrantCWT(grantToken, grantOpts)
	if err != nil {
		return SessionIdentityCWTResult{}, err
	}

	bindingOpts := opts.SessionBinding
	bindingOpts.Now = now
	statement, err := VerifySessionBindingCWT(bindingToken, bindingOpts)
	if err != nil {
		return SessionIdentityCWTResult{}, err
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return SessionIdentityCWTResult{}, err
	}
	if err := opts.Policy.ValidateAssertion(assertion, opts.ExpectedBinding, now); err != nil {
		return SessionIdentityCWTResult{}, err
	}
	if err := identitypolicy.MarkSessionBindingUsed(opts.ReplayCache, statement); err != nil {
		return SessionIdentityCWTResult{}, err
	}

	return SessionIdentityCWTResult{
		Grant:     grant,
		Statement: statement,
		Assertion: assertion,
	}, nil
}

func parseCWT(token []byte, opts CWTVerifyOptions) (map[any]any, string, error) {
	if err := validateCWTVerifyOptions(opts); err != nil {
		return nil, "", err
	}
	keyFunc, err := cwtKeyFuncForOptions(opts)
	if err != nil {
		return nil, "", err
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		return nil, "", fmt.Errorf("agtp: decode COSE_Sign1: %w", err)
	}
	if _, ok := msg.Headers.Unprotected[cose.HeaderLabelKeyID]; ok {
		return nil, "", ErrUnprotectedKeyID
	}

	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, "", fmt.Errorf("agtp: missing COSE algorithm: %w", err)
	}
	if !allowedCOSEAlgorithm(alg, opts.ValidAlgorithms) {
		return nil, "", ErrUnsafeCOSEAlgorithm
	}

	keyID, err := keyIDFromCOSE(&msg)
	if err != nil {
		return nil, "", err
	}
	key, err := keyFunc(keyID)
	if err != nil {
		return nil, "", err
	}
	verifier, err := cose.NewVerifier(alg, key)
	if err != nil {
		return nil, "", fmt.Errorf("agtp: create COSE verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, "", fmt.Errorf("agtp: verify COSE_Sign1: %w", err)
	}

	claims := map[any]any{}
	if err := cbor.Unmarshal(msg.Payload, &claims); err != nil {
		return nil, "", fmt.Errorf("agtp: decode CWT payload: %w", err)
	}
	if err := validateCWTRegisteredClaims(claims, opts); err != nil {
		return nil, "", err
	}
	return claims, keyID, nil
}

func validateCWTVerifyOptions(opts CWTVerifyOptions) error {
	if len(opts.ValidAlgorithms) == 0 {
		return ErrMissingCOSEAlgorithms
	}
	for _, alg := range opts.ValidAlgorithms {
		if alg == cose.AlgorithmReserved {
			return ErrUnsafeCOSEAlgorithm
		}
	}
	if strings.TrimSpace(opts.ExpectedIssuer) == "" {
		return ErrMissingExpectedIssuer
	}
	if strings.TrimSpace(opts.ExpectedAudience) == "" {
		return ErrMissingExpectedAudience
	}
	return nil
}

func cwtKeyFuncForOptions(opts CWTVerifyOptions) (CWTKeyFunc, error) {
	if opts.KeyFunc == nil && len(opts.LocalKeys) == 0 {
		return nil, ErrMissingKeyFunc
	}
	if opts.KeyFunc != nil && len(opts.LocalKeys) > 0 {
		return nil, ErrAmbiguousKeySource
	}

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

func validateCWTRegisteredClaims(claims map[any]any, opts CWTVerifyOptions) error {
	issuer, ok := cwtStringClaim(claims, cose.CWTClaimIssuer)
	if !ok || strings.TrimSpace(issuer) != opts.ExpectedIssuer {
		return ErrInvalidIssuer
	}
	if !cwtAudienceMatches(claims, opts.ExpectedAudience) {
		return ErrInvalidAudience
	}

	expiresAt, ok := cwtTimeClaim(claims, cose.CWTClaimExpirationTime)
	if !ok {
		return ErrMissingExpiration
	}
	issuedAt, ok := cwtTimeClaim(claims, cose.CWTClaimIssuedAt)
	if !ok {
		return ErrMissingIssuedAt
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.After(expiresAt) {
		return ErrExpiredToken
	}
	if issuedAt.After(now) {
		return ErrFutureToken
	}
	return nil
}

func allowedCOSEAlgorithm(alg cose.Algorithm, allowed []cose.Algorithm) bool {
	for _, candidate := range allowed {
		if candidate == alg {
			return true
		}
	}
	return false
}

func keyIDFromCOSE(msg *cose.Sign1Message) (string, error) {
	value, ok := msg.Headers.Protected[cose.HeaderLabelKeyID]
	if !ok {
		return "", ErrMissingKeyID
	}
	keyID, ok := cwtStringValue(value)
	if !ok || strings.TrimSpace(keyID) == "" {
		return "", ErrMissingKeyID
	}
	return keyID, nil
}

func cwtProfileClaims(claims map[any]any) profileClaims {
	return profileClaims{
		TokenType:            cwtStringClaimOrEmpty(claims, ClaimTokenType),
		ProfileVersion:       cwtStringClaimOrEmpty(claims, ClaimProfileVersion),
		LegacyTokenType:      cwtStringClaimOrEmpty(claims, LegacyClaimTokenType),
		LegacyProfileVersion: cwtStringClaimOrEmpty(claims, LegacyClaimProfileVersion),
	}
}

func cwtIDFromClaims(claims map[any]any) string {
	return cwtStringClaimOrEmpty(claims, cose.CWTClaimCWTID)
}

func cwtConfirmationKey(claims map[any]any) string {
	value, ok := cwtClaimValue(claims, cose.CWTClaimConfirmation)
	if !ok {
		value, ok = cwtClaimValue(claims, "cnf")
	}
	if !ok {
		return ""
	}
	switch cnf := value.(type) {
	case map[any]any:
		if keyID, ok := cwtMapStringValue(cnf, "kid"); ok {
			return keyID
		}
	case map[string]any:
		if keyID, ok := cwtStringValue(cnf["kid"]); ok {
			return keyID
		}
	}
	return ""
}

func cwtAudienceMatches(claims map[any]any, expected string) bool {
	value, ok := cwtClaimValue(claims, cose.CWTClaimAudience)
	if !ok {
		return false
	}
	audience, ok := cwtStringValue(value)
	if ok {
		return audience == expected
	}
	switch values := value.(type) {
	case []any:
		for _, item := range values {
			audience, ok := cwtStringValue(item)
			if ok && audience == expected {
				return true
			}
		}
	case []string:
		for _, audience := range values {
			if audience == expected {
				return true
			}
		}
	}
	return false
}

func cwtStringClaimOrEmpty(claims map[any]any, key any) string {
	value, _ := cwtStringClaim(claims, key)
	return value
}

func cwtStringClaim(claims map[any]any, key any) (string, bool) {
	value, ok := cwtClaimValue(claims, key)
	if !ok {
		return "", false
	}
	return cwtStringValue(value)
}

func cwtStringSliceClaim(claims map[any]any, key any) []string {
	value, ok := cwtClaimValue(claims, key)
	if !ok {
		return nil
	}
	switch values := value.(type) {
	case []string:
		return append([]string{}, values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, item := range values {
			if value, ok := cwtStringValue(item); ok {
				out = append(out, value)
			}
		}
		return out
	case string:
		if strings.TrimSpace(values) == "" {
			return nil
		}
		return []string{values}
	default:
		return nil
	}
}

func cwtTimeClaim(claims map[any]any, key any) (time.Time, bool) {
	value, ok := cwtClaimValue(claims, key)
	if !ok {
		return time.Time{}, false
	}
	switch v := value.(type) {
	case int:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case uint64:
		if v > uint64(1<<63-1) {
			return time.Time{}, false
		}
		return time.Unix(int64(v), 0), true
	default:
		return time.Time{}, false
	}
}

func cwtClaimValue(claims map[any]any, key any) (any, bool) {
	for _, candidate := range cwtKeyAliases(key) {
		if value, ok := claims[candidate]; ok {
			return value, true
		}
	}
	return nil, false
}

func cwtMapStringValue(values map[any]any, key any) (string, bool) {
	value, ok := cwtClaimValue(values, key)
	if !ok {
		return "", false
	}
	return cwtStringValue(value)
}

func cwtKeyAliases(key any) []any {
	switch k := key.(type) {
	case int64:
		return []any{k, int(k), uint64(k)}
	case int:
		return []any{k, int64(k), uint64(k)}
	case uint64:
		if k <= uint64(1<<63-1) {
			return []any{k, int64(k), int(k)}
		}
		return []any{k}
	default:
		return []any{key}
	}
}

func cwtStringValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	default:
		return "", false
	}
}
