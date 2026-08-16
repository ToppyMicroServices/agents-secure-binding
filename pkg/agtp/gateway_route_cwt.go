// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/gatewayroute"
	"github.com/veraison/go-cose"
)

// GatewayRouteCWTOptions contains local policy for accepting a signed Gateway
// Route Assertion carried as CWT/COSE.
type GatewayRouteCWTOptions struct {
	Assertion CWTVerifyOptions
	Expected  gatewayroute.ExpectedRoute
	Proof     *gatewayroute.HolderOfKeyProof

	ExpectedGrantHash                   string
	ExpectedGatewaySessionBindingSHA256 string
	ExpectedAgentHolderOfKeyProofSHA256 string

	Route gatewayroute.Options
}

// VerifyGatewayRouteAssertionCWT verifies the COSE signature and registered CWT
// claims, then maps the route assertion into the gatewayroute policy model.
func VerifyGatewayRouteAssertionCWT(token []byte, opts CWTVerifyOptions) (gatewayroute.Assertion, error) {
	claims, _, err := parseCWT(token, opts)
	if err != nil {
		return gatewayroute.Assertion{}, err
	}
	cwtID := cwtIDFromClaims(claims)
	if cwtID == "" {
		return gatewayroute.Assertion{}, ErrMissingCWTID
	}
	if isListed(cwtID, opts.RevokedCWTIDs) {
		return gatewayroute.Assertion{}, ErrRevokedCWTID
	}
	assertion := gatewayRouteAssertionFromCWTClaims(claims)
	if err := validateGatewayRouteCore(assertion); err != nil {
		return gatewayroute.Assertion{}, err
	}
	return assertion, nil
}

// VerifyGatewayRouteCWT verifies and accepts a signed Gateway Route Assertion
// against verifier-local route policy, replay state, and final-Agent proof
// requirements.
func VerifyGatewayRouteCWT(token []byte, opts GatewayRouteCWTOptions) (gatewayroute.Assertion, error) {
	if opts.Route.ReplayCache == nil {
		return gatewayroute.Assertion{}, ErrMissingReplayCache
	}
	now := opts.Assertion.Now
	if now.IsZero() {
		now = time.Now()
	}
	assertion, err := VerifyGatewayRouteAssertionCWT(token, opts.Assertion)
	if err != nil {
		return gatewayroute.Assertion{}, err
	}
	if err := validateGatewayRouteAcceptance(
		assertion,
		opts.ExpectedGrantHash,
		opts.ExpectedGatewaySessionBindingSHA256,
		opts.ExpectedAgentHolderOfKeyProofSHA256,
		opts.Expected.RequireAgentHolderOfKeyProof,
	); err != nil {
		return gatewayroute.Assertion{}, err
	}
	if err := gatewayroute.Validate(assertion, opts.Proof, opts.Expected, routeOptionsWithNow(opts.Route, now)); err != nil {
		return gatewayroute.Assertion{}, err
	}
	return assertion, nil
}

func gatewayRouteAssertionFromCWTClaims(claims map[any]any) gatewayroute.Assertion {
	issuedAt, _ := cwtTimeClaim(claims, cose.CWTClaimIssuedAt)
	expiresAt, _ := cwtTimeClaim(claims, cose.CWTClaimExpirationTime)
	issuer, _ := cwtStringClaim(claims, cose.CWTClaimIssuer)
	audience, _ := cwtStringClaim(claims, cose.CWTClaimAudience)
	return gatewayroute.Assertion{
		Type:                        cwtStringClaimOrEmpty(claims, gatewayroute.FieldType),
		Version:                     cwtIntClaimOrZero(claims, gatewayroute.FieldVersion),
		Issuer:                      issuer,
		Audience:                    audience,
		ID:                          cwtIDFromClaims(claims),
		IssuedAt:                    issuedAt,
		ExpiresAt:                   expiresAt,
		Nonce:                       cwtStringClaimOrEmpty(claims, gatewayroute.FieldNonce),
		GrantHash:                   cwtStringClaimOrEmpty(claims, gatewayroute.FieldGrantHash),
		GatewaySessionBindingSHA256: cwtStringClaimOrEmpty(claims, gatewayroute.FieldGatewaySessionBindingSHA256),
		RouteID:                     cwtStringClaimOrEmpty(claims, gatewayroute.FieldRouteID),
		NextHop:                     cwtStringClaimOrEmpty(claims, gatewayroute.FieldNextHop),
		Tenant:                      cwtStringClaimOrEmpty(claims, gatewayroute.FieldTenant),
		Principal:                   cwtStringClaimOrEmpty(claims, gatewayroute.FieldPrincipal),
		AuthorityScope:              cwtStringClaimOrEmpty(claims, gatewayroute.FieldAuthorityScope),
		PolicyID:                    cwtStringClaimOrEmpty(claims, gatewayroute.FieldPolicyID),
		TargetAgent:                 cwtStringClaimOrEmpty(claims, gatewayroute.FieldTargetAgent),
		TargetWorkload:              cwtStringClaimOrEmpty(claims, gatewayroute.FieldTargetWorkload),
		TargetAgentKeyThumbprint:    cwtStringClaimOrEmpty(claims, gatewayroute.FieldTargetAgentKeyThumbprint),
		UpstreamAuthn:               cwtStringClaimOrEmpty(claims, gatewayroute.FieldUpstreamAuthn),
		UpstreamPeer:                cwtStringClaimOrEmpty(claims, gatewayroute.FieldUpstreamPeer),
		RequestContextSHA256:        cwtStringClaimOrEmpty(claims, gatewayroute.FieldRequestContextSHA256),
		TaskID:                      cwtStringClaimOrEmpty(claims, gatewayroute.FieldTaskID),
		ContextID:                   cwtStringClaimOrEmpty(claims, gatewayroute.FieldContextID),
		SessionID:                   cwtStringClaimOrEmpty(claims, gatewayroute.FieldSessionID),
		AuditHash:                   cwtStringClaimOrEmpty(claims, gatewayroute.FieldAuditHash),
		AgentHolderOfKeyProofSHA256: cwtStringClaimOrEmpty(claims, gatewayroute.FieldAgentHOKProofSHA256),
	}
}

func cwtIntClaimOrZero(claims map[any]any, key any) int {
	value, ok := cwtClaimValue(claims, key)
	if !ok {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	default:
		return 0
	}
}
