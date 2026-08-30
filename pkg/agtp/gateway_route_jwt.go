// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/gatewayroute"
	"github.com/golang-jwt/jwt/v5"
)

// GatewayRouteJWTOptions contains local policy for accepting a signed Gateway
// Route Assertion carried as JWT/JWS.
type GatewayRouteJWTOptions struct {
	Assertion JWTVerifyOptions
	Expected  gatewayroute.ExpectedRoute
	Proof     *gatewayroute.HolderOfKeyProof

	ExpectedGrantHash                   string
	ExpectedGatewaySessionBindingSHA256 string
	ExpectedAgentHolderOfKeyProofSHA256 string

	Route gatewayroute.Options
}

type gatewayRouteAssertionClaims struct {
	jwt.RegisteredClaims

	Type                        string `json:"gta_type,omitempty"`
	Version                     int    `json:"gta_version,omitempty"`
	Nonce                       string `json:"nonce,omitempty"`
	GrantHash                   string `json:"grant_hash,omitempty"`
	GatewaySessionBindingSHA256 string `json:"gateway_session_binding_sha256,omitempty"`
	RouteID                     string `json:"route_id,omitempty"`
	NextHop                     string `json:"next_hop,omitempty"`
	Tenant                      string `json:"tenant,omitempty"`
	Principal                   string `json:"principal,omitempty"`
	AuthorityScope              string `json:"authority_scope,omitempty"`
	PolicyID                    string `json:"policy_id,omitempty"`
	TargetAgent                 string `json:"target_agent,omitempty"`
	TargetWorkload              string `json:"target_workload,omitempty"`
	TargetAgentKeyThumbprint    string `json:"target_agent_key_thumbprint,omitempty"`
	UpstreamAuthn               string `json:"upstream_authn,omitempty"`
	UpstreamPeer                string `json:"upstream_peer,omitempty"`
	RequestContextSHA256        string `json:"request_context_sha256,omitempty"`
	TaskID                      string `json:"task_id,omitempty"`
	ContextID                   string `json:"context_id,omitempty"`
	SessionID                   string `json:"session_id,omitempty"`
	AuditHash                   string `json:"audit_hash,omitempty"`
	AgentHolderOfKeyProofSHA256 string `json:"agent_hok_proof_sha256,omitempty"`
}

// VerifyGatewayRouteAssertionJWT verifies the JWS signature and registered JWT
// claims, then maps the route assertion into the gatewayroute policy model.
func VerifyGatewayRouteAssertionJWT(tokenString string, opts JWTVerifyOptions) (gatewayroute.Assertion, error) {
	claims := &gatewayRouteAssertionClaims{}
	if _, _, err := parseJWT(tokenString, claims, opts); err != nil {
		return gatewayroute.Assertion{}, err
	}
	assertion := gatewayRouteAssertionFromJWTClaims(claims)
	if err := validateGatewayRouteCore(assertion); err != nil {
		return gatewayroute.Assertion{}, err
	}
	return assertion, nil
}

// VerifyGatewayRouteJWT verifies and accepts a signed Gateway Route Assertion
// against verifier-local route policy, replay state, and final-Agent proof
// requirements.
func VerifyGatewayRouteJWT(tokenString string, opts GatewayRouteJWTOptions) (gatewayroute.Assertion, error) {
	if opts.Route.ReplayCache == nil {
		return gatewayroute.Assertion{}, ErrMissingReplayCache
	}
	now := opts.Assertion.Now
	if now.IsZero() {
		now = time.Now()
	}
	assertion, err := VerifyGatewayRouteAssertionJWT(tokenString, opts.Assertion)
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

func gatewayRouteAssertionFromJWTClaims(c *gatewayRouteAssertionClaims) gatewayroute.Assertion {
	var issuedAt, expiresAt time.Time
	if c.IssuedAt != nil {
		issuedAt = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		expiresAt = c.ExpiresAt.Time
	}
	audience := ""
	if len(c.Audience) > 0 {
		audience = c.Audience[0]
	}
	return gatewayroute.Assertion{
		Type:                        c.Type,
		Version:                     c.Version,
		Issuer:                      c.Issuer,
		Audience:                    audience,
		ID:                          c.ID,
		IssuedAt:                    issuedAt,
		ExpiresAt:                   expiresAt,
		Nonce:                       c.Nonce,
		GrantHash:                   c.GrantHash,
		GatewaySessionBindingSHA256: c.GatewaySessionBindingSHA256,
		RouteID:                     c.RouteID,
		NextHop:                     c.NextHop,
		Tenant:                      c.Tenant,
		Principal:                   c.Principal,
		AuthorityScope:              c.AuthorityScope,
		PolicyID:                    c.PolicyID,
		TargetAgent:                 c.TargetAgent,
		TargetWorkload:              c.TargetWorkload,
		TargetAgentKeyThumbprint:    c.TargetAgentKeyThumbprint,
		UpstreamAuthn:               c.UpstreamAuthn,
		UpstreamPeer:                c.UpstreamPeer,
		RequestContextSHA256:        c.RequestContextSHA256,
		TaskID:                      c.TaskID,
		ContextID:                   c.ContextID,
		SessionID:                   c.SessionID,
		AuditHash:                   c.AuditHash,
		AgentHolderOfKeyProofSHA256: c.AgentHolderOfKeyProofSHA256,
	}
}
