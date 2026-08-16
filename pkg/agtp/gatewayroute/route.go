// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package gatewayroute is an experimental reference-adapter policy gate for
// Gateway Route Assertions after their wire signatures have already been
// checked by the caller.
//
// The package is not part of the Direct-Agent core verifier path. Runtime
// gateway-routed mode remains out of scope for this repository until it is split
// into an explicit experimental module or a separate implementation surface.
package gatewayroute

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

var (
	ErrMissingExpected = errors.New("gatewayroute: missing expected value")
	ErrMissingObserved = errors.New("gatewayroute: missing observed value")
	ErrMismatch        = errors.New("gatewayroute: value mismatch")
	ErrExpired         = errors.New("gatewayroute: expired assertion")
	ErrFuture          = errors.New("gatewayroute: assertion issued in the future")
	ErrReplayDetected  = errors.New("gatewayroute: replay detected")
	ErrUnsafeValue     = errors.New("gatewayroute: unsafe value")
)

const (
	AssertionType    = "ai2ai.gateway-route-assertion"
	AssertionVersion = 1

	FieldAll                         = "*"
	FieldType                        = "gta_type"
	FieldVersion                     = "gta_version"
	FieldIssuer                      = "iss"
	FieldAudience                    = "aud"
	FieldID                          = "jti"
	FieldIssuedAt                    = "iat"
	FieldExpiresAt                   = "exp"
	FieldNonce                       = "nonce"
	FieldGrantHash                   = "grant_hash"
	FieldGatewaySessionBindingSHA256 = "gateway_session_binding_sha256"
	FieldRouteID                     = "route_id"
	FieldNextHop                     = "next_hop"
	FieldTenant                      = "tenant"
	FieldPrincipal                   = "principal"
	FieldAuthorityScope              = "authority_scope"
	FieldPolicyID                    = "policy_id"
	FieldTargetAgent                 = "target_agent"
	FieldTargetWorkload              = "target_workload"
	FieldTargetAgentKeyThumbprint    = "target_agent_key_thumbprint"
	FieldUpstreamAuthn               = "upstream_authn"
	FieldUpstreamPeer                = "upstream_peer"
	FieldRequestContextSHA256        = "request_context_sha256"
	FieldTaskID                      = "task_id"
	FieldContextID                   = "context_id"
	FieldSessionID                   = "session_id"
	FieldAuditHash                   = "audit_hash"
	FieldAgentHOKProofSHA256         = "agent_hok_proof_sha256"
	FieldHolderAgent                 = "holder.agent"
	FieldHolderWorkload              = "holder.workload"
	FieldHolderKeyThumbprint         = "holder.key_thumbprint"
	FieldHolderNonce                 = "holder.nonce"
)

// Assertion is a verified Gateway Route Assertion.
type Assertion struct {
	Type                        string
	Version                     int
	Issuer                      string
	Audience                    string
	ID                          string
	IssuedAt                    time.Time
	ExpiresAt                   time.Time
	Nonce                       string
	GrantHash                   string
	GatewaySessionBindingSHA256 string
	RouteID                     string
	NextHop                     string
	Tenant                      string
	Principal                   string
	AuthorityScope              string
	PolicyID                    string
	TargetAgent                 string
	TargetWorkload              string
	TargetAgentKeyThumbprint    string
	UpstreamAuthn               string
	UpstreamPeer                string
	RequestContextSHA256        string
	TaskID                      string
	ContextID                   string
	SessionID                   string
	AuditHash                   string
	AgentHolderOfKeyProofSHA256 string
}

// HolderOfKeyProof is an already-verified final-Agent holder-of-key proof.
type HolderOfKeyProof struct {
	AgentID       string
	WorkloadID    string
	KeyThumbprint string
	GrantHash     string
	RouteID       string
	TaskID        string
	ContextID     string
	Nonce         string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// ExpectedRoute contains verifier-local expected route policy.
type ExpectedRoute struct {
	Issuer                       string
	Audience                     string
	Tenant                       string
	AuthorityScope               string
	RouteID                      string
	PolicyID                     string
	TargetAgent                  string
	TargetWorkload               string
	TargetAgentKeyThumbprint     string
	RequestContextSHA256         string
	TaskID                       string
	ContextID                    string
	AuditHash                    string
	RequireAgentHolderOfKeyProof bool
}

// Options contains acceptance integrations outside the signed route assertion.
type Options struct {
	Now         time.Time
	ReplayCache identitypolicy.ReplayCache
}

// Validate checks a verified Gateway Route Assertion against local route policy
// and an optional final-Agent holder-of-key proof.
func Validate(assertion Assertion, proof *HolderOfKeyProof, expected ExpectedRoute, opts Options) error {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	var errs []error
	errs = append(errs, validateCore(assertion, now)...)
	errs = append(errs, compareExpected(assertion, expected)...)
	if expected.RequireAgentHolderOfKeyProof {
		errs = append(errs, validateHolderProof(assertion, proof, expected, now)...)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if opts.ReplayCache != nil {
		if err := opts.ReplayCache.MarkUsed(replayKey(assertion), assertion.ExpiresAt); err != nil {
			if errors.Is(err, identitypolicy.ErrReplayDetected) {
				return ErrReplayDetected
			}
			return err
		}
	}
	return nil
}

func validateCore(a Assertion, now time.Time) []error {
	var errs []error
	for _, f := range []field{
		{FieldType, a.Type},
		{FieldIssuer, a.Issuer},
		{FieldAudience, a.Audience},
		{FieldID, a.ID},
		{FieldNonce, a.Nonce},
		{FieldGrantHash, a.GrantHash},
		{FieldGatewaySessionBindingSHA256, a.GatewaySessionBindingSHA256},
		{FieldRouteID, a.RouteID},
		{FieldNextHop, a.NextHop},
		{FieldPolicyID, a.PolicyID},
		{FieldTargetAgent, a.TargetAgent},
		{FieldUpstreamAuthn, a.UpstreamAuthn},
		{FieldUpstreamPeer, a.UpstreamPeer},
		{FieldRequestContextSHA256, a.RequestContextSHA256},
	} {
		errs = append(errs, validateObserved(f)...)
	}
	if a.Type != "" && a.Type != AssertionType {
		errs = append(errs, fieldError(FieldType, ErrMismatch))
	}
	if a.Version != AssertionVersion {
		errs = append(errs, fieldError(FieldVersion, ErrMismatch))
	}
	if a.IssuedAt.IsZero() {
		errs = append(errs, fieldError(FieldIssuedAt, ErrMissingObserved))
	} else if a.IssuedAt.After(now) {
		errs = append(errs, fieldError(FieldIssuedAt, ErrFuture))
	}
	if a.ExpiresAt.IsZero() {
		errs = append(errs, fieldError(FieldExpiresAt, ErrMissingObserved))
	} else if now.After(a.ExpiresAt) {
		errs = append(errs, fieldError(FieldExpiresAt, ErrExpired))
	}
	return errs
}

func compareExpected(a Assertion, expected ExpectedRoute) []error {
	var errs []error
	for _, f := range []expectedField{
		{FieldIssuer, expected.Issuer, a.Issuer},
		{FieldAudience, expected.Audience, a.Audience},
		{FieldTenant, expected.Tenant, a.Tenant},
		{FieldAuthorityScope, expected.AuthorityScope, a.AuthorityScope},
		{FieldRouteID, expected.RouteID, a.RouteID},
		{FieldPolicyID, expected.PolicyID, a.PolicyID},
		{FieldTargetAgent, expected.TargetAgent, a.TargetAgent},
		{FieldTargetWorkload, expected.TargetWorkload, a.TargetWorkload},
		{FieldTargetAgentKeyThumbprint, expected.TargetAgentKeyThumbprint, a.TargetAgentKeyThumbprint},
		{FieldRequestContextSHA256, expected.RequestContextSHA256, a.RequestContextSHA256},
		{FieldTaskID, expected.TaskID, a.TaskID},
		{FieldContextID, expected.ContextID, a.ContextID},
		{FieldAuditHash, expected.AuditHash, a.AuditHash},
	} {
		if isEmpty(f.want) {
			continue
		}
		if isUnsafe(f.want) {
			errs = append(errs, fieldError(f.name, ErrUnsafeValue))
			continue
		}
		if isEmpty(f.got) {
			errs = append(errs, fieldError(f.name, ErrMissingObserved))
			continue
		}
		if isUnsafe(f.got) {
			errs = append(errs, fieldError(f.name, ErrUnsafeValue))
			continue
		}
		if f.want != f.got {
			errs = append(errs, fieldError(f.name, ErrMismatch))
		}
	}
	if isEmpty(expected.Issuer) || isEmpty(expected.Audience) || isEmpty(expected.RouteID) ||
		isEmpty(expected.PolicyID) || isEmpty(expected.TargetAgent) || isEmpty(expected.RequestContextSHA256) {
		errs = append(errs, fieldError(FieldAll, ErrMissingExpected))
	}
	return errs
}

func validateHolderProof(a Assertion, proof *HolderOfKeyProof, expected ExpectedRoute, now time.Time) []error {
	if proof == nil {
		return []error{fieldError(FieldAgentHOKProofSHA256, ErrMissingObserved)}
	}
	var errs []error
	for _, f := range []expectedField{
		{FieldHolderAgent, a.TargetAgent, proof.AgentID},
		{FieldHolderWorkload, a.TargetWorkload, proof.WorkloadID},
		{FieldHolderKeyThumbprint, holderKeyThumbprint(a, expected), proof.KeyThumbprint},
		{FieldGrantHash, a.GrantHash, proof.GrantHash},
		{FieldRouteID, a.RouteID, proof.RouteID},
		{FieldTaskID, a.TaskID, proof.TaskID},
		{FieldContextID, a.ContextID, proof.ContextID},
		{FieldHolderNonce, a.Nonce, proof.Nonce},
	} {
		if isEmpty(f.want) {
			continue
		}
		if isEmpty(f.got) {
			errs = append(errs, fieldError(f.name, ErrMissingObserved))
			continue
		}
		if isUnsafe(f.got) {
			errs = append(errs, fieldError(f.name, ErrUnsafeValue))
			continue
		}
		if f.want != f.got {
			errs = append(errs, fieldError(f.name, ErrMismatch))
		}
	}
	if proof.IssuedAt.After(now) {
		errs = append(errs, fieldError(FieldIssuedAt, ErrFuture))
	}
	if proof.ExpiresAt.IsZero() {
		errs = append(errs, fieldError(FieldExpiresAt, ErrMissingObserved))
	} else if now.After(proof.ExpiresAt) {
		errs = append(errs, fieldError(FieldExpiresAt, ErrExpired))
	}
	if isEmpty(a.AgentHolderOfKeyProofSHA256) {
		errs = append(errs, fieldError(FieldAgentHOKProofSHA256, ErrMissingObserved))
	}
	return errs
}

func replayKey(a Assertion) string {
	return a.Issuer + "\x00" + a.Audience + "\x00" + a.Tenant + "\x00" +
		a.AuthorityScope + "\x00" + a.RouteID + "\x00" + a.GrantHash + "\x00" + a.Nonce
}

func holderKeyThumbprint(a Assertion, expected ExpectedRoute) string {
	if expected.TargetAgentKeyThumbprint != "" {
		return expected.TargetAgentKeyThumbprint
	}
	return a.TargetAgentKeyThumbprint
}

type field struct {
	name  string
	value string
}

type expectedField struct {
	name string
	want string
	got  string
}

func validateObserved(f field) []error {
	if isEmpty(f.value) {
		return []error{fieldError(f.name, ErrMissingObserved)}
	}
	if isUnsafe(f.value) {
		return []error{fieldError(f.name, ErrUnsafeValue)}
	}
	return nil
}

func fieldError(field string, err error) error {
	return fmt.Errorf("%s: %w", field, err)
}

func isEmpty(value string) bool {
	return strings.TrimSpace(value) == ""
}

func isUnsafe(value string) bool {
	return strings.ContainsAny(value, "\r\n<>")
}
