// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package production provides the supported production composition for the
// Direct-Agent v1 verifier. It keeps deployment-owned trust, revocation,
// attestation, and distributed replay policy outside the wire-token parser
// while enforcing them in one fail-closed acceptance transaction.
package production

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

var (
	ErrMissingTrustSource       = errors.New("production: missing trust source")
	ErrTrustSourceUnavailable   = errors.New("production: trust source unavailable")
	ErrMissingAttestation       = errors.New("production: missing attestation result")
	ErrMissingAttestationPolicy = errors.New("production: missing attestation policy")
	ErrMissingReplayCache       = errors.New("production: missing distributed replay cache")
	ErrMissingPolicy            = errors.New("production: missing identity policy")
	ErrInvalidAuthority         = errors.New("production: invalid authority policy")
	ErrMissingContext           = errors.New("production: missing context")
)

// TrustSnapshot is one fail-closed view of trusted keys and revocation state.
// Grant and binding authorities use separate snapshots so their key roles
// cannot be silently combined.
type TrustSnapshot struct {
	Keys            []clients.LocalKey
	DisabledKeyIDs  []string
	RevokedTokenIDs []string
}

// TrustSource returns the current trusted-key and revocation snapshot. A
// source error rejects the request; callers must not fall back to stale data.
type TrustSource interface {
	Snapshot(context.Context) (TrustSnapshot, error)
}

// StaticTrustSource is suitable for deployments whose immutable configuration
// is replaced atomically during key rotation or revocation updates.
type StaticTrustSource struct {
	Trust TrustSnapshot
	Err   error
}

// Snapshot returns a defensive copy of the configured trust snapshot.
func (s StaticTrustSource) Snapshot(context.Context) (TrustSnapshot, error) {
	if s.Err != nil {
		return TrustSnapshot{}, fmt.Errorf("%w: %v", ErrTrustSourceUnavailable, s.Err)
	}
	return cloneTrustSnapshot(s.Trust), nil
}

// AuthorityPolicy fixes the issuer, audience, signing algorithms, and trust
// source used for one token role.
type AuthorityPolicy struct {
	ExpectedIssuer   string
	ExpectedAudience string
	ValidMethods     []string
	TrustSource      TrustSource
}

// AttestationPolicy authenticates and appraises an attestation result against
// the binding derived by the relying service from the accepted TLS session and
// exact application context.
type AttestationPolicy interface {
	Verify(context.Context, AttestationResult, string, time.Time) error
}

// Profile is the supported Direct-Agent v1 production composition.
type Profile struct {
	GrantAuthority   AuthorityPolicy
	BindingAuthority AuthorityPolicy
	IdentityPolicy   identitypolicy.Policy
	Attestation      AttestationPolicy
	ReplayCache      identitypolicy.ReplayCache
	Now              func() time.Time
}

// VerifyRequest contains untrusted wire tokens plus verifier-derived binding
// and authenticated attestation material for one protected action.
type VerifyRequest struct {
	GrantJWT          string
	SessionBindingJWT string
	ExpectedBinding   identitypolicy.Binding
	Attestation       AttestationResult
}

// AcceptedIdentity is the minimal application projection returned after every
// production gate succeeds and replay state is committed.
type AcceptedIdentity struct {
	Issuer                  string
	Agent                   string
	TaskID                  string
	DelegationID            string
	IntentRef               string
	CapabilityRef           string
	Scopes                  []string
	Resources               []string
	AuthorizationDetails    []string
	GrantExpiresAt          time.Time
	SessionBindingExpiresAt time.Time
	AttestationExpiresAt    time.Time
}

// Validate checks deployment-owned configuration without reading a token.
func (p Profile) Validate(ctx context.Context) error {
	if ctx == nil {
		return ErrMissingContext
	}
	if !p.IdentityPolicy.Enabled() {
		return ErrMissingPolicy
	}
	if err := p.IdentityPolicy.ValidateMode(); err != nil {
		return fmt.Errorf("%w: identity policy: %v", ErrInvalidAuthority, err)
	}
	if p.Attestation == nil {
		return ErrMissingAttestationPolicy
	}
	if p.ReplayCache == nil {
		return ErrMissingReplayCache
	}
	if _, err := p.jwtOptions(ctx, p.GrantAuthority, time.Time{}); err != nil {
		return fmt.Errorf("grant authority: %w", err)
	}
	if _, err := p.jwtOptions(ctx, p.BindingAuthority, time.Time{}); err != nil {
		return fmt.Errorf("binding authority: %w", err)
	}
	return nil
}

// Verify authenticates the grant and session proof, evaluates local policy and
// attestation, then commits one distributed replay key before returning an
// accepted identity.
func (p Profile) Verify(ctx context.Context, req VerifyRequest) (AcceptedIdentity, error) {
	if ctx == nil {
		return AcceptedIdentity{}, ErrMissingContext
	}
	if !p.IdentityPolicy.Enabled() {
		return AcceptedIdentity{}, ErrMissingPolicy
	}
	if p.Attestation == nil {
		return AcceptedIdentity{}, ErrMissingAttestationPolicy
	}
	if p.ReplayCache == nil {
		return AcceptedIdentity{}, ErrMissingReplayCache
	}
	if strings.TrimSpace(req.Attestation.ResultID) == "" {
		return AcceptedIdentity{}, ErrMissingAttestation
	}

	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}

	verified, err := verifyIdentity(
		ctx,
		p.GrantAuthority,
		p.BindingAuthority,
		p.IdentityPolicy,
		req.GrantJWT,
		req.SessionBindingJWT,
		req.ExpectedBinding,
		now,
	)
	if err != nil {
		return AcceptedIdentity{}, err
	}
	if err := p.Attestation.Verify(ctx, req.Attestation, req.ExpectedBinding.AttestationBinderSHA256, now); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("verify attestation: %w", err)
	}

	replayExpiry := earliestTime(verified.statement.Binding.ExpiresAt, req.Attestation.ExpiresAt, verified.grant.ExpiresAt)
	replayKey := strings.Join([]string{
		"asb.production.v1",
		verified.grant.GrantHash,
		verified.grant.Audience,
		verified.statement.Binding.RequestContextSHA256,
		verified.statement.Binding.Nonce,
	}, "\x00")
	if err := p.ReplayCache.MarkUsed(replayKey, replayExpiry); err != nil {
		return AcceptedIdentity{}, fmt.Errorf("commit replay state: %w", err)
	}

	return AcceptedIdentity{
		Issuer:                  verified.assertion.Issuer,
		Agent:                   verified.assertion.Values.Agent,
		TaskID:                  verified.assertion.Values.TaskID,
		DelegationID:            verified.assertion.Values.DelegationID,
		IntentRef:               verified.assertion.Values.IntentRef,
		CapabilityRef:           verified.assertion.Values.CapabilityRef,
		Scopes:                  append([]string(nil), verified.assertion.Values.Scopes...),
		Resources:               append([]string(nil), verified.assertion.Values.Resources...),
		AuthorizationDetails:    append([]string(nil), verified.assertion.Values.AuthorizationDetails...),
		GrantExpiresAt:          verified.grant.ExpiresAt,
		SessionBindingExpiresAt: verified.statement.Binding.ExpiresAt,
		AttestationExpiresAt:    req.Attestation.ExpiresAt,
	}, nil
}

type verifiedIdentity struct {
	grant     identitypolicy.VerifiedGrant
	statement identitypolicy.VerifiedSessionBindingStatement
	assertion identitypolicy.Assertion
}

func verifyIdentity(
	ctx context.Context,
	grantAuthority AuthorityPolicy,
	bindingAuthority AuthorityPolicy,
	policy identitypolicy.Policy,
	grantJWT string,
	bindingJWT string,
	expectedBinding identitypolicy.Binding,
	now time.Time,
) (verifiedIdentity, error) {
	grantOpts, err := jwtOptions(ctx, grantAuthority, now)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("grant authority: %w", err)
	}
	grant, err := clients.VerifyIdentityGrantJWT(grantJWT, grantOpts)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("verify grant: %w", err)
	}

	bindingOpts, err := jwtOptions(ctx, bindingAuthority, now)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("binding authority: %w", err)
	}
	statement, err := clients.VerifySessionBindingJWT(bindingJWT, bindingOpts)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("verify session binding: %w", err)
	}

	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return verifiedIdentity{}, fmt.Errorf("bind grant to session: %w", err)
	}
	if err := policy.ValidateAssertion(assertion, expectedBinding, now); err != nil {
		return verifiedIdentity{}, fmt.Errorf("verify expected identity: %w", err)
	}
	return verifiedIdentity{grant: grant, statement: statement, assertion: assertion}, nil
}

func (p Profile) jwtOptions(ctx context.Context, authority AuthorityPolicy, now time.Time) (clients.JWTVerifyOptions, error) {
	return jwtOptions(ctx, authority, now)
}

func jwtOptions(ctx context.Context, authority AuthorityPolicy, now time.Time) (clients.JWTVerifyOptions, error) {
	if authority.TrustSource == nil {
		return clients.JWTVerifyOptions{}, ErrMissingTrustSource
	}
	if strings.TrimSpace(authority.ExpectedIssuer) == "" ||
		strings.TrimSpace(authority.ExpectedAudience) == "" || len(authority.ValidMethods) == 0 {
		return clients.JWTVerifyOptions{}, ErrInvalidAuthority
	}
	snapshot, err := authority.TrustSource.Snapshot(ctx)
	if err != nil {
		if errors.Is(err, ErrTrustSourceUnavailable) {
			return clients.JWTVerifyOptions{}, err
		}
		return clients.JWTVerifyOptions{}, fmt.Errorf("%w: %v", ErrTrustSourceUnavailable, err)
	}
	opts := clients.JWTVerifyOptions{
		ExpectedIssuer:   authority.ExpectedIssuer,
		ExpectedAudience: authority.ExpectedAudience,
		ValidMethods:     append([]string(nil), authority.ValidMethods...),
		LocalKeys:        append([]clients.LocalKey(nil), snapshot.Keys...),
		DisabledKeyIDs:   append([]string(nil), snapshot.DisabledKeyIDs...),
		RevokedJWTIDs:    append([]string(nil), snapshot.RevokedTokenIDs...),
		Now:              now,
	}
	if err := clients.ValidateJWTVerifyOptions(opts); err != nil {
		return clients.JWTVerifyOptions{}, fmt.Errorf("%w: %v", ErrInvalidAuthority, err)
	}
	return opts, nil
}

func cloneTrustSnapshot(in TrustSnapshot) TrustSnapshot {
	out := TrustSnapshot{
		Keys:            append([]clients.LocalKey(nil), in.Keys...),
		DisabledKeyIDs:  append([]string(nil), in.DisabledKeyIDs...),
		RevokedTokenIDs: append([]string(nil), in.RevokedTokenIDs...),
	}
	return out
}

func earliestTime(values ...time.Time) time.Time {
	var earliest time.Time
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if earliest.IsZero() || value.Before(earliest) {
			earliest = value
		}
	}
	return earliest
}
