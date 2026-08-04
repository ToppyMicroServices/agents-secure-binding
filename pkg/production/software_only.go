// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
)

var ErrUnexpectedAttestationBinding = errors.New("production: software-only profile forbids attestation binding")

// SoftwareOnlyProfile is the supported Direct-Agent v1 production
// composition for deployments that trust the software host and do not select
// platform attestation. It still requires role-separated trust, exact TLS and
// action binding, verifier-local policy, freshness, revocation, and durable
// replay state.
type SoftwareOnlyProfile struct {
	GrantAuthority   AuthorityPolicy
	BindingAuthority AuthorityPolicy
	IdentityPolicy   identitypolicy.Policy
	ReplayCache      identitypolicy.ReplayCache
	Now              func() time.Time
}

// SoftwareOnlyVerifyRequest contains the two untrusted wire tokens and the
// verifier-derived TLS/action binding. Attestation evidence is intentionally
// absent from this request type.
type SoftwareOnlyVerifyRequest struct {
	GrantJWT          string
	SessionBindingJWT string
	ExpectedBinding   identitypolicy.Binding
}

// Validate checks software-only deployment configuration without reading a
// token.
func (p SoftwareOnlyProfile) Validate(ctx context.Context) error {
	if ctx == nil {
		return ErrMissingContext
	}
	if !p.IdentityPolicy.Enabled() {
		return ErrMissingPolicy
	}
	if err := p.IdentityPolicy.ValidateMode(); err != nil {
		return fmt.Errorf("%w: identity policy: %v", ErrInvalidAuthority, err)
	}
	if isNilInterface(p.ReplayCache) {
		return ErrMissingReplayCache
	}
	if _, err := jwtOptions(ctx, p.GrantAuthority, time.Time{}); err != nil {
		return fmt.Errorf("grant authority: %w", err)
	}
	if _, err := jwtOptions(ctx, p.BindingAuthority, time.Time{}); err != nil {
		return fmt.Errorf("binding authority: %w", err)
	}
	return nil
}

// Verify authenticates the grant and session proof, evaluates local policy,
// and commits one distributed replay key. Both the expected binding and the
// signed session proof must omit attestation_binder_sha256.
func (p SoftwareOnlyProfile) Verify(ctx context.Context, req SoftwareOnlyVerifyRequest) (AcceptedIdentity, error) {
	if ctx == nil {
		return AcceptedIdentity{}, ErrMissingContext
	}
	if !p.IdentityPolicy.Enabled() {
		return AcceptedIdentity{}, ErrMissingPolicy
	}
	if isNilInterface(p.ReplayCache) {
		return AcceptedIdentity{}, ErrMissingReplayCache
	}
	if strings.TrimSpace(req.ExpectedBinding.AttestationBinderSHA256) != "" {
		return AcceptedIdentity{}, ErrUnexpectedAttestationBinding
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
	if strings.TrimSpace(verified.statement.Binding.AttestationBinderSHA256) != "" {
		return AcceptedIdentity{}, ErrUnexpectedAttestationBinding
	}

	replayExpiry := earliestTime(verified.statement.Binding.ExpiresAt, verified.grant.ExpiresAt)
	replayKey := strings.Join([]string{
		"asb.production.software-only.v1",
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
	}, nil
}
