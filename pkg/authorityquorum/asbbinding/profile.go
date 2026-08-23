// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/authorityquorum"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

var (
	ErrMissingAuthorityResolver = errors.New("authorityquorum asbbinding: missing authority resolver")
	ErrUnknownAuthority         = errors.New("authorityquorum asbbinding: unknown authority credential")
	ErrMissingASBProof          = errors.New("authorityquorum asbbinding: missing ASB proof material")
	ErrRequestContextMismatch   = errors.New("authorityquorum asbbinding: ASB request context mismatch")
	ErrAmbiguousPolicy          = errors.New("authorityquorum asbbinding: ambiguous authorization policy")
	ErrInvalidProjection        = errors.New("authorityquorum asbbinding: invalid verified projection")
)

// Evidence carries signed ASB material and verifier-local acceptance state.
// ExpectedBinding and AcceptedUntil must come from trusted transport and local
// policy, never HTTP headers or peer-controlled request fields.
type Evidence struct {
	GrantJWT          string
	SessionBindingJWT string
	Options           VerificationOptions
	AcceptedUntil     time.Time
}

// VerificationOptions contains only the checks used by this profile. Exact
// replay is handled by the shared quorum Store after all checks pass.
type VerificationOptions struct {
	Grant           clients.JWTVerifyOptions
	SessionBinding  clients.JWTVerifyOptions
	Policy          identitypolicy.Policy
	ExpectedBinding identitypolicy.Binding
}

// VerifiedActor contains only identity facts accepted by the ASB verifier.
type VerifiedActor struct {
	GrantIssuer      string
	ActorID          string
	ProofIssuer      string
	SignerKey        string
	CredentialDigest string
}

type ResolvedAuthority struct {
	AuthorityID        string
	AuthorityMapDigest string
}

// AuthorityResolver maps accepted actors and credentials to stable policy
// slots. A rotation key for the same authority must resolve to the same slot.
type AuthorityResolver interface {
	ResolveAuthority(context.Context, VerifiedActor) (ResolvedAuthority, error)
}

type AuthorityResolverFunc func(context.Context, VerifiedActor) (ResolvedAuthority, error)

func (f AuthorityResolverFunc) ResolveAuthority(ctx context.Context, actor VerifiedActor) (ResolvedAuthority, error) {
	return f(ctx, actor)
}

// Profile composes exact-request ASB verification with the generic quorum
// service. Approval replay is idempotently deduplicated by the shared quorum
// Store using an ID derived from the verified proof and exact request.
type Profile struct {
	Service     authorityquorum.Service
	Authorities AuthorityResolver
}

func (p Profile) Submit(
	ctx context.Context,
	request authorityquorum.ApprovalRequest,
	evidence Evidence,
) (authorityquorum.Approval, error) {
	if ctx == nil {
		return authorityquorum.Approval{}, errors.New("authorityquorum asbbinding: missing context")
	}
	if p.Authorities == nil {
		return authorityquorum.Approval{}, ErrMissingAuthorityResolver
	}
	digest, err := authorityquorum.ApprovalDigest(request)
	if err != nil {
		return authorityquorum.Approval{}, err
	}
	now := p.currentTime()
	accepted, actor, err := p.accept(digest, evidence, now)
	if err != nil {
		return authorityquorum.Approval{}, err
	}
	resolved, err := p.Authorities.ResolveAuthority(ctx, actor)
	if err != nil {
		return authorityquorum.Approval{}, fmt.Errorf("%w: %v", ErrUnknownAuthority, err)
	}
	if strings.TrimSpace(resolved.AuthorityID) == "" || strings.TrimSpace(resolved.AuthorityMapDigest) == "" {
		return authorityquorum.Approval{}, ErrUnknownAuthority
	}
	accepted.AuthorityID = resolved.AuthorityID
	accepted.AuthorityMapDigest = resolved.AuthorityMapDigest
	return p.Service.Approve(ctx, request, accepted)
}

func (p Profile) accept(
	digest authorityquorum.Digest,
	evidence Evidence,
	now time.Time,
) (authorityquorum.AcceptedAuthority, VerifiedActor, error) {
	if now.IsZero() || evidence.AcceptedUntil.IsZero() || !now.Before(evidence.AcceptedUntil) {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrInvalidProjection
	}
	if strings.TrimSpace(evidence.GrantJWT) == "" || strings.TrimSpace(evidence.SessionBindingJWT) == "" {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrMissingASBProof
	}
	expectedContextHash := authorityquorum.RequestContextSHA256(digest)
	expected := evidence.Options.ExpectedBinding
	if expected.RequestContextSHA256 != expectedContextHash ||
		strings.TrimSpace(expected.LeafPublicKeySHA256) == "" ||
		strings.TrimSpace(expected.TLSExporterSHA256) == "" ||
		strings.TrimSpace(expected.Nonce) == "" {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrRequestContextMismatch
	}

	policy := evidence.Options.Policy
	if err := policy.ValidateMode(); err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, fmt.Errorf("%w: %v", ErrAmbiguousPolicy, err)
	}
	if policy.Mode == identitypolicy.ModeDisabled || policy.SetMode == identitypolicy.SetModeContainsAll ||
		len(policy.Expected.AuthorizationDetails) != 0 {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrAmbiguousPolicy
	}
	policy.Mode = identitypolicy.ModeRequired
	policy.SetMode = identitypolicy.SetModeExact
	policy.Require.L6 = true
	policy.Expected.AuthorizationDetails = []string{authorityquorum.AuthorizationDetail(digest)}

	grantOptions := evidence.Options.Grant
	grantOptions.Now = now
	grant, err := clients.VerifyIdentityGrantJWT(evidence.GrantJWT, grantOptions)
	if err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, fmt.Errorf("authorityquorum asbbinding: verify grant: %w", err)
	}
	bindingOptions := evidence.Options.SessionBinding
	bindingOptions.Now = now
	bindingOptions, keyCapture := captureVerificationKey(bindingOptions)
	statement, err := clients.VerifySessionBindingJWT(evidence.SessionBindingJWT, bindingOptions)
	if err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, fmt.Errorf("authorityquorum asbbinding: verify session proof: %w", err)
	}
	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, fmt.Errorf("authorityquorum asbbinding: bind grant to session: %w", err)
	}
	if err := policy.ValidateAssertion(assertion, expected, now); err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, fmt.Errorf("authorityquorum asbbinding: verify identity policy: %w", err)
	}
	if statement.Binding.RequestContextSHA256 != expectedContextHash ||
		len(grant.Values.AuthorizationDetails) != 1 ||
		grant.Values.AuthorizationDetails[0] != authorityquorum.AuthorizationDetail(digest) {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrRequestContextMismatch
	}
	if strings.TrimSpace(assertion.Values.Agent) == "" || strings.TrimSpace(grant.JWTID) == "" ||
		strings.TrimSpace(statement.JWTID) == "" || strings.TrimSpace(statement.SignerKey) == "" {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrInvalidProjection
	}
	credentialDigest, err := keyCapture.finish(bindingOptions, statement.SignerKey)
	if err != nil {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrInvalidProjection
	}
	issuedAt := latestTime(grant.IssuedAt, statement.Binding.IssuedAt)
	expiresAt := earliestTime(grant.ExpiresAt, statement.Binding.ExpiresAt, evidence.AcceptedUntil)
	if issuedAt.IsZero() || expiresAt.IsZero() || now.Before(issuedAt) || !now.Before(expiresAt) {
		return authorityquorum.AcceptedAuthority{}, VerifiedActor{}, ErrInvalidProjection
	}
	return authorityquorum.AcceptedAuthority{
			ApprovalDigest: digest, PrincipalDigest: verifiedPrincipalDigest(grant.Issuer, assertion.Values.Agent),
			CredentialDigest: credentialDigest, AuthorizationID: grant.JWTID,
			ProofIssuer: evidence.Options.SessionBinding.ExpectedIssuer,
			ProofID:     statement.JWTID, ProofSignerKey: statement.SignerKey,
			Audience: grant.Audience, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}, VerifiedActor{
			GrantIssuer: grant.Issuer, ActorID: assertion.Values.Agent,
			ProofIssuer: evidence.Options.SessionBinding.ExpectedIssuer,
			SignerKey:   statement.SignerKey, CredentialDigest: credentialDigest,
		}, nil
}

func (p Profile) currentTime() time.Time {
	if p.Service.Now != nil {
		return p.Service.Now()
	}
	return time.Now()
}

func latestTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
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
