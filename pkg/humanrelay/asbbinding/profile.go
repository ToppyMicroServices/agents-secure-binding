// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

var (
	ErrMissingParticipantResolver = errors.New("human relay binding: missing Participant resolver")
	ErrAgentRequired              = errors.New("human relay binding: requester Participant is not AGENT")
	ErrAgentInactive              = errors.New("human relay binding: requester Agent is not active")
	ErrRequestContextMismatch     = errors.New("human relay binding: ASB context does not bind the relay intent")
	ErrAmbiguousPolicy            = errors.New("human relay binding: application authorization policy is ambiguous")
	ErrMissingASBProof            = errors.New("human relay binding: missing ASB proof material")
	ErrInvalidProjection          = errors.New("human relay binding: invalid verified projection")
)

type Evidence struct {
	GrantJWT          string
	SessionBindingJWT string
	Options           clients.SessionIdentityJWTOptions
	AcceptedUntil     time.Time
}

// Profile verifies an exact Agent relay intent and consumes the ASB replay
// key before returning a TaskCoord-safe projection.
type Profile struct {
	Participants taskcoord.ParticipantResolver
	Now          func() time.Time
}

func (p Profile) VerifyAndConsume(ctx context.Context, request humanrelay.RelayIntentRequest, evidence Evidence) (humanrelay.AuthenticatedRelayIntent, error) {
	if ctx == nil {
		return humanrelay.AuthenticatedRelayIntent{}, errors.New("human relay binding: missing context")
	}
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, err
	}
	now := p.currentTime().UTC()
	if now.IsZero() {
		return humanrelay.AuthenticatedRelayIntent{}, ErrInvalidProjection
	}
	if strings.TrimSpace(evidence.GrantJWT) == "" || strings.TrimSpace(evidence.SessionBindingJWT) == "" {
		return humanrelay.AuthenticatedRelayIntent{}, ErrMissingASBProof
	}
	if isNilDependency(evidence.Options.ReplayCache) {
		return humanrelay.AuthenticatedRelayIntent{}, clients.ErrMissingReplayCache
	}
	expectedContextHash := RequestContextSHA256(digest)
	if evidence.Options.ExpectedBinding.RequestContextSHA256 != expectedContextHash ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.LeafPublicKeySHA256) == "" ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.TLSExporterSHA256) == "" ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.Nonce) == "" {
		return humanrelay.AuthenticatedRelayIntent{}, ErrRequestContextMismatch
	}
	policy := evidence.Options.Policy
	if policy.Mode == identitypolicy.ModeDisabled || policy.SetMode == identitypolicy.SetModeContainsAll ||
		len(policy.Expected.AuthorizationDetails) != 0 {
		return humanrelay.AuthenticatedRelayIntent{}, ErrAmbiguousPolicy
	}
	policy.Mode = identitypolicy.ModeRequired
	policy.SetMode = identitypolicy.SetModeExact
	policy.Require.L6 = true
	policy.Expected.AuthorizationDetails = []string{AuthorizationDetail(digest)}

	grantOptions := evidence.Options.Grant
	grantOptions.Now = now
	grant, err := clients.VerifyIdentityGrantJWT(evidence.GrantJWT, grantOptions)
	if err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("human relay binding: verify grant: %w", err)
	}
	bindingOptions := evidence.Options.SessionBinding
	bindingOptions.Now = now
	statement, err := clients.VerifySessionBindingJWT(evidence.SessionBindingJWT, bindingOptions)
	if err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("human relay binding: verify session binding: %w", err)
	}
	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("human relay binding: bind grant to session: %w", err)
	}
	if err := policy.ValidateAssertion(assertion, evidence.Options.ExpectedBinding, now); err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("human relay binding: verify identity policy: %w", err)
	}
	if statement.Binding.RequestContextSHA256 != expectedContextHash || len(grant.Values.AuthorizationDetails) != 1 ||
		grant.Values.AuthorizationDetails[0] != AuthorizationDetail(digest) {
		return humanrelay.AuthenticatedRelayIntent{}, ErrRequestContextMismatch
	}
	for field, value := range map[string]string{
		"actor_id": assertion.Values.Agent, "authorization_id": grant.JWTID, "proof_id": statement.JWTID,
	} {
		if strings.TrimSpace(value) == "" {
			return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("%w: %s is missing", ErrInvalidProjection, field)
		}
	}
	issuedAt := latestTime(grant.IssuedAt, statement.Binding.IssuedAt)
	expiresAt := earliestTime(grant.ExpiresAt, statement.Binding.ExpiresAt, evidence.AcceptedUntil)
	if issuedAt.IsZero() || expiresAt.IsZero() || now.Before(issuedAt) || !now.Before(expiresAt) {
		return humanrelay.AuthenticatedRelayIntent{}, ErrInvalidProjection
	}
	requester, err := p.resolveParticipant(ctx, request.RequesterParticipantID)
	if err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, err
	}
	if requester.Kind != taskcoord.ParticipantAgent {
		return humanrelay.AuthenticatedRelayIntent{}, ErrAgentRequired
	}
	if requester.Status != taskcoord.ParticipantActive {
		return humanrelay.AuthenticatedRelayIntent{}, ErrAgentInactive
	}
	if err := identitypolicy.MarkSessionBindingUsed(evidence.Options.ReplayCache, statement); err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, fmt.Errorf("human relay binding: commit replay state: %w", err)
	}
	projection := humanrelay.AuthenticatedRelayIntent{
		RequestDigest: digest.String(), ActorID: assertion.Values.Agent,
		AuthorizationID: grant.JWTID, ProofID: statement.JWTID, VerifierNonce: statement.Binding.Nonce,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	if err := projection.Validate(); err != nil {
		return humanrelay.AuthenticatedRelayIntent{}, err
	}
	return projection, nil
}

func (p Profile) resolveParticipant(ctx context.Context, participantID string) (taskcoord.Participant, error) {
	if isNilDependency(p.Participants) {
		return taskcoord.Participant{}, ErrMissingParticipantResolver
	}
	participant, err := p.Participants.LoadParticipant(ctx, participantID)
	if err != nil {
		return taskcoord.Participant{}, err
	}
	if err := participant.Validate(); err != nil || participant.ParticipantID != participantID {
		return taskcoord.Participant{}, ErrInvalidProjection
	}
	return participant, nil
}

func (p Profile) currentTime() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func isNilDependency(dependency any) bool {
	if dependency == nil {
		return true
	}
	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func latestTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if latest.IsZero() || value.After(latest) {
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
