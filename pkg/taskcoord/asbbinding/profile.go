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
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

var (
	ErrMissingParticipantResolver = errors.New("asbbinding: missing Participant resolver")
	ErrHumanRequired              = errors.New("asbbinding: Participant is not HUMAN")
	ErrHumanInactive              = errors.New("asbbinding: Human Participant is not active")
	ErrRequestContextMismatch     = errors.New("asbbinding: ASB request context does not bind the Human request")
	ErrAmbiguousPolicy            = errors.New("asbbinding: application authorization policy is ambiguous")
	ErrMissingASBProof            = errors.New("asbbinding: missing ASB proof material")
	ErrInvalidProjection          = errors.New("asbbinding: invalid verified projection")
)

// Evidence carries signed ASB material and verifier-local acceptance state.
// Options.ExpectedBinding and AcceptedUntil must come from trusted transport
// and policy adapters; peer-supplied headers or request fields are not valid
// sources for either value.
type Evidence struct {
	GrantJWT          string
	SessionBindingJWT string
	Options           clients.SessionIdentityJWTOptions
	AcceptedUntil     time.Time
}

// Profile composes an exact Human request with the existing ASB verifier.
// Participants must resolve trusted registry state, not peer-supplied records.
type Profile struct {
	Participants taskcoord.ParticipantResolver
	Now          func() time.Time
}

func (p Profile) Offer(ctx context.Context, request OfferRequest, evidence Evidence) (taskcoord.Transition, error) {
	digest, err := OfferDigest(request)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	now := p.currentTime()
	if request.DueAt != nil && !request.DueAt.After(now) {
		return taskcoord.Transition{}, invalid("due_at must be after verifier time")
	}
	accepted, err := p.accept(ctx, request.ParticipantID, digest, evidence, now)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	target, err := p.resolveParticipant(ctx, request.TargetParticipantID)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	if target.Status != taskcoord.ParticipantActive {
		return taskcoord.Transition{}, taskcoord.ErrParticipantUnavailable
	}
	definition := taskcoord.AssignmentDefinition{
		EventID:         request.EventID,
		AssignmentID:    request.AssignmentID,
		TaskID:          request.TaskID,
		ParticipantID:   request.TargetParticipantID,
		Role:            request.Role,
		AuthorityDigest: request.AuthorityDigest,
		OfferedAt:       now,
		DueAt:           cloneTime(request.DueAt),
	}
	auth := accepted.operation(taskcoord.OperationOffer, request.TaskID, request.AssignmentID)
	auth.TargetParticipantID = request.TargetParticipantID
	transition, err := taskcoord.Offer(definition, target, auth)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	if err := accepted.commitReplay(); err != nil {
		return taskcoord.Transition{}, err
	}
	return transition, nil
}

func (p Profile) Apply(ctx context.Context, current taskcoord.Assignment, request TransitionRequest, evidence Evidence) (taskcoord.Transition, error) {
	if err := current.Validate(); err != nil {
		return taskcoord.Transition{}, err
	}
	if current.TaskID != request.TaskID || current.AssignmentID != request.AssignmentID {
		return taskcoord.Transition{}, invalid("request target does not match current Assignment")
	}
	if current.Revision != request.ExpectedRevision {
		return taskcoord.Transition{}, invalid("request revision does not match current Assignment")
	}
	digest, err := TransitionDigest(request)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	now := p.currentTime()
	accepted, err := p.accept(ctx, request.ParticipantID, digest, evidence, now)
	if err != nil {
		return taskcoord.Transition{}, err
	}
	transition, err := taskcoord.Apply(current, taskcoord.Event{
		ID:               request.EventID,
		Kind:             request.Operation,
		ExpectedRevision: request.ExpectedRevision,
		At:               now,
		Detail:           request.Detail,
		EvidenceRef:      request.EvidenceRef,
		Auth:             accepted.operation(request.Operation, request.TaskID, request.AssignmentID),
	})
	if err != nil {
		return taskcoord.Transition{}, err
	}
	if err := accepted.commitReplay(); err != nil {
		return taskcoord.Transition{}, err
	}
	return transition, nil
}

func (p Profile) Delegate(
	ctx context.Context,
	parent taskcoord.Assignment,
	request DelegationRequest,
	verified taskcoord.VerifiedDelegation,
	evidence Evidence,
) (taskcoord.DelegationTransition, error) {
	if err := parent.Validate(); err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	if err := verified.Validate(); err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	if verified.DecisionID != request.DecisionID {
		return taskcoord.DelegationTransition{}, invalid("verified delegation decision does not match request")
	}
	if parent.TaskID != request.ParentTaskID || parent.AssignmentID != request.ParentAssignmentID {
		return taskcoord.DelegationTransition{}, invalid("request parent does not match current Assignment")
	}
	if parent.Revision != request.ExpectedRevision {
		return taskcoord.DelegationTransition{}, invalid("request revision does not match current Assignment")
	}
	digest, err := DelegationDigest(request)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	now := p.currentTime()
	if request.DueAt != nil && !request.DueAt.After(now) {
		return taskcoord.DelegationTransition{}, invalid("due_at must be after verifier time")
	}
	accepted, err := p.accept(ctx, request.ParticipantID, digest, evidence, now)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	target, err := p.resolveParticipant(ctx, request.TargetParticipantID)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	if target.Status != taskcoord.ParticipantActive {
		return taskcoord.DelegationTransition{}, taskcoord.ErrParticipantUnavailable
	}
	child := taskcoord.AssignmentDefinition{
		EventID:            request.ChildEventID,
		AssignmentID:       request.ChildAssignmentID,
		TaskID:             request.ChildTaskID,
		ParticipantID:      request.TargetParticipantID,
		Role:               request.Role,
		AuthorityDigest:    request.AuthorityDigest,
		ParentAssignmentID: request.ParentAssignmentID,
		OfferedAt:          now,
		DueAt:              cloneTime(request.DueAt),
	}
	auth := accepted.operation(taskcoord.OperationDelegate, request.ParentTaskID, request.ParentAssignmentID)
	auth.TargetTaskID = request.ChildTaskID
	auth.TargetAssignmentID = request.ChildAssignmentID
	auth.TargetParticipantID = request.TargetParticipantID
	event := taskcoord.Event{
		ID:               request.EventID,
		Kind:             taskcoord.OperationDelegate,
		ExpectedRevision: request.ExpectedRevision,
		At:               now,
		Detail:           request.Detail,
		EvidenceRef:      request.EvidenceRef,
		Auth:             auth,
	}
	transition, err := taskcoord.Delegate(parent, accepted.human, target, child, event, verified)
	if err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	if err := accepted.commitReplay(); err != nil {
		return taskcoord.DelegationTransition{}, err
	}
	return transition, nil
}

func (p Profile) NewInteractionEvent(ctx context.Context, request InteractionRequest, evidence Evidence) (taskcoord.InteractionEvent, error) {
	digest, err := InteractionDigest(request)
	if err != nil {
		return taskcoord.InteractionEvent{}, err
	}
	now := p.currentTime()
	accepted, err := p.accept(ctx, request.ParticipantID, digest, evidence, now)
	if err != nil {
		return taskcoord.InteractionEvent{}, err
	}
	definition := taskcoord.InteractionEventDefinition{
		EventID:       request.EventID,
		InteractionID: request.InteractionID,
		TaskID:        request.TaskID,
		AssignmentID:  request.AssignmentID,
		Kind:          request.Kind,
		InReplyTo:     request.InReplyTo,
		Supersedes:    request.Supersedes,
		Finality:      request.Finality,
		ContentRef:    request.ContentRef,
		ContentDigest: request.ContentDigest,
		EvidenceRef:   request.EvidenceRef,
		At:            now,
	}
	auth := taskcoord.AuthenticatedInteraction{
		ActorID:         accepted.actorID,
		ParticipantID:   request.ParticipantID,
		AuthorizationID: accepted.authorizationID,
		ProofID:         accepted.proofID,
		EventID:         request.EventID,
		InteractionID:   request.InteractionID,
		TaskID:          request.TaskID,
		AssignmentID:    request.AssignmentID,
		Kind:            request.Kind,
		InReplyTo:       request.InReplyTo,
		Supersedes:      request.Supersedes,
		Finality:        request.Finality,
		ContentRef:      request.ContentRef,
		ContentDigest:   request.ContentDigest,
		EvidenceRef:     request.EvidenceRef,
		At:              now,
		VerifierNonce:   accepted.nonce,
		IssuedAt:        accepted.issuedAt,
		ExpiresAt:       accepted.expiresAt,
	}
	event, err := taskcoord.NewInteractionEvent(definition, auth)
	if err != nil {
		return taskcoord.InteractionEvent{}, err
	}
	if err := accepted.commitReplay(); err != nil {
		return taskcoord.InteractionEvent{}, err
	}
	return event, nil
}

type acceptance struct {
	human           taskcoord.Participant
	actorID         string
	authorizationID string
	proofID         string
	nonce           string
	issuedAt        time.Time
	expiresAt       time.Time
	replay          identitypolicy.ReplayCache
	statement       identitypolicy.VerifiedSessionBindingStatement
}

func (a acceptance) commitReplay() error {
	if err := identitypolicy.MarkSessionBindingUsed(a.replay, a.statement); err != nil {
		return fmt.Errorf("asbbinding: commit ASB replay state: %w", err)
	}
	return nil
}

func (a acceptance) operation(kind taskcoord.OperationKind, taskID, assignmentID string) taskcoord.AuthenticatedOperation {
	return taskcoord.AuthenticatedOperation{
		ActorID:         a.actorID,
		ParticipantID:   a.human.ParticipantID,
		AuthorizationID: a.authorizationID,
		ProofID:         a.proofID,
		Operation:       kind,
		TaskID:          taskID,
		AssignmentID:    assignmentID,
		VerifierNonce:   a.nonce,
		IssuedAt:        a.issuedAt,
		ExpiresAt:       a.expiresAt,
	}
}

func (p Profile) accept(ctx context.Context, participantID string, digest Digest, evidence Evidence, now time.Time) (acceptance, error) {
	if ctx == nil {
		return acceptance{}, errors.New("asbbinding: missing context")
	}
	if now.IsZero() {
		return acceptance{}, ErrInvalidProjection
	}
	if strings.TrimSpace(evidence.GrantJWT) == "" || strings.TrimSpace(evidence.SessionBindingJWT) == "" {
		return acceptance{}, ErrMissingASBProof
	}
	if evidence.Options.ReplayCache == nil {
		return acceptance{}, clients.ErrMissingReplayCache
	}
	expectedContextHash := RequestContextSHA256(digest)
	if evidence.Options.ExpectedBinding.RequestContextSHA256 != expectedContextHash ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.LeafPublicKeySHA256) == "" ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.TLSExporterSHA256) == "" ||
		strings.TrimSpace(evidence.Options.ExpectedBinding.Nonce) == "" {
		return acceptance{}, ErrRequestContextMismatch
	}

	policy := evidence.Options.Policy
	if policy.Mode == identitypolicy.ModeDisabled || policy.SetMode == identitypolicy.SetModeContainsAll ||
		len(policy.Expected.AuthorizationDetails) != 0 {
		return acceptance{}, ErrAmbiguousPolicy
	}
	policy.Mode = identitypolicy.ModeRequired
	policy.SetMode = identitypolicy.SetModeExact
	policy.Require.L6 = true
	policy.Expected.AuthorizationDetails = []string{AuthorizationDetail(digest)}

	grantOptions := evidence.Options.Grant
	grantOptions.Now = now
	grant, err := clients.VerifyIdentityGrantJWT(evidence.GrantJWT, grantOptions)
	if err != nil {
		return acceptance{}, fmt.Errorf("asbbinding: verify ASB grant: %w", err)
	}
	bindingOptions := evidence.Options.SessionBinding
	bindingOptions.Now = now
	statement, err := clients.VerifySessionBindingJWT(evidence.SessionBindingJWT, bindingOptions)
	if err != nil {
		return acceptance{}, fmt.Errorf("asbbinding: verify ASB session binding: %w", err)
	}
	assertion, err := identitypolicy.NewAssertionFromSessionBinding(grant, statement, now)
	if err != nil {
		return acceptance{}, fmt.Errorf("asbbinding: bind ASB grant to session: %w", err)
	}
	if err := policy.ValidateAssertion(assertion, evidence.Options.ExpectedBinding, now); err != nil {
		return acceptance{}, fmt.Errorf("asbbinding: verify ASB identity policy: %w", err)
	}
	if statement.Binding.RequestContextSHA256 != expectedContextHash ||
		len(grant.Values.AuthorizationDetails) != 1 ||
		grant.Values.AuthorizationDetails[0] != AuthorizationDetail(digest) {
		return acceptance{}, ErrRequestContextMismatch
	}
	actorID := assertion.Values.Agent
	if err := validateID("actor_id", actorID); err != nil {
		return acceptance{}, fmt.Errorf("%w: %v", ErrInvalidProjection, err)
	}
	if err := validateID("authorization_id", grant.JWTID); err != nil {
		return acceptance{}, fmt.Errorf("%w: %v", ErrInvalidProjection, err)
	}
	if err := validateID("proof_id", statement.JWTID); err != nil {
		return acceptance{}, fmt.Errorf("%w: %v", ErrInvalidProjection, err)
	}
	if grant.IssuedAt.IsZero() || statement.Binding.IssuedAt.IsZero() ||
		grant.ExpiresAt.IsZero() || statement.Binding.ExpiresAt.IsZero() {
		return acceptance{}, ErrInvalidProjection
	}
	issuedAt := latestTime(grant.IssuedAt, statement.Binding.IssuedAt)
	expiresAt := earliestTime(grant.ExpiresAt, statement.Binding.ExpiresAt, evidence.AcceptedUntil)
	if issuedAt.IsZero() || expiresAt.IsZero() || now.Before(issuedAt) || !now.Before(expiresAt) {
		return acceptance{}, ErrInvalidProjection
	}
	human, err := p.resolveHuman(ctx, participantID)
	if err != nil {
		return acceptance{}, err
	}
	return acceptance{
		human:           human,
		actorID:         actorID,
		authorizationID: grant.JWTID,
		proofID:         statement.JWTID,
		nonce:           statement.Binding.Nonce,
		issuedAt:        issuedAt,
		expiresAt:       expiresAt,
		replay:          evidence.Options.ReplayCache,
		statement:       statement,
	}, nil
}

func (p Profile) resolveHuman(ctx context.Context, participantID string) (taskcoord.Participant, error) {
	participant, err := p.resolveParticipant(ctx, participantID)
	if err != nil {
		return taskcoord.Participant{}, err
	}
	if participant.Kind != taskcoord.ParticipantHuman {
		return taskcoord.Participant{}, ErrHumanRequired
	}
	if participant.Status != taskcoord.ParticipantActive {
		return taskcoord.Participant{}, ErrHumanInactive
	}
	return participant, nil
}

func (p Profile) resolveParticipant(ctx context.Context, participantID string) (taskcoord.Participant, error) {
	if ctx == nil {
		return taskcoord.Participant{}, errors.New("asbbinding: missing context")
	}
	if p.Participants == nil {
		return taskcoord.Participant{}, ErrMissingParticipantResolver
	}
	participant, err := p.Participants.LoadParticipant(ctx, participantID)
	if err != nil {
		return taskcoord.Participant{}, err
	}
	if err := participant.Validate(); err != nil {
		return taskcoord.Participant{}, err
	}
	if participant.ParticipantID != participantID {
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

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
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
