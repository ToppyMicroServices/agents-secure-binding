// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ParticipantResolver resolves internal Participant records. Implementations
// must not expose this lookup as a public people-search endpoint.
type ParticipantResolver interface {
	LoadParticipant(context.Context, string) (Participant, error)
}

// HumanReachabilityDirectory is deliberately separate from Store and from any
// Agent discovery API. Matching returns only privacy-minimized candidates;
// grants expose relay sessions rather than direct contacts.
type HumanReachabilityDirectory interface {
	RegisterHumanMatchConsent(context.Context, HumanMatchConsent) error
	RevokeHumanMatchConsent(context.Context, HumanMatchConsentRevocation) error
	MatchHumans(context.Context, AuthenticatedHumanMatchQuery) ([]HumanMatchCandidate, error)
	IssueHumanReachabilityGrant(context.Context, HumanReachabilityGrantDefinition) (HumanReachabilityGrant, error)
	LoadActiveHumanReachabilityGrant(context.Context, AuthenticatedReachabilityAccess) (HumanReachabilityGrant, error)
	RevokeHumanReachabilityGrant(context.Context, HumanReachabilityRevocation) error
}

var _ HumanReachabilityDirectory = (*MemoryReachabilityDirectory)(nil)

type candidateBinding struct {
	humanID     string
	requesterID string
}

type committedReachabilityGrant struct {
	grant                   HumanReachabilityGrant
	consentID               string
	humanID                 string
	approvalActorID         string
	approvalAuthorizationID string
	approvalProofID         string
}

type pendingHumanMatch struct {
	consentID string
	humanID   string
	candidate HumanMatchCandidate
}

// MemoryReachabilityDirectory is a concurrency-safe application stub. It
// stores no Email address, SNS account, or telephone number. Production relay
// resolution and encrypted contact storage remain external responsibilities.
type MemoryReachabilityDirectory struct {
	mu                      sync.RWMutex
	participants            ParticipantResolver
	now                     func() time.Time
	consents                map[string]HumanMatchConsent
	consentRevocations      map[string]HumanMatchConsentRevocation
	consentRevocationEvents map[string]HumanMatchConsentRevocation
	candidateBindings       map[string]candidateBinding
	grants                  map[string]committedReachabilityGrant
	grantRevocations        map[string]HumanReachabilityRevocation
	grantRevocationEvents   map[string]HumanReachabilityRevocation
}

// NewMemoryReachabilityDirectory returns an in-process privacy-safe directory
// stub using the local wall clock for expiry checks.
func NewMemoryReachabilityDirectory(participants ParticipantResolver) *MemoryReachabilityDirectory {
	return newMemoryReachabilityDirectory(participants, time.Now)
}

func newMemoryReachabilityDirectory(participants ParticipantResolver, now func() time.Time) *MemoryReachabilityDirectory {
	return &MemoryReachabilityDirectory{
		participants:            participants,
		now:                     now,
		consents:                make(map[string]HumanMatchConsent),
		consentRevocations:      make(map[string]HumanMatchConsentRevocation),
		consentRevocationEvents: make(map[string]HumanMatchConsentRevocation),
		candidateBindings:       make(map[string]candidateBinding),
		grants:                  make(map[string]committedReachabilityGrant),
		grantRevocations:        make(map[string]HumanReachabilityRevocation),
		grantRevocationEvents:   make(map[string]HumanReachabilityRevocation),
	}
}

// RegisterHumanMatchConsent registers one requester-scoped Human opt-in. An
// identical retry is idempotent; an opaque CandidateID can never be rebound to
// another Human or requester.
func (d *MemoryReachabilityDirectory) RegisterHumanMatchConsent(ctx context.Context, consent HumanMatchConsent) error {
	if err := consent.Validate(); err != nil {
		return err
	}
	human, requester, err := d.resolvePair(ctx, consent.HumanParticipantID, consent.RequesterParticipantID)
	if err != nil {
		return err
	}
	if human.Kind != ParticipantHuman {
		return invalidReachability("consent subject must be HUMAN")
	}
	if requester.Kind != ParticipantAgent {
		return invalidReachability("matching requester must be AGENT")
	}
	if human.Status != ParticipantActive || requester.Status != ParticipantActive {
		return ErrParticipantUnavailable
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.consents[consent.ConsentID]; ok {
		if sameHumanMatchConsent(existing, consent) {
			return nil
		}
		return fmt.Errorf("%w: consent %s", ErrEventConflict, consent.ConsentID)
	}
	binding := candidateBinding{humanID: consent.HumanParticipantID, requesterID: consent.RequesterParticipantID}
	if existing, ok := d.candidateBindings[consent.CandidateID]; ok && existing != binding {
		return invalidReachability("candidate_id is already bound in another pairwise context")
	}
	for consentID, existing := range d.consents {
		if sameConsentScope(existing, consent) && validityWindowsOverlap(existing.GrantedAt, existing.ExpiresAt, consent.GrantedAt, consent.ExpiresAt) {
			if revocation, revoked := d.consentRevocations[consentID]; !revoked || revocation.At.After(consent.GrantedAt) {
				return fmt.Errorf("%w: overlapping Human match consent", ErrAlreadyExists)
			}
		}
	}
	d.consents[consent.ConsentID] = consent
	d.candidateBindings[consent.CandidateID] = binding
	return nil
}

// RevokeHumanMatchConsent records an immutable Human withdrawal. A revoked
// consent is never returned, including for a backdated query.
func (d *MemoryReachabilityDirectory) RevokeHumanMatchConsent(ctx context.Context, revocation HumanMatchConsentRevocation) error {
	if err := revocation.Validate(); err != nil {
		return err
	}
	human, err := d.resolveParticipant(ctx, revocation.HumanParticipantID)
	if err != nil {
		return err
	}
	if human.Kind != ParticipantHuman {
		return invalidReachability("consent revoker must be HUMAN")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.consentRevocationEvents[revocation.EventID]; ok {
		if sameConsentRevocation(existing, revocation) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrEventConflict, revocation.EventID)
	}
	consent, ok := d.consents[revocation.ConsentID]
	if !ok || consent.HumanParticipantID != revocation.HumanParticipantID {
		return fmt.Errorf("%w: consent %s", ErrNotFound, revocation.ConsentID)
	}
	if revocation.At.Before(consent.GrantedAt) {
		return invalidReachability("revocation predates consent")
	}
	if _, revoked := d.consentRevocations[revocation.ConsentID]; revoked {
		return fmt.Errorf("%w: consent %s is already revoked", ErrAlreadyExists, revocation.ConsentID)
	}
	d.consentRevocations[revocation.ConsentID] = revocation
	d.consentRevocationEvents[revocation.EventID] = revocation
	return nil
}

// MatchHumans performs exact, consent-scoped matching. It never returns the
// Human Participant identifier or a direct contact endpoint.
func (d *MemoryReachabilityDirectory) MatchHumans(ctx context.Context, request AuthenticatedHumanMatchQuery) ([]HumanMatchCandidate, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	query := request.Query
	if d == nil || d.now == nil {
		return nil, invalidReachability("clock is required")
	}
	now := d.currentTime()
	if now.Before(request.IssuedAt) || !now.Before(request.ExpiresAt) {
		return nil, invalidReachability("match request is not currently valid")
	}
	requester, err := d.resolveParticipant(ctx, query.RequesterParticipantID)
	if err != nil {
		return nil, err
	}
	if requester.Kind != ParticipantAgent {
		return nil, invalidReachability("matching requester must be AGENT")
	}
	if requester.Status != ParticipantActive {
		return nil, ErrParticipantUnavailable
	}
	d.mu.RLock()
	pending := make([]pendingHumanMatch, 0, len(d.consents))
	for consentID, consent := range d.consents {
		if _, revoked := d.consentRevocations[consentID]; revoked {
			continue
		}
		if now.Before(consent.GrantedAt) || !now.Before(consent.ExpiresAt) {
			continue
		}
		if consent.RequesterParticipantID != query.RequesterParticipantID ||
			consent.Purpose != query.Purpose ||
			consent.Capability != query.Capability ||
			consent.Channel != query.Channel {
			continue
		}
		pending = append(pending, pendingHumanMatch{
			consentID: consentID,
			humanID:   consent.HumanParticipantID,
			candidate: HumanMatchCandidate{
				CandidateID:       consent.CandidateID,
				Capability:        consent.Capability,
				Channel:           consent.Channel,
				ContactRequestRef: consent.ContactRequestRef,
				ExpiresAt:         consent.ExpiresAt,
			},
		})
	}
	d.mu.RUnlock()

	active := make([]pendingHumanMatch, 0, len(pending))
	for _, match := range pending {
		human, err := d.resolveParticipant(ctx, match.humanID)
		if err == nil && human.Kind == ParticipantHuman && human.Status == ParticipantActive {
			active = append(active, match)
		}
	}

	// Recheck consent state after external Participant resolution so a
	// concurrent revocation cannot be returned after it commits.
	now = d.currentTime()
	d.mu.RLock()
	defer d.mu.RUnlock()
	byCandidate := make(map[string]HumanMatchCandidate)
	for _, match := range active {
		consent, ok := d.consents[match.consentID]
		if !ok || consent.HumanParticipantID != match.humanID {
			continue
		}
		if _, revoked := d.consentRevocations[match.consentID]; revoked {
			continue
		}
		if now.Before(consent.GrantedAt) || !now.Before(consent.ExpiresAt) {
			continue
		}
		byCandidate[match.candidate.CandidateID] = match.candidate
	}
	ids := make([]string, 0, len(byCandidate))
	for candidateID := range byCandidate {
		ids = append(ids, candidateID)
	}
	sort.Strings(ids)
	if len(ids) > int(query.Limit) {
		ids = ids[:query.Limit]
	}
	results := make([]HumanMatchCandidate, 0, len(ids))
	for _, candidateID := range ids {
		results = append(results, byCandidate[candidateID])
	}
	return results, nil
}

// IssueHumanReachabilityGrant creates a requester-facing relay capability only
// when it is bound to a currently active Human consent and approval.
func (d *MemoryReachabilityDirectory) IssueHumanReachabilityGrant(ctx context.Context, def HumanReachabilityGrantDefinition) (HumanReachabilityGrant, error) {
	if err := validateID("consent_id", def.ConsentID); err != nil {
		return HumanReachabilityGrant{}, invalidReachabilityError(err)
	}
	if err := validateID("approved_by_participant_id", def.ApprovedByParticipantID); err != nil {
		return HumanReachabilityGrant{}, invalidReachabilityError(err)
	}
	for field, value := range map[string]string{
		"approval_actor_id":         def.ApprovalActorID,
		"approval_authorization_id": def.ApprovalAuthorizationID,
		"approval_proof_id":         def.ApprovalProofID,
	} {
		if err := validateID(field, value); err != nil {
			return HumanReachabilityGrant{}, invalidReachabilityError(err)
		}
	}
	grant := HumanReachabilityGrant{
		Schema:                 HumanReachabilityGrantSchemaV1,
		GrantID:                def.GrantID,
		CandidateID:            def.CandidateID,
		RequesterParticipantID: def.RequesterParticipantID,
		Purpose:                def.Purpose,
		Capability:             def.Capability,
		Channel:                def.Channel,
		RelaySessionRef:        def.RelaySessionRef,
		IssuedAt:               def.IssuedAt,
		ExpiresAt:              def.ExpiresAt,
	}
	if err := grant.Validate(); err != nil {
		return HumanReachabilityGrant{}, err
	}
	human, requester, err := d.resolvePair(ctx, def.ApprovedByParticipantID, def.RequesterParticipantID)
	if err != nil {
		return HumanReachabilityGrant{}, err
	}
	if human.Kind != ParticipantHuman || requester.Kind != ParticipantAgent {
		return HumanReachabilityGrant{}, invalidReachability("grant approval must bind a HUMAN to an AGENT requester")
	}
	if human.Status != ParticipantActive || requester.Status != ParticipantActive {
		return HumanReachabilityGrant{}, ErrParticipantUnavailable
	}

	if d.now == nil {
		return HumanReachabilityGrant{}, invalidReachability("clock is required")
	}
	now := d.currentTime()
	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.grants[grant.GrantID]; ok {
		if existing.consentID == def.ConsentID &&
			existing.humanID == def.ApprovedByParticipantID &&
			existing.approvalActorID == def.ApprovalActorID &&
			existing.approvalAuthorizationID == def.ApprovalAuthorizationID &&
			existing.approvalProofID == def.ApprovalProofID &&
			sameReachabilityGrant(existing.grant, grant) {
			return existing.grant, nil
		}
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrEventConflict, grant.GrantID)
	}
	consent, ok := d.consents[def.ConsentID]
	if !ok {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: consent %s", ErrNotFound, def.ConsentID)
	}
	if _, revoked := d.consentRevocations[def.ConsentID]; revoked {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: consent %s", ErrNotFound, def.ConsentID)
	}
	if now.Before(consent.GrantedAt) || !now.Before(consent.ExpiresAt) {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: consent %s", ErrNotFound, def.ConsentID)
	}
	if consent.HumanParticipantID != def.ApprovedByParticipantID ||
		consent.CandidateID != grant.CandidateID ||
		consent.RequesterParticipantID != grant.RequesterParticipantID ||
		consent.Purpose != grant.Purpose ||
		consent.Capability != grant.Capability ||
		consent.Channel != grant.Channel {
		return HumanReachabilityGrant{}, invalidReachability("grant does not match Human consent")
	}
	if grant.IssuedAt.Before(consent.GrantedAt) || !grant.IssuedAt.Before(consent.ExpiresAt) || grant.ExpiresAt.After(consent.ExpiresAt) {
		return HumanReachabilityGrant{}, invalidReachability("grant validity exceeds Human consent")
	}
	if now.Before(grant.IssuedAt) || !now.Before(grant.ExpiresAt) {
		return HumanReachabilityGrant{}, invalidReachability("grant is not currently active")
	}
	d.grants[grant.GrantID] = committedReachabilityGrant{
		grant:                   grant,
		consentID:               def.ConsentID,
		humanID:                 def.ApprovedByParticipantID,
		approvalActorID:         def.ApprovalActorID,
		approvalAuthorizationID: def.ApprovalAuthorizationID,
		approvalProofID:         def.ApprovalProofID,
	}
	return grant, nil
}

// LoadActiveHumanReachabilityGrant returns a relay grant only for its exact
// requester, purpose, and channel. Missing, expired, revoked, and mismatched
// grants intentionally share ErrNotFound to reduce probing information.
func (d *MemoryReachabilityDirectory) LoadActiveHumanReachabilityGrant(ctx context.Context, access AuthenticatedReachabilityAccess) (HumanReachabilityGrant, error) {
	if err := access.Validate(); err != nil {
		return HumanReachabilityGrant{}, err
	}
	if d == nil || d.now == nil {
		return HumanReachabilityGrant{}, invalidReachability("clock is required")
	}
	now := d.currentTime()
	if now.Before(access.IssuedAt) || !now.Before(access.ExpiresAt) {
		return HumanReachabilityGrant{}, invalidReachability("grant access request is not currently valid")
	}
	requester, err := d.resolveParticipant(ctx, access.RequesterParticipantID)
	if err != nil {
		return HumanReachabilityGrant{}, err
	}
	if requester.Kind != ParticipantAgent || requester.Status != ParticipantActive {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}

	d.mu.RLock()
	committed, ok := d.grants[access.GrantID]
	if !ok ||
		committed.grant.RequesterParticipantID != access.RequesterParticipantID ||
		committed.grant.Purpose != access.Purpose ||
		committed.grant.Capability != access.Capability ||
		committed.grant.Channel != access.Channel ||
		now.Before(committed.grant.IssuedAt) ||
		!now.Before(committed.grant.ExpiresAt) {
		d.mu.RUnlock()
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	if _, revoked := d.grantRevocations[access.GrantID]; revoked {
		d.mu.RUnlock()
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	if _, revoked := d.consentRevocations[committed.consentID]; revoked {
		d.mu.RUnlock()
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	d.mu.RUnlock()

	human, err := d.resolveParticipant(ctx, committed.humanID)
	if err != nil || human.Kind != ParticipantHuman || human.Status != ParticipantActive {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}

	// Recheck after external resolution so a concurrent revocation cannot be
	// returned after it commits.
	now = d.currentTime()
	d.mu.RLock()
	defer d.mu.RUnlock()
	latest, ok := d.grants[access.GrantID]
	if !ok || !sameReachabilityGrant(latest.grant, committed.grant) ||
		now.Before(latest.grant.IssuedAt) || !now.Before(latest.grant.ExpiresAt) {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	if _, revoked := d.grantRevocations[access.GrantID]; revoked {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	if _, revoked := d.consentRevocations[latest.consentID]; revoked {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: grant %s", ErrNotFound, access.GrantID)
	}
	return latest.grant, nil
}

// RevokeHumanReachabilityGrant records an immutable revocation by either the
// consenting Human or the exact Agent requester.
func (d *MemoryReachabilityDirectory) RevokeHumanReachabilityGrant(ctx context.Context, revocation HumanReachabilityRevocation) error {
	if err := revocation.Validate(); err != nil {
		return err
	}
	participant, err := d.resolveParticipant(ctx, revocation.ParticipantID)
	if err != nil {
		return err
	}
	if participant.Kind != ParticipantHuman && participant.Kind != ParticipantAgent {
		return invalidReachability("grant revoker must be HUMAN or AGENT")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.grantRevocationEvents[revocation.EventID]; ok {
		if sameReachabilityRevocation(existing, revocation) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrEventConflict, revocation.EventID)
	}
	committed, ok := d.grants[revocation.GrantID]
	if !ok || (revocation.ParticipantID != committed.humanID && revocation.ParticipantID != committed.grant.RequesterParticipantID) {
		return fmt.Errorf("%w: grant %s", ErrNotFound, revocation.GrantID)
	}
	if revocation.At.Before(committed.grant.IssuedAt) {
		return invalidReachability("revocation predates grant")
	}
	if _, revoked := d.grantRevocations[revocation.GrantID]; revoked {
		return fmt.Errorf("%w: grant %s is already revoked", ErrAlreadyExists, revocation.GrantID)
	}
	d.grantRevocations[revocation.GrantID] = revocation
	d.grantRevocationEvents[revocation.EventID] = revocation
	return nil
}

func (d *MemoryReachabilityDirectory) resolvePair(ctx context.Context, firstID, secondID string) (Participant, Participant, error) {
	first, err := d.resolveParticipant(ctx, firstID)
	if err != nil {
		return Participant{}, Participant{}, err
	}
	second, err := d.resolveParticipant(ctx, secondID)
	if err != nil {
		return Participant{}, Participant{}, err
	}
	return first, second, nil
}

func (d *MemoryReachabilityDirectory) resolveParticipant(ctx context.Context, participantID string) (Participant, error) {
	if d == nil || d.participants == nil {
		return Participant{}, invalidReachability("Participant resolver is required")
	}
	return d.participants.LoadParticipant(ctx, participantID)
}

func (d *MemoryReachabilityDirectory) currentTime() time.Time {
	if d == nil || d.now == nil {
		return time.Time{}
	}
	return d.now()
}

func sameHumanMatchConsent(a, b HumanMatchConsent) bool {
	return a.Schema == b.Schema &&
		a.ConsentID == b.ConsentID &&
		a.HumanParticipantID == b.HumanParticipantID &&
		a.CandidateID == b.CandidateID &&
		a.RequesterParticipantID == b.RequesterParticipantID &&
		a.Purpose == b.Purpose &&
		a.Capability == b.Capability &&
		a.Channel == b.Channel &&
		a.ContactRequestRef == b.ContactRequestRef &&
		a.ActorID == b.ActorID &&
		a.AuthorizationID == b.AuthorizationID &&
		a.ProofID == b.ProofID &&
		a.GrantedAt.Equal(b.GrantedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}

func sameConsentScope(a, b HumanMatchConsent) bool {
	return a.HumanParticipantID == b.HumanParticipantID &&
		a.CandidateID == b.CandidateID &&
		a.RequesterParticipantID == b.RequesterParticipantID &&
		a.Purpose == b.Purpose &&
		a.Capability == b.Capability &&
		a.Channel == b.Channel
}

func validityWindowsOverlap(aStart, aEnd, bStart, bEnd time.Time) bool {
	return aStart.Before(bEnd) && bStart.Before(aEnd)
}

func sameConsentRevocation(a, b HumanMatchConsentRevocation) bool {
	return a.Schema == b.Schema &&
		a.EventID == b.EventID &&
		a.ConsentID == b.ConsentID &&
		a.HumanParticipantID == b.HumanParticipantID &&
		a.ActorID == b.ActorID &&
		a.AuthorizationID == b.AuthorizationID &&
		a.ProofID == b.ProofID &&
		a.At.Equal(b.At)
}

func sameReachabilityGrant(a, b HumanReachabilityGrant) bool {
	return a.Schema == b.Schema &&
		a.GrantID == b.GrantID &&
		a.CandidateID == b.CandidateID &&
		a.RequesterParticipantID == b.RequesterParticipantID &&
		a.Purpose == b.Purpose &&
		a.Capability == b.Capability &&
		a.Channel == b.Channel &&
		a.RelaySessionRef == b.RelaySessionRef &&
		a.IssuedAt.Equal(b.IssuedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}

func sameReachabilityRevocation(a, b HumanReachabilityRevocation) bool {
	return a.Schema == b.Schema &&
		a.EventID == b.EventID &&
		a.GrantID == b.GrantID &&
		a.ParticipantID == b.ParticipantID &&
		a.ActorID == b.ActorID &&
		a.AuthorizationID == b.AuthorizationID &&
		a.ProofID == b.ProofID &&
		a.At.Equal(b.At)
}
