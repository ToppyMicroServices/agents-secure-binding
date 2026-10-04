// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
)

const maxReachabilityStateBytes = 32 << 20

type durableReachabilityState struct {
	Schema             string                                      `json:"schema"`
	Consents           map[string]HumanMatchConsent                `json:"consents"`
	ConsentRevocations map[string]HumanMatchConsentRevocation      `json:"consent_revocations"`
	Grants             map[string]HumanReachabilityGrantDefinition `json:"grants"`
	GrantRevocations   map[string]HumanReachabilityRevocation      `json:"grant_revocations"`
}

// ExportState encodes retained consent, grant and revocation history. The
// caller must provide durable storage and serialize Participant changes and
// relay commits with this directory. It does not export direct contact data.
func (d *MemoryReachabilityDirectory) ExportState() ([]byte, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, count := range []int{len(d.consents), len(d.grants), len(d.consentRevocationEvents), len(d.grantRevocationEvents)} {
		if count > 10_000 {
			return nil, ErrStoreLimit
		}
	}
	grants := make(map[string]HumanReachabilityGrantDefinition, len(d.grants))
	for id, entry := range d.grants {
		g := entry.grant
		grants[id] = HumanReachabilityGrantDefinition{
			GrantID: g.GrantID, ConsentID: entry.consentID, ApprovedByParticipantID: entry.humanID,
			CandidateID: g.CandidateID, RequesterParticipantID: g.RequesterParticipantID,
			Purpose: g.Purpose, Capability: g.Capability, Channel: g.Channel,
			RelaySessionRef: g.RelaySessionRef, IssuedAt: g.IssuedAt, ExpiresAt: g.ExpiresAt,
			ApprovalActorID: entry.approvalActorID, ApprovalAuthorizationID: entry.approvalAuthorizationID,
			ApprovalProofID: entry.approvalProofID,
		}
	}
	data, err := json.Marshal(durableReachabilityState{
		Schema: "asb.reachability-state/v1", Consents: d.consents,
		ConsentRevocations: d.consentRevocationEvents, Grants: grants,
		GrantRevocations: d.grantRevocationEvents,
	})
	if len(data) > maxReachabilityStateBytes {
		return nil, ErrStoreLimit
	}
	return data, err
}

// RestoreMemoryReachabilityDirectory validates a trusted local snapshot against
// the Participant registry from the same durable transaction. Historical grants
// are checked at their original issue time, without treating them as fresh
// authorizations. Protect the snapshot from rollback as well as modification.
func RestoreMemoryReachabilityDirectory(ctx context.Context, data []byte, participants ParticipantResolver, now func() time.Time) (*MemoryReachabilityDirectory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d, err := NewMemoryReachabilityDirectoryWithClock(participants, now)
	if err != nil || len(data) == 0 {
		return d, err
	}
	if err := strictjson.ValidateDocument(data, maxReachabilityStateBytes); err != nil {
		return nil, err
	}
	var state durableReachabilityState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if state.Schema != "asb.reachability-state/v1" || state.Consents == nil || state.Grants == nil ||
		state.ConsentRevocations == nil || state.GrantRevocations == nil {
		return nil, fmt.Errorf("task coordination: incomplete reachability snapshot")
	}
	for _, count := range []int{len(state.Consents), len(state.Grants), len(state.ConsentRevocations), len(state.GrantRevocations)} {
		if count > 10_000 {
			return nil, ErrStoreLimit
		}
	}
	for id, consent := range state.Consents {
		if id != consent.ConsentID || consent.Validate() != nil {
			return nil, fmt.Errorf("task coordination: invalid stored consent")
		}
		human, requester, err := d.resolvePair(ctx, consent.HumanParticipantID, consent.RequesterParticipantID)
		if err != nil || human.Kind != ParticipantHuman || requester.Kind != ParticipantAgent {
			return nil, fmt.Errorf("task coordination: invalid stored consent Participants")
		}
		binding := candidateBinding{humanID: consent.HumanParticipantID, requesterID: consent.RequesterParticipantID}
		if existing, ok := d.candidateBindings[consent.CandidateID]; ok && existing != binding {
			return nil, fmt.Errorf("task coordination: conflicting stored candidate binding")
		}
		d.consents[id] = consent
		d.candidateBindings[consent.CandidateID] = binding
	}
	for id, grant := range state.Grants {
		if id != grant.GrantID {
			return nil, fmt.Errorf("task coordination: invalid stored grant identifier")
		}
		// Suspension denies present use without making history unreadable.
		// Only structural replay uses this historical active projection.
		d.participants = historicalReachabilityParticipants{participants}
		d.now = func() time.Time { return grant.IssuedAt }
		if _, err := d.IssueHumanReachabilityGrant(ctx, grant); err != nil {
			return nil, fmt.Errorf("task coordination: invalid stored grant: %w", err)
		}
	}
	d.participants = participants
	d.now = now
	for id, revocation := range state.ConsentRevocations {
		if id != revocation.EventID {
			return nil, fmt.Errorf("task coordination: invalid stored consent revocation identifier")
		}
		if err := d.RevokeHumanMatchConsent(ctx, revocation); err != nil {
			return nil, fmt.Errorf("task coordination: invalid stored consent revocation: %w", err)
		}
	}
	for id, revocation := range state.GrantRevocations {
		if id != revocation.EventID {
			return nil, fmt.Errorf("task coordination: invalid stored grant revocation identifier")
		}
		if err := d.RevokeHumanReachabilityGrant(ctx, revocation); err != nil {
			return nil, fmt.Errorf("task coordination: invalid stored grant revocation: %w", err)
		}
	}
	return d, nil
}

type historicalReachabilityParticipants struct{ current ParticipantResolver }

func (h historicalReachabilityParticipants) LoadParticipant(ctx context.Context, id string) (Participant, error) {
	p, err := h.current.LoadParticipant(ctx, id)
	if err != nil {
		return Participant{}, err
	}
	if err := p.Validate(); err != nil || p.ParticipantID != id {
		return Participant{}, fmt.Errorf("task coordination: invalid historical Participant")
	}
	p.Status = ParticipantActive
	return p, nil
}
