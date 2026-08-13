// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAgentDiscoveryRejectsHuman(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	def := AgentDiscoveryDefinition{
		RecordID:      "agent-record:1",
		Capability:    "translation",
		InvocationRef: "https://agents.example/invoke/translator-1",
		PublishedAt:   base,
		ExpiresAt:     base.Add(time.Hour),
	}
	if _, err := NewAgentDiscoveryRecord(participant("human:1", ParticipantHuman, false, base), def); !errors.Is(err, ErrHumanNotDiscoverable) {
		t.Fatalf("Human discovery error = %v, want ErrHumanNotDiscoverable", err)
	}
	if _, err := NewAgentDiscoveryRecord(participant("service:1", ParticipantAutomatedService, false, base), def); !errors.Is(err, ErrInvalidDiscovery) {
		t.Fatalf("service discovery error = %v, want ErrInvalidDiscovery", err)
	}
	agent := participant("agent:1", ParticipantAgent, false, base)
	record, err := NewAgentDiscoveryRecord(agent, def)
	if err != nil {
		t.Fatal(err)
	}
	if record.Kind != ParticipantAgent || record.ParticipantID != agent.ParticipantID {
		t.Fatalf("record = %+v", record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAgentDiscoveryRecord(bytes.NewReader(raw)); err != nil {
		t.Fatalf("DecodeAgentDiscoveryRecord() error = %v", err)
	}
}

func TestAgentDirectoryRechecksParticipantBinding(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	human := participant("human:1", ParticipantHuman, false, base)
	agent := participant("agent:1", ParticipantAgent, false, base)
	store := NewMemoryStore()
	for _, p := range []Participant{human, agent} {
		if err := store.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	directory := newMemoryAgentDirectory(store, func() time.Time { return base.Add(time.Minute) })
	record, err := NewAgentDiscoveryRecord(agent, AgentDiscoveryDefinition{
		RecordID:      "agent-record:1",
		Capability:    "translation",
		InvocationRef: "https://agents.example/invoke/translator-1",
		PublishedAt:   base,
		ExpiresAt:     base.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	forged := record
	forged.RecordID = "agent-record:forged-human"
	forged.ParticipantID = human.ParticipantID
	forged.Kind = ParticipantAgent
	if err := directory.RegisterAgentDiscoveryRecord(ctx, forged); !errors.Is(err, ErrHumanNotDiscoverable) {
		t.Fatalf("forged Human binding error = %v, want ErrHumanNotDiscoverable", err)
	}
	if err := directory.RegisterAgentDiscoveryRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	results, err := directory.SearchAgents(ctx, AgentSearchQuery{Capability: "translation", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].ParticipantID != agent.ParticipantID {
		t.Fatalf("Agent search results = %+v", results)
	}
}

func TestHumanMatchingReturnsOnlyOpaqueRelayCandidate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	store, directory, human, agent := reachabilityFixture(t, base)
	_ = store
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	rawConsent, err := json.Marshal(consent)
	if err != nil {
		t.Fatal(err)
	}
	decodedConsent, err := DecodeHumanMatchConsent(bytes.NewReader(rawConsent))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.RegisterHumanMatchConsent(ctx, decodedConsent); err != nil {
		t.Fatalf("idempotent consent registration error = %v", err)
	}

	query := HumanMatchQuery{
		RequesterParticipantID: agent.ParticipantID,
		Purpose:                consent.Purpose,
		Capability:             consent.Capability,
		Channel:                consent.Channel,
		Limit:                  5,
	}
	results, err := directory.MatchHumans(ctx, authenticatedHumanMatch(query, base))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].CandidateID != consent.CandidateID {
		t.Fatalf("results = %+v", results)
	}
	raw, err := json.Marshal(results[0])
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(raw)
	for _, forbidden := range []string{human.ParticipantID, "human_participant_id", "actor_id", "authorization_id", "proof_id", "mailto:", "tel:"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("match result leaked %q: %s", forbidden, serialized)
		}
	}

	query.Purpose = "different-purpose"
	results, err = directory.MatchHumans(ctx, authenticatedHumanMatch(query, base))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("purpose-mismatched results = %+v", results)
	}
}

func TestHumanMatchingConsentRevocationIsImmediate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	_, directory, human, agent := reachabilityFixture(t, base)
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	revocation := HumanMatchConsentRevocation{
		Schema:             HumanMatchConsentRevocationSchemaV1,
		EventID:            "revoke-consent:1",
		ConsentID:          consent.ConsentID,
		HumanParticipantID: human.ParticipantID,
		ActorID:            "service:human-gateway",
		AuthorizationID:    "authorization:revoke-consent:1",
		ProofID:            "proof:revoke-consent:1",
		At:                 base.Add(3 * time.Minute),
	}
	if err := directory.RevokeHumanMatchConsent(ctx, revocation); err != nil {
		t.Fatal(err)
	}
	if err := directory.RevokeHumanMatchConsent(ctx, revocation); err != nil {
		t.Fatalf("idempotent consent revocation error = %v", err)
	}
	results, err := directory.MatchHumans(ctx, authenticatedHumanMatch(HumanMatchQuery{
		RequesterParticipantID: agent.ParticipantID,
		Purpose:                consent.Purpose,
		Capability:             consent.Capability,
		Channel:                consent.Channel,
		Limit:                  1,
	}, base))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("revoked consent remained discoverable: %+v", results)
	}
}

func TestHumanReachabilityRechecksHumanStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	human := participant("human:private", ParticipantHuman, false, base)
	agent := participant("agent:requester", ParticipantAgent, false, base)
	resolver := &mutableParticipantResolver{participants: map[string]Participant{
		human.ParticipantID: human,
		agent.ParticipantID: agent,
	}}
	directory := newMemoryReachabilityDirectory(resolver, func() time.Time { return base.Add(5 * time.Minute) })
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, HumanReachabilityGrantDefinition{
		GrantID:                 "reachability-grant:status-recheck",
		ConsentID:               consent.ConsentID,
		ApprovedByParticipantID: human.ParticipantID,
		CandidateID:             consent.CandidateID,
		RequesterParticipantID:  agent.ParticipantID,
		Purpose:                 consent.Purpose,
		Capability:              consent.Capability,
		Channel:                 consent.Channel,
		RelaySessionRef:         "https://relay.example/sessions/status-recheck",
		IssuedAt:                base.Add(2 * time.Minute),
		ExpiresAt:               base.Add(20 * time.Minute),
		ApprovalActorID:         "service:human-gateway",
		ApprovalAuthorizationID: "authorization:grant:status-recheck",
		ApprovalProofID:         "proof:grant:status-recheck",
	})
	if err != nil {
		t.Fatal(err)
	}

	human.Status = ParticipantSuspended
	resolver.participants[human.ParticipantID] = human
	results, err := directory.MatchHumans(ctx, authenticatedHumanMatch(HumanMatchQuery{
		RequesterParticipantID: agent.ParticipantID,
		Purpose:                consent.Purpose,
		Capability:             consent.Capability,
		Channel:                consent.Channel,
		Limit:                  1,
	}, base))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("suspended Human remained matchable: %+v", results)
	}
	if _, err := directory.LoadActiveHumanReachabilityGrant(ctx, authenticatedGrantAccess(grant, base)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("suspended Human grant error = %v, want ErrNotFound", err)
	}
}

func TestHumanReachabilityGrantContainsOnlyRelayAndCanBeRevoked(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	_, directory, human, agent := reachabilityFixture(t, base)
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	def := HumanReachabilityGrantDefinition{
		GrantID:                 "reachability-grant:1",
		ConsentID:               consent.ConsentID,
		ApprovedByParticipantID: human.ParticipantID,
		CandidateID:             consent.CandidateID,
		RequesterParticipantID:  agent.ParticipantID,
		Purpose:                 consent.Purpose,
		Capability:              consent.Capability,
		Channel:                 consent.Channel,
		RelaySessionRef:         "https://relay.example/sessions/opaque-session-1",
		IssuedAt:                base.Add(2 * time.Minute),
		ExpiresAt:               base.Add(20 * time.Minute),
		ApprovalActorID:         "service:human-gateway",
		ApprovalAuthorizationID: "authorization:grant:1",
		ApprovalProofID:         "proof:grant:1",
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, def)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := directory.IssueHumanReachabilityGrant(ctx, def); err != nil || !sameReachabilityGrant(retry, grant) {
		t.Fatalf("idempotent grant = %+v, error = %v", retry, err)
	}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(raw)
	for _, forbidden := range []string{
		human.ParticipantID,
		"human_participant_id",
		consent.ConsentID,
		"consent_id",
		def.ApprovalActorID,
		"approval_actor_id",
		"approval_authorization_id",
		"approval_proof_id",
		"mailto:",
		"tel:",
	} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("grant leaked %q: %s", forbidden, serialized)
		}
	}
	decoded, err := DecodeHumanReachabilityGrant(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !sameReachabilityGrant(decoded, grant) {
		t.Fatalf("decoded grant = %+v, want %+v", decoded, grant)
	}
	access := authenticatedGrantAccess(grant, base)
	loaded, err := directory.LoadActiveHumanReachabilityGrant(ctx, access)
	if err != nil || !sameReachabilityGrant(loaded, grant) {
		t.Fatalf("active grant = %+v, error = %v", loaded, err)
	}
	access.Purpose = "different-purpose"
	if _, err := directory.LoadActiveHumanReachabilityGrant(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mismatched grant error = %v, want ErrNotFound", err)
	}

	revocation := HumanReachabilityRevocation{
		Schema:          HumanReachabilityRevocationSchemaV1,
		EventID:         "revoke-grant:1",
		GrantID:         grant.GrantID,
		ParticipantID:   human.ParticipantID,
		ActorID:         "service:human-gateway",
		AuthorizationID: "authorization:revoke-grant:1",
		ProofID:         "proof:revoke-grant:1",
		At:              base.Add(4 * time.Minute),
	}
	if err := directory.RevokeHumanReachabilityGrant(ctx, revocation); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.LoadActiveHumanReachabilityGrant(ctx, authenticatedGrantAccess(grant, base)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked grant error = %v, want ErrNotFound", err)
	}
}

func TestHumanContactReferencesRejectDirectEndpoints(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	human := participant("human:1", ParticipantHuman, false, base)
	human.IdentityRef = "mailto:person@example.com"
	if err := human.Validate(); !errors.Is(err, ErrInvalidParticipant) {
		t.Fatalf("Human identity error = %v, want ErrInvalidParticipant", err)
	}
	human.IdentityRef = "https://social.example/person"
	if err := human.Validate(); !errors.Is(err, ErrInvalidParticipant) {
		t.Fatalf("public Human identity error = %v, want ErrInvalidParticipant", err)
	}
	consent := humanConsent("human:1", "agent:1", base)
	consent.ContactRequestRef = "tel:+3585550100"
	if err := consent.Validate(); !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("contact request error = %v, want ErrInvalidReachability", err)
	}
	query := HumanMatchQuery{
		RequesterParticipantID: "agent:1",
		Purpose:                "*",
		Capability:             "translation",
		Channel:                ReachabilityEmail,
		Limit:                  1,
	}
	if err := query.Validate(); !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("wildcard query error = %v, want ErrInvalidReachability", err)
	}
	authenticated := authenticatedHumanMatch(HumanMatchQuery{
		RequesterParticipantID: "agent:1",
		Purpose:                "task-consultation",
		Capability:             "translation",
		Channel:                ReachabilityEmail,
		Limit:                  1,
	}, base)
	authenticated.AuthorizationID = ""
	if err := authenticated.Validate(); !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("unauthenticated query error = %v, want ErrInvalidReachability", err)
	}
}

func reachabilityFixture(t *testing.T, base time.Time) (*MemoryStore, *MemoryReachabilityDirectory, Participant, Participant) {
	t.Helper()
	ctx := context.Background()
	human := participant("human:private", ParticipantHuman, false, base)
	agent := participant("agent:requester", ParticipantAgent, false, base)
	store := NewMemoryStore()
	for _, p := range []Participant{human, agent} {
		if err := store.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	now := base.Add(5 * time.Minute)
	directory := newMemoryReachabilityDirectory(store, func() time.Time { return now })
	return store, directory, human, agent
}

func humanConsent(humanID, requesterID string, base time.Time) HumanMatchConsent {
	return HumanMatchConsent{
		Schema:                 HumanMatchConsentSchemaV1,
		ConsentID:              "human-consent:1",
		HumanParticipantID:     humanID,
		CandidateID:            "candidate:pairwise:7f3e",
		RequesterParticipantID: requesterID,
		Purpose:                "task-consultation",
		Capability:             "translation",
		Channel:                ReachabilityEmail,
		ContactRequestRef:      "https://relay.example/contact-requests/opaque-request-1",
		ActorID:                "service:human-gateway",
		AuthorizationID:        "authorization:human-consent:1",
		ProofID:                "proof:human-consent:1",
		GrantedAt:              base.Add(time.Minute),
		ExpiresAt:              base.Add(time.Hour),
	}
}

func authenticatedHumanMatch(query HumanMatchQuery, base time.Time) AuthenticatedHumanMatchQuery {
	return AuthenticatedHumanMatchQuery{
		Query:           query,
		ActorID:         "service:agent-gateway",
		AuthorizationID: "authorization:human-match:1",
		ProofID:         "proof:human-match:1",
		VerifierNonce:   "nonce:human-match:1",
		IssuedAt:        base.Add(4 * time.Minute),
		ExpiresAt:       base.Add(10 * time.Minute),
	}
}

func authenticatedGrantAccess(grant HumanReachabilityGrant, base time.Time) AuthenticatedReachabilityAccess {
	return AuthenticatedReachabilityAccess{
		GrantID:                grant.GrantID,
		RequesterParticipantID: grant.RequesterParticipantID,
		Purpose:                grant.Purpose,
		Capability:             grant.Capability,
		Channel:                grant.Channel,
		ActorID:                "service:agent-gateway",
		AuthorizationID:        "authorization:grant-access:1",
		ProofID:                "proof:grant-access:1",
		VerifierNonce:          "nonce:grant-access:1",
		IssuedAt:               base.Add(4 * time.Minute),
		ExpiresAt:              base.Add(10 * time.Minute),
	}
}

type mutableParticipantResolver struct {
	participants map[string]Participant
}

func (r *mutableParticipantResolver) LoadParticipant(_ context.Context, participantID string) (Participant, error) {
	participant, ok := r.participants[participantID]
	if !ok {
		return Participant{}, ErrNotFound
	}
	return participant, nil
}
