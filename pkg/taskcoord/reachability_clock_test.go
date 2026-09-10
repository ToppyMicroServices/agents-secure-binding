// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewMemoryReachabilityDirectoryWithClockRejectsNilClock(t *testing.T) {
	t.Parallel()

	directory, err := NewMemoryReachabilityDirectoryWithClock(NewMemoryStore(), nil)
	if !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("constructor error = %v, want ErrInvalidReachability", err)
	}
	if directory != nil {
		t.Fatalf("constructor directory = %#v, want nil", directory)
	}
}

func TestParticipantDirectoriesRejectTypedNilResolver(t *testing.T) {
	t.Parallel()

	var participants *MemoryStore
	directory, err := NewMemoryReachabilityDirectoryWithClock(participants, time.Now)
	if !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("constructor error = %v, want ErrInvalidReachability", err)
	}
	if directory != nil {
		t.Fatalf("constructor directory = %#v, want nil", directory)
	}

	directory = NewMemoryReachabilityDirectory(participants)
	if _, err := directory.resolveParticipant(context.Background(), "human:typed-nil"); !errors.Is(err, ErrInvalidReachability) {
		t.Fatalf("reachability resolver error = %v, want ErrInvalidReachability", err)
	}
	agentDirectory := NewMemoryAgentDirectory(participants)
	if _, err := agentDirectory.resolveParticipant(context.Background(), "agent:typed-nil"); !errors.Is(err, ErrInvalidDiscovery) {
		t.Fatalf("discovery resolver error = %v, want ErrInvalidDiscovery", err)
	}
}

func TestNewMemoryReachabilityDirectoryWithClockUsesExclusiveExpiryBoundary(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	human := participant("human:clock-boundary", ParticipantHuman, false, base)
	agent := participant("agent:clock-boundary", ParticipantAgent, false, base)
	participants := NewMemoryStore()
	for _, value := range []Participant{human, agent} {
		if err := participants.RegisterParticipant(ctx, value); err != nil {
			t.Fatal(err)
		}
	}

	current := base.Add(5 * time.Minute)
	directory, err := NewMemoryReachabilityDirectoryWithClock(
		participants,
		func() time.Time { return current },
	)
	if err != nil {
		t.Fatal(err)
	}
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	consent.ConsentID = "human-consent:clock-boundary"
	consent.CandidateID = "candidate:pairwise:clock-boundary"
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, HumanReachabilityGrantDefinition{
		GrantID:                 "reachability-grant:clock-boundary",
		ConsentID:               consent.ConsentID,
		ApprovedByParticipantID: human.ParticipantID,
		CandidateID:             consent.CandidateID,
		RequesterParticipantID:  agent.ParticipantID,
		Purpose:                 consent.Purpose,
		Capability:              consent.Capability,
		Channel:                 consent.Channel,
		RelaySessionRef:         "https://relay.example/sessions/clock-boundary",
		IssuedAt:                base.Add(2 * time.Minute),
		ExpiresAt:               base.Add(20 * time.Minute),
		ApprovalActorID:         "service:human-gateway",
		ApprovalAuthorizationID: "authorization:grant:clock-boundary",
		ApprovalProofID:         "proof:grant:clock-boundary",
	})
	if err != nil {
		t.Fatal(err)
	}
	access := AuthenticatedReachabilityAccess{
		GrantID:                grant.GrantID,
		RequesterParticipantID: grant.RequesterParticipantID,
		Purpose:                grant.Purpose,
		Capability:             grant.Capability,
		Channel:                grant.Channel,
		ActorID:                "service:agent-gateway",
		AuthorizationID:        "authorization:grant-access:clock-boundary",
		ProofID:                "proof:grant-access:clock-boundary",
		VerifierNonce:          "nonce:grant-access:clock-boundary",
		IssuedAt:               base.Add(4 * time.Minute),
		ExpiresAt:              base.Add(time.Hour),
	}

	current = grant.ExpiresAt.Add(-time.Nanosecond)
	if _, err := directory.LoadActiveHumanReachabilityGrant(ctx, access); err != nil {
		t.Fatalf("grant immediately before expiry error = %v", err)
	}

	current = grant.ExpiresAt
	if _, err := directory.LoadActiveHumanReachabilityGrant(ctx, access); !errors.Is(err, ErrNotFound) {
		t.Fatalf("grant at expiry error = %v, want ErrNotFound", err)
	}
}
