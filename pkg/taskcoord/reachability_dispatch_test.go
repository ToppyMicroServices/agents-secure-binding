// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHumanReachabilityDispatchTransactionRejectsExpiredGrantBeforeCallback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	human := participant("human:dispatch-expiry", ParticipantHuman, false, base)
	agent := participant("agent:dispatch-expiry", ParticipantAgent, false, base)
	participants := NewMemoryStore()
	for _, value := range []Participant{human, agent} {
		if err := participants.RegisterParticipant(ctx, value); err != nil {
			t.Fatal(err)
		}
	}

	current := base.Add(5 * time.Minute)
	directory := newMemoryReachabilityDirectory(participants, func() time.Time { return current })
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	consent.ConsentID = "human-consent:dispatch-expiry"
	consent.CandidateID = "candidate:pairwise:dispatch-expiry"
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, HumanReachabilityGrantDefinition{
		GrantID:                 "reachability-grant:dispatch-expiry",
		ConsentID:               consent.ConsentID,
		ApprovedByParticipantID: human.ParticipantID,
		CandidateID:             consent.CandidateID,
		RequesterParticipantID:  agent.ParticipantID,
		Purpose:                 consent.Purpose,
		Capability:              consent.Capability,
		Channel:                 consent.Channel,
		RelaySessionRef:         "https://relay.example/sessions/dispatch-expiry",
		IssuedAt:                base.Add(2 * time.Minute),
		ExpiresAt:               base.Add(20 * time.Minute),
		ApprovalActorID:         "service:human-gateway",
		ApprovalAuthorizationID: "authorization:grant:dispatch-expiry",
		ApprovalProofID:         "proof:grant:dispatch-expiry",
	})
	if err != nil {
		t.Fatal(err)
	}
	access := HumanReachabilityDispatchAccess{
		GrantID:                grant.GrantID,
		RequesterParticipantID: grant.RequesterParticipantID,
		Purpose:                grant.Purpose,
		Capability:             grant.Capability,
		Channel:                grant.Channel,
	}

	callbackCalls := 0
	if err := directory.CommitWithActiveHumanReachabilityGrantForDispatch(
		ctx,
		access,
		func(got HumanReachabilityGrant) error {
			callbackCalls++
			if !sameReachabilityGrant(got, grant) {
				t.Fatalf("dispatch grant = %+v, want %+v", got, grant)
			}
			return nil
		},
	); err != nil {
		t.Fatalf("active dispatch transaction error = %v", err)
	}
	if callbackCalls != 1 {
		t.Fatalf("active dispatch callback calls = %d, want 1", callbackCalls)
	}

	// Expiry is exclusive. At the exact ExpiresAt boundary the transaction
	// must reject before the callback can begin an external effect.
	current = grant.ExpiresAt
	err = directory.CommitWithActiveHumanReachabilityGrantForDispatch(
		ctx,
		access,
		func(HumanReachabilityGrant) error {
			callbackCalls++
			return nil
		},
	)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired dispatch transaction error = %v, want ErrNotFound", err)
	}
	if callbackCalls != 1 {
		t.Fatalf("expired dispatch invoked callback; calls = %d, want 1", callbackCalls)
	}
}
