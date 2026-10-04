// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestReachabilitySnapshotRetainsRevocationAndHistoricalGrants(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	registry, directory, human, agent := reachabilityFixture(t, base)
	consent := humanConsent(human.ParticipantID, agent.ParticipantID, base)
	ctx := context.Background()
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	definition := HumanReachabilityGrantDefinition{
		GrantID: "grant:durable", ConsentID: consent.ConsentID, ApprovedByParticipantID: human.ParticipantID,
		CandidateID: consent.CandidateID, RequesterParticipantID: agent.ParticipantID,
		Purpose: consent.Purpose, Capability: consent.Capability, Channel: consent.Channel,
		RelaySessionRef: "https://relay.example/sessions/durable", IssuedAt: base.Add(2 * time.Minute), ExpiresAt: base.Add(40 * time.Minute),
		ApprovalActorID: "actor:human", ApprovalAuthorizationID: "authorization:human", ApprovalProofID: "proof:human",
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, definition)
	if err != nil {
		t.Fatal(err)
	}
	activeRaw, err := directory.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	revocation := HumanReachabilityRevocation{Schema: HumanReachabilityRevocationSchemaV1, EventID: "event:revoke", GrantID: grant.GrantID,
		ParticipantID: human.ParticipantID, ActorID: "actor:human", AuthorizationID: "authorization:revoke", ProofID: "proof:revoke", At: base.Add(6 * time.Minute)}
	if err := directory.RevokeHumanReachabilityGrant(ctx, revocation); err != nil {
		t.Fatal(err)
	}
	raw, err := directory.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	// Expired historical grants must remain restorable; wall-clock rollback
	// must not resurrect a grant whose revocation has committed.
	for _, now := range []time.Time{base.Add(24 * time.Hour), base.Add(5 * time.Minute)} {
		restored, err := RestoreMemoryReachabilityDirectory(raw, registry, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if err := restored.RevokeHumanReachabilityGrant(ctx, revocation); err != nil {
			t.Fatal("lost immutable retry history", err)
		}
		if _, err := restored.LoadActiveHumanReachabilityGrant(ctx, authenticatedGrantAccess(grant, base)); err == nil {
			t.Fatal("restored revoked grant became active")
		}
	}
	human.Status = ParticipantSuspended
	current := &mutableParticipantResolver{participants: map[string]Participant{human.ParticipantID: human, agent.ParticipantID: agent}}
	if restored, err := RestoreMemoryReachabilityDirectory(activeRaw, current, func() time.Time { return base.Add(5 * time.Minute) }); err != nil {
		t.Fatal("current suspension made historical state unreadable", err)
	} else if _, err := restored.LoadActiveHumanReachabilityGrant(ctx, authenticatedGrantAccess(grant, base)); !errors.Is(err, ErrNotFound) {
		t.Fatal("historical active projection escaped into current authorization", err)
	}
	for _, corrupt := range []func(map[string]any){
		func(v map[string]any) { v["unknown"] = true },
		func(v map[string]any) { v["consents"] = nil },
		func(v map[string]any) { delete(v["consents"].(map[string]any), consent.ConsentID) },
		func(v map[string]any) {
			v["grants"].(map[string]any)[grant.GrantID].(map[string]any)["RequesterParticipantID"] = "agent:other"
		},
	} {
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		corrupt(doc)
		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreMemoryReachabilityDirectory(encoded, registry, time.Now); err == nil {
			t.Fatal("corrupt reachability snapshot accepted")
		}
	}
	if _, err := RestoreMemoryReachabilityDirectory([]byte(`{"schema":"x","schema":"asb.reachability-state/v1"}`), registry, time.Now); err == nil {
		t.Fatal("duplicate JSON keys accepted")
	}
	directory.grants = make(map[string]committedReachabilityGrant, 10_001)
	for i := range 10_001 {
		directory.grants[time.Unix(int64(i), 0).String()] = committedReachabilityGrant{}
	}
	if _, err := directory.ExportState(); !errors.Is(err, ErrStoreLimit) {
		t.Fatal("state capacity not enforced before persistence")
	}
}
