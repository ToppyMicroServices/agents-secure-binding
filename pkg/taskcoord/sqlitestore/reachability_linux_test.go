// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func reachabilityGrantFixture(t *testing.T, s *Store) (taskcoord.HumanReachabilityGrant, taskcoord.AuthenticatedReachabilityAccess) {
	t.Helper()
	for _, p := range []taskcoord.Participant{
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:relay", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:human", Status: taskcoord.ParticipantActive, RegisteredAt: base},
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:relay", Kind: taskcoord.ParticipantAgent, IdentityRef: "urn:identity:agent", Status: taskcoord.ParticipantActive, RegisteredAt: base},
	} {
		if err := s.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	consent := taskcoord.HumanMatchConsent{
		Schema: taskcoord.HumanMatchConsentSchemaV1, ConsentID: "consent:relay", HumanParticipantID: "human:relay",
		CandidateID: "candidate:relay", RequesterParticipantID: "agent:relay", Purpose: "consultation", Capability: "translation", Channel: taskcoord.ReachabilityEmail,
		ContactRequestRef: "https://relay.example/requests/opaque", ActorID: "gateway:human", AuthorizationID: "authorization:consent", ProofID: "proof:consent", GrantedAt: base, ExpiresAt: base.Add(time.Hour),
	}
	if err := s.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := s.IssueHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityGrantDefinition{
		GrantID: "grant:relay", ConsentID: consent.ConsentID, ApprovedByParticipantID: consent.HumanParticipantID,
		CandidateID: consent.CandidateID, RequesterParticipantID: consent.RequesterParticipantID, Purpose: consent.Purpose, Capability: consent.Capability, Channel: consent.Channel,
		RelaySessionRef: "https://relay.example/sessions/opaque", IssuedAt: base, ExpiresAt: base.Add(time.Hour),
		ApprovalActorID: "gateway:human", ApprovalAuthorizationID: "authorization:grant", ApprovalProofID: "proof:grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	access := taskcoord.AuthenticatedReachabilityAccess{GrantID: grant.GrantID, RequesterParticipantID: grant.RequesterParticipantID,
		Purpose: grant.Purpose, Capability: grant.Capability, Channel: grant.Channel,
		ActorID: "gateway:agent", AuthorizationID: "authorization:use", ProofID: "proof:use", VerifierNonce: "nonce:use", IssuedAt: base, ExpiresAt: base.Add(time.Hour)}
	return grant, access
}

func revokeGrant(s *Store) error {
	return s.RevokeHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityRevocation{
		Schema: taskcoord.HumanReachabilityRevocationSchemaV1, EventID: "event:withdraw", GrantID: "grant:relay", ParticipantID: "human:relay",
		ActorID: "gateway:human", AuthorizationID: "authorization:withdraw", ProofID: "proof:withdraw", At: base.Add(time.Minute),
	})
}

func dispatchAccess(g taskcoord.HumanReachabilityGrant) taskcoord.HumanReachabilityDispatchAccess {
	return taskcoord.HumanReachabilityDispatchAccess{GrantID: g.GrantID, RequesterParticipantID: g.RequesterParticipantID, Purpose: g.Purpose, Capability: g.Capability, Channel: g.Channel}
}

func TestDurableReachabilityRevocationAndSchemaMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(time.Minute))
	_, offer := offerFixture(t)
	human, _ := offerFixture(t)
	if err := s.RegisterParticipant(ctx, human); err != nil {
		t.Fatal(err)
	}
	if err := s.CommitAssignment(ctx, 0, offer.Assignment, offer.Record); err != nil {
		t.Fatal(err)
	}
	// Recreate the exact earlier schema shape, retaining all TaskCoord data.
	for _, query := range []string{"DROP TABLE reachability", "DROP TABLE outbox_quarantine", "PRAGMA user_version=1"} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(time.Minute))
	if _, err := s.LoadAssignment(ctx, offer.Assignment.AssignmentID); err != nil {
		t.Fatal("migration lost assignment", err)
	}
	grant, access := reachabilityGrantFixture(t, s)
	_ = s.Close()
	s = openTest(t, path, base.Add(2*time.Minute))
	if got, err := s.LoadActiveHumanReachabilityGrant(ctx, access); err != nil || got.GrantID != grant.GrantID {
		t.Fatal("grant missing after restart", err)
	}
	if err := revokeGrant(s); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, path, base.Add(time.Minute))
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	calls := 0
	callback := func(taskcoord.HumanReachabilityGrant) error { calls++; return nil }
	if err := s.CommitWithActiveHumanReachabilityGrant(bounded, access, callback); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatal("revoked grant queued", err)
	}
	if err := s.CommitWithActiveHumanReachabilityGrantForDispatch(bounded, dispatchAccess(grant), callback); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatal("revoked grant dispatched", err)
	}
	if calls != 0 {
		t.Fatal("revoked callback executed")
	}
	if err := revokeGrant(s); err != nil {
		t.Fatal("revocation retry history lost", err)
	}
}

func TestRelayGrantGuardReleasesDatabaseBeforeCallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(time.Minute))
	grant, _ := reachabilityGrantFixture(t, s)
	other := openTest(t, path, base.Add(time.Minute))
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := s.CommitWithActiveHumanReachabilityGrantForDispatch(bounded, dispatchAccess(grant), func(taskcoord.HumanReachabilityGrant) error {
		// There is no SQLite write transaction held during external I/O.
		if _, err := other.db.ExecContext(bounded, "BEGIN IMMEDIATE"); err != nil {
			return err
		}
		if _, err := other.db.ExecContext(bounded, "ROLLBACK"); err != nil {
			return err
		}
		short, stop := context.WithTimeout(ctx, 30*time.Millisecond)
		defer stop()
		err := other.RegisterParticipant(short, taskcoord.Participant{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:blocked", Kind: taskcoord.ParticipantAgent, IdentityRef: "urn:identity:blocked", Status: taskcoord.ParticipantActive, RegisteredAt: base})
		if !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("mutation bypassed grant guard: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := revokeGrant(other); err != nil {
		t.Fatal("guard not released", err)
	}
	if err := s.CommitWithActiveHumanReachabilityGrantForDispatch(ctx, dispatchAccess(grant), func(taskcoord.HumanReachabilityGrant) error { t.Fatal("unbounded callback ran"); return nil }); err == nil {
		t.Fatal("unbounded callback accepted")
	}
}

func TestRelayGrantGuardProcessCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	s := openTest(t, path, base.Add(time.Minute))
	_, access := reachabilityGrantFixture(t, s)
	runctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(runctx, os.Args[0], "-test.run=^TestRelayGrantGuardChild$")
	command.Env = append(os.Environ(), "ASB_GRANT_GUARD_CHILD="+path)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "grant-guard-held" {
		t.Fatal("child did not enter grant guard")
	}
	short, stop := context.WithTimeout(ctx, 40*time.Millisecond)
	defer stop()
	if err := s.CommitWithActiveHumanReachabilityGrant(short, access, func(taskcoord.HumanReachabilityGrant) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cross-process guard bypassed", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("child should have been killed")
	}
	if err := revokeGrant(s); err != nil {
		t.Fatal("process death retained lock", err)
	}
	if _, err := s.LoadActiveHumanReachabilityGrant(ctx, access); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatal("revocation not durable", err)
	}
}

func TestRelayGrantGuardChild(t *testing.T) {
	path := os.Getenv("ASB_GRANT_GUARD_CHILD")
	if path == "" {
		return
	}
	s := openTest(t, path, base.Add(time.Minute))
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	access := taskcoord.HumanReachabilityDispatchAccess{GrantID: "grant:relay", RequesterParticipantID: "agent:relay", Purpose: "consultation", Capability: "translation", Channel: taskcoord.ReachabilityEmail}
	if err := s.CommitWithActiveHumanReachabilityGrantForDispatch(bounded, access, func(taskcoord.HumanReachabilityGrant) error {
		fmt.Println("grant-guard-held")
		<-bounded.Done()
		return bounded.Err()
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReachabilityRejectsHardLinkAliases(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "coord.db")
	s := openTest(t, path, base)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.db")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(alias); err == nil {
		_ = opened.Close()
		t.Fatal("hardlinked database bypassed canonical guard")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path+".reachability.lock", filepath.Join(root, "guard-alias")); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path); err == nil {
		_ = opened.Close()
		t.Fatal("hardlinked guard accepted")
	}
}
