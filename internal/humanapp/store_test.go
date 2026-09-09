// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

var storeTestTime = time.Date(2026, time.September, 8, 0, 0, 0, 0, time.UTC)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return storeTestTime }
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// These storage tests supply already-verified identities. The transport tests
// exercise the cryptographic verifier; this callback exercises its required
// transaction-local replay commit.
func testStoreAuth(actor, key string) Authenticator {
	return func(replay identitypolicy.ReplayCache) (production.AcceptedIdentity, error) {
		if err := replay.MarkUsed(key, storeTestTime.Add(time.Hour)); err != nil {
			return production.AcceptedIdentity{}, err
		}
		return production.AcceptedIdentity{Issuer: "local-manager", Agent: actor}, nil
	}
}

func testProposal(id string, enabled bool, revision uint64) Command {
	return Command{
		CommandID: "propose-" + id, Kind: KindPropose, OperationID: id, ExpectedRevision: revision,
		Change: &protectedchange.ChangeRequest{ChangeID: id, Tenant: Tenant, Setting: SettingName, Enabled: enabled},
	}
}

func testDecision(id, kind string, operation Operation) Command {
	return Command{CommandID: id, Kind: kind, OperationID: operation.OperationID, ProposalDigest: operation.ProposalDigest, ExpectedRevision: operation.Before.Revision}
}

func testStatus(operation Operation) Command {
	return Command{CommandID: "status-" + operation.OperationID, Kind: KindStatus, OperationID: operation.OperationID, ProposalDigest: operation.ProposalDigest}
}

func executeStore(t *testing.T, store *Store, command Command, actor, key string) ([]byte, Response) {
	t.Helper()
	raw, err := store.Execute(context.Background(), command, testStoreAuth(actor, key))
	if err != nil {
		t.Fatalf("Execute(%s): %v", command.Kind, err)
	}
	var response Response
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return raw, response
}

func requireSetting(t *testing.T, response Response, enabled bool, revision uint64) {
	t.Helper()
	if response.Setting == nil || response.Setting.Enabled != enabled || response.Setting.Revision != revision {
		t.Fatalf("setting = %+v, want enabled=%v revision=%d", response.Setting, enabled, revision)
	}
}

func TestInboxKeepsOldPendingVisibleAndReportsFullQueue(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	_, oldest := executeStore(t, store, testProposal("oldest", true, 0), ActorAgent, "oldest")
	for i := 0; i <= maxInboxOperations; i++ {
		id := fmt.Sprintf("history-%03d", i)
		created := storeTestTime.Add(time.Duration(i+1) * time.Millisecond)
		store.now = func() time.Time { return created }
		_, proposed := executeStore(t, store, testProposal(id, true, 0), ActorAgent, id)
		executeStore(t, store, testDecision("deny-"+id, KindDecline, *proposed.Operation), ActorGateway, "deny-"+id)
	}
	inbox := func(key string) Response {
		_, response := executeStore(t, store, Command{CommandID: key, Kind: KindInbox}, ActorGateway, key)
		if response.Inbox == nil || response.Inbox.Limit != maxInboxOperations || len(response.Operations) != maxInboxOperations {
			t.Fatalf("missing bounded inbox metadata: %+v", response.Inbox)
		}
		return response
	}
	response := inbox("inbox-history")
	if response.Inbox.Pending != 1 || response.Inbox.Total != maxInboxOperations+2 || response.Operations[0].OperationID != "oldest" || response.Operations[1].OperationID != "history-100" {
		t.Fatalf("new history hid pending work or counts are wrong: %+v", response.Inbox)
	}
	for i := 0; i < maxInboxOperations; i++ {
		id := fmt.Sprintf("pending-%03d", i)
		created := storeTestTime.Add(time.Duration(i+1000) * time.Millisecond)
		store.now = func() time.Time { return created }
		executeStore(t, store, testProposal(id, true, 0), ActorAgent, id)
	}
	response = inbox("inbox-backlog")
	if response.Inbox.Pending != maxInboxOperations+1 || response.Operations[0].OperationID != "oldest" || response.Operations[maxInboxOperations-1].OperationID != "pending-098" {
		t.Fatal("pending queue must expose its oldest items and full count")
	}
	executeStore(t, store, testDecision("deny-oldest", KindDecline, *oldest.Operation), ActorGateway, "deny-oldest")
	response = inbox("inbox-drained")
	if response.Inbox.Pending != maxInboxOperations || response.Operations[0].OperationID != "pending-000" || response.Operations[maxInboxOperations-1].OperationID != "pending-099" {
		t.Fatal("reviewing the oldest proposal must expose the next pending item")
	}
}

func TestStoreRestoresPendingAndOriginalAppliedResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store := openTestStore(t, path)
	proposal := testProposal("change-1", true, 0)
	proposedBytes, proposed := executeStore(t, store, proposal, ActorAgent, "proposal-proof")
	if proposed.Operation == nil || proposed.Operation.State != StatePending {
		t.Fatalf("proposal = %+v", proposed)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	_, pending := executeStore(t, store, testStatus(*proposed.Operation), ActorGateway, "pending-proof")
	if pending.Operation.State != StatePending {
		t.Fatalf("reopened operation = %+v", pending.Operation)
	}
	decision := testDecision("approve-1", KindApprove, *pending.Operation)
	original, applied := executeStore(t, store, decision, ActorGateway, "approval-proof")
	if applied.Operation.State != StateApplied || applied.Operation.Reviewer != ActorGateway || applied.Operation.HumanParticipant != HumanParticipant || applied.Operation.Assurance != Assurance {
		t.Fatalf("applied operation = %+v", applied.Operation)
	}
	requireSetting(t, applied, true, 1)
	// Treat the committed response as lost. Close the process-owned connection,
	// then reconcile the same command using a fresh authenticated proof.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	recovered, _ := executeStore(t, store, decision, ActorGateway, "recovery-proof")
	if !bytes.Equal(recovered, original) {
		t.Fatalf("recovery changed the original response\n got %s\nwant %s", recovered, original)
	}
	oldProposal, _ := executeStore(t, store, proposal, ActorAgent, "proposal-retry-proof")
	if !bytes.Equal(oldProposal, proposedBytes) {
		t.Fatal("proposal retry replaced the first proposal response")
	}
	_, status := executeStore(t, store, testStatus(*proposed.Operation), ActorAgent, "status-proof")
	if status.Operation.State != StateApplied {
		t.Fatalf("status = %+v", status.Operation)
	}
	requireSetting(t, status, true, 1)
}

func TestStoreDeclinePersistsWithoutSettingEffect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store := openTestStore(t, path)
	_, proposed := executeStore(t, store, testProposal("denied", true, 0), ActorAgent, "propose")
	decision := testDecision("decline", KindDecline, *proposed.Operation)
	original, denied := executeStore(t, store, decision, ActorGateway, "decline")
	if denied.Operation.State != StateDenied || denied.Operation.After != nil {
		t.Fatalf("denied = %+v", denied.Operation)
	}
	requireSetting(t, denied, false, 0)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	recovered, denied := executeStore(t, store, decision, ActorGateway, "retry")
	if !bytes.Equal(original, recovered) {
		t.Fatal("decline response was not preserved")
	}
	requireSetting(t, denied, false, 0)
}

func TestStoreStaleReviewCannotApply(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	_, first := executeStore(t, store, testProposal("first", true, 0), ActorAgent, "first")
	_, second := executeStore(t, store, testProposal("second", false, 0), ActorAgent, "second")
	_, applied := executeStore(t, store, testDecision("approve-first", KindApprove, *first.Operation), ActorGateway, "apply-first")
	requireSetting(t, applied, true, 1)
	_, stale := executeStore(t, store, testDecision("approve-second", KindApprove, *second.Operation), ActorGateway, "apply-second")
	if stale.Operation.State != StateStale || stale.Operation.After != nil {
		t.Fatalf("stale operation = %+v", stale.Operation)
	}
	requireSetting(t, stale, true, 1)
	_, status := executeStore(t, store, testStatus(*second.Operation), ActorAgent, "status")
	if status.Operation.State != StateStale {
		t.Fatalf("status = %+v", status.Operation)
	}
}

func TestStoreWrongReviewBindingRollsBack(t *testing.T) {
	for _, change := range []string{"digest", "revision"} {
		t.Run(change, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
			_, proposed := executeStore(t, store, testProposal("proposal", true, 0), ActorAgent, "propose")
			correct := testDecision("approval", KindApprove, *proposed.Operation)
			wrong := correct
			if change == "digest" {
				wrong.ProposalDigest = "sha256:" + strings.Repeat("0", 64)
			} else {
				wrong.ExpectedRevision++
			}
			raw, err := store.Execute(context.Background(), wrong, testStoreAuth(ActorGateway, "decision-proof"))
			if !errors.Is(err, ErrConflict) || raw != nil {
				t.Fatalf("wrong review result = %s, %v", raw, err)
			}
			_, status := executeStore(t, store, testStatus(*proposed.Operation), ActorAgent, "status")
			if status.Operation.State != StatePending {
				t.Fatalf("operation changed after rejected review: %+v", status.Operation)
			}
			requireSetting(t, status, false, 0)
			// Failed application validation rolled the replay reservation back.
			_, applied := executeStore(t, store, correct, ActorGateway, "decision-proof")
			requireSetting(t, applied, true, 1)
		})
	}
}

func TestStoreMutationIdentifierConflictPreservesFirstResult(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	command := testProposal("original", true, 0)
	original, _ := executeStore(t, store, command, ActorAgent, "original-proof")
	changed := testProposal("original", false, 0)
	if _, err := store.Execute(context.Background(), changed, testStoreAuth(ActorAgent, "changed-proof")); !errors.Is(err, ErrConflict) {
		t.Fatalf("altered command error = %v", err)
	}
	changed = command
	changed.CommandID = "another-command"
	if _, err := store.Execute(context.Background(), changed, testStoreAuth(ActorAgent, "new-command-proof")); !errors.Is(err, ErrConflict) {
		t.Fatalf("reused operation error = %v", err)
	}
	recovered, _ := executeStore(t, store, command, ActorAgent, "fresh-proof")
	if !bytes.Equal(original, recovered) {
		t.Fatal("conflict replaced the original result")
	}
}

func TestStoreRequiresAuthorizedActorAndExactlyOneReplayCommit(t *testing.T) {
	for _, mode := range []string{"wrong-role", "unknown-actor", "no-replay", "double-replay", "failed-auth"} {
		t.Run(mode, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
			command := testProposal("proposal", true, 0)
			auth := func(replay identitypolicy.ReplayCache) (production.AcceptedIdentity, error) {
				actor := ActorAgent
				if mode == "wrong-role" {
					actor = ActorGateway
				} else if mode == "unknown-actor" {
					actor = "unknown"
				}
				if mode != "no-replay" {
					if err := replay.MarkUsed("proof", storeTestTime.Add(time.Hour)); err != nil {
						return production.AcceptedIdentity{}, err
					}
				}
				if mode == "double-replay" {
					_ = replay.MarkUsed("second-proof", storeTestTime.Add(time.Hour))
				}
				if mode == "failed-auth" {
					return production.AcceptedIdentity{}, ErrUnauthorized
				}
				return production.AcceptedIdentity{Agent: actor}, nil
			}
			raw, err := store.Execute(context.Background(), command, auth)
			if !errors.Is(err, ErrUnauthorized) || raw != nil {
				t.Fatalf("result = %s, %v", raw, err)
			}
			_, inbox := executeStore(t, store, Command{CommandID: "inbox", Kind: KindInbox}, ActorGateway, "inbox-proof")
			if len(inbox.Operations) != 0 {
				t.Fatal("unauthorized proposal persisted")
			}
			requireSetting(t, inbox, false, 0)
			// No command receipt or replay reservation survived the rejection.
			executeStore(t, store, command, ActorAgent, "proof")
		})
	}
}

func TestStoreAgentCannotMakeHumanDecision(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	_, proposed := executeStore(t, store, testProposal("proposal", true, 0), ActorAgent, "propose")
	for _, kind := range []string{KindApprove, KindDecline} {
		_, err := store.Execute(context.Background(), testDecision("decision-"+kind, kind, *proposed.Operation), testStoreAuth(ActorAgent, "proof-"+kind))
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%s error = %v", kind, err)
		}
	}
	_, status := executeStore(t, store, testStatus(*proposed.Operation), ActorAgent, "status")
	if status.Operation.State != StatePending {
		t.Fatalf("state = %s", status.Operation.State)
	}
	requireSetting(t, status, false, 0)
}

func TestStoreAuthenticatesBeforeOperationLookup(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	command := Command{CommandID: "status", Kind: KindStatus, OperationID: "missing", ProposalDigest: "sha256:" + strings.Repeat("0", 64)}
	authenticated := false
	_, err := store.Execute(context.Background(), command, func(identitypolicy.ReplayCache) (production.AcceptedIdentity, error) {
		authenticated = true
		return production.AcceptedIdentity{}, ErrUnauthorized
	})
	if !authenticated || !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("authenticated=%v, error=%v", authenticated, err)
	}
}

func TestStoreCommitFailureRollsBackProposalAndApproval(t *testing.T) {
	for _, phase := range []string{"proposal", "approval"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.sqlite")
			store := openTestStore(t, path)
			command := testProposal("proposal", true, 0)
			actor := ActorAgent
			var operation Operation
			if phase == "approval" {
				_, proposed := executeStore(t, store, command, ActorAgent, "initial-proposal")
				operation = *proposed.Operation
				command = testDecision("approval", KindApprove, operation)
				actor = ActorGateway
			}
			store.beforeCommit = func() error { return errors.New("injected commit failure") }
			raw, err := store.Execute(context.Background(), command, testStoreAuth(actor, "attempt-proof"))
			if !errors.Is(err, ErrUnavailable) || raw != nil {
				t.Fatalf("failure = %s, %v", raw, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store = openTestStore(t, path)
			_, inbox := executeStore(t, store, Command{CommandID: "inbox", Kind: KindInbox}, ActorGateway, "inbox")
			requireSetting(t, inbox, false, 0)
			if phase == "proposal" && len(inbox.Operations) != 0 {
				t.Fatal("uncommitted proposal survived restart")
			}
			if phase == "approval" && (len(inbox.Operations) != 1 || inbox.Operations[0].State != StatePending) {
				t.Fatalf("uncommitted approval survived restart: %+v", inbox.Operations)
			}
			_, recovered := executeStore(t, store, command, actor, "attempt-proof")
			if phase == "approval" {
				requireSetting(t, recovered, true, 1)
			}
		})
	}
}

func TestStoreConcurrentDecisionsHaveOneWinner(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	_, proposed := executeStore(t, store, testProposal("proposal", true, 0), ActorAgent, "proposal")
	var group sync.WaitGroup
	results := make(chan error, 2)
	for _, kind := range []string{KindApprove, KindDecline} {
		group.Go(func() {
			_, err := store.Execute(context.Background(), testDecision("decision-"+kind, kind, *proposed.Operation), testStoreAuth(ActorGateway, "proof-"+kind))
			results <- err
		})
	}
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	_, status := executeStore(t, store, testStatus(*proposed.Operation), ActorGateway, "status")
	switch status.Operation.State {
	case StateApplied:
		requireSetting(t, status, true, 1)
	case StateDenied:
		requireSetting(t, status, false, 0)
	default:
		t.Fatalf("unexpected terminal state %s", status.Operation.State)
	}
}

func TestStoreReplaySurvivesRestartAndReadCommandsStayLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sqlite")
	store := openTestStore(t, path)
	proposal := testProposal("proposal", true, 0)
	_, proposed := executeStore(t, store, proposal, ActorAgent, "proposal-proof")
	statusCommand := testStatus(*proposed.Operation)
	inboxCommand := Command{CommandID: "inbox", Kind: KindInbox}
	executeStore(t, store, statusCommand, ActorAgent, "before-status")
	executeStore(t, store, inboxCommand, ActorGateway, "before-inbox")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	if _, err := store.Execute(context.Background(), proposal, testStoreAuth(ActorAgent, "proposal-proof")); !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("repeated proof error = %v", err)
	}
	executeStore(t, store, testDecision("approve", KindApprove, *proposed.Operation), ActorGateway, "approve-proof")
	_, status := executeStore(t, store, statusCommand, ActorAgent, "after-status")
	_, inbox := executeStore(t, store, inboxCommand, ActorGateway, "after-inbox")
	if status.Operation.State != StateApplied || len(inbox.Operations) != 1 || inbox.Operations[0].State != StateApplied {
		t.Fatalf("read command returned an old view: status=%+v inbox=%+v", status, inbox)
	}
}

func TestStorePrunesExpiredReplayAndBoundsInbox(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	for index := 0; index < maxInboxOperations+3; index++ {
		id := fmt.Sprintf("proposal-%03d", index)
		executeStore(t, store, testProposal(id, true, 0), ActorAgent, id)
	}
	_, inbox := executeStore(t, store, Command{CommandID: "inbox", Kind: KindInbox}, ActorGateway, "inbox")
	if len(inbox.Operations) != maxInboxOperations {
		t.Fatalf("inbox size = %d", len(inbox.Operations))
	}
	later := storeTestTime.Add(2 * time.Hour)
	store.now = func() time.Time { return later }
	_, err := store.Execute(context.Background(), Command{CommandID: "later-inbox", Kind: KindInbox}, func(replay identitypolicy.ReplayCache) (production.AcceptedIdentity, error) {
		if err := replay.MarkUsed("new-proof", later.Add(time.Hour)); err != nil {
			return production.AcceptedIdentity{}, err
		}
		return production.AcceptedIdentity{Agent: ActorGateway}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM replay").Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay count=%d error=%v", count, err)
	}
}

func TestStoreRestartWithoutDatabaseClose(t *testing.T) {
	const childDatabase = "ASB_HUMAN_STORE_CHILD_DATABASE"
	if path := os.Getenv(childDatabase); path != "" {
		store := openTestStore(t, path)
		_, proposal := executeStore(t, store, testProposal("process", true, 0), ActorAgent, "proposal")
		result, _ := executeStore(t, store, testDecision("approve-process", KindApprove, *proposal.Operation), ActorGateway, "approval")
		if _, err := os.Stdout.Write(result); err != nil {
			t.Fatal(err)
		}
		// Skip testing cleanup and sql.DB.Close to leave recovery to SQLite's
		// committed WAL state, as when the service exits before replying.
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "state.sqlite")
	child := exec.Command(os.Args[0], "-test.run=^TestStoreRestartWithoutDatabaseClose$")
	child.Env = append(os.Environ(), childDatabase+"="+path)
	original, err := child.Output()
	if err != nil {
		t.Fatalf("child process: %v", err)
	}
	var result Response
	if err := json.Unmarshal(original, &result); err != nil || result.Operation == nil {
		t.Fatalf("child response = %s, error = %v", original, err)
	}
	store := openTestStore(t, path)
	recovered, response := executeStore(t, store, testDecision("approve-process", KindApprove, *result.Operation), ActorGateway, "recovery")
	if !bytes.Equal(original, recovered) {
		t.Fatal("process restart changed the committed response")
	}
	requireSetting(t, response, true, 1)
}

func TestStoreExpiresProofBeforeCommitWithoutEffect(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	command := testProposal("proposal", true, 0)
	now := storeTestTime
	store.now = func() time.Time { return now }
	store.beforeCommit = func() error {
		now = now.Add(time.Hour)
		return nil
	}
	if _, err := store.Execute(context.Background(), command, testStoreAuth(ActorAgent, "proof")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired proof error = %v", err)
	}
	store.beforeCommit = nil
	now = storeTestTime
	_, inbox := executeStore(t, store, Command{CommandID: "inbox", Kind: KindInbox}, ActorGateway, "inbox")
	if len(inbox.Operations) != 0 {
		t.Fatal("expired authorization committed a proposal")
	}
	executeStore(t, store, command, ActorAgent, "proof")
}

func TestStoreProposalLimitReservesDecisionsAndAllowsRecovery(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	proposals := make([]Operation, 0, maxProposalRecords)
	var original []byte
	var firstCommand Command
	for index := 0; index < maxProposalRecords; index++ {
		id := fmt.Sprintf("proposal-%04d", index)
		command := testProposal(id, true, 0)
		raw, response := executeStore(t, store, command, ActorAgent, id)
		proposals = append(proposals, *response.Operation)
		if index == 0 {
			original, firstCommand = raw, command
		}
	}
	_, err := store.Execute(context.Background(), testProposal("over-limit", true, 0), testStoreAuth(ActorAgent, "over-limit-proof"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("proposal admission limit error = %v", err)
	}
	// Exercise the ordinary command path at the actual configured limit. Every
	// admitted proposal must still have room for one approval or denial.
	for index, operation := range proposals {
		kind := KindDecline
		if index == 0 {
			kind = KindApprove
		}
		id := fmt.Sprintf("decision-%04d", index)
		_, response := executeStore(t, store, testDecision(id, kind, operation), ActorGateway, id)
		if response.Operation.State == StatePending {
			t.Fatalf("proposal %s could not be decided at the admission limit", operation.OperationID)
		}
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM commands").Scan(&count); err != nil || count != maxMutationRecords {
		t.Fatalf("mutation count=%d error=%v", count, err)
	}
	recovered, _ := executeStore(t, store, firstCommand, ActorAgent, "recovery")
	if !bytes.Equal(original, recovered) {
		t.Fatal("full store lost the original response")
	}
	_, inbox := executeStore(t, store, Command{CommandID: "inbox", Kind: KindInbox}, ActorGateway, "inbox")
	if len(inbox.Operations) != maxInboxOperations {
		t.Fatal("full store did not preserve the bounded inbox")
	}
	requireSetting(t, inbox, true, 1)
}
