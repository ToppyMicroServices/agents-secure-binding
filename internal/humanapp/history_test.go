// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryOrdersDecisionTimeIncludingFractionalSeconds(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
	for i, fraction := range []time.Duration{10 * time.Nanosecond, 0, time.Nanosecond} {
		id := fmt.Sprintf("history-%d", i)
		_, proposal := executeStore(t, store, testProposal(id, true, 0), ActorAgent, "propose-"+id)
		now := storeTestTime.Add(time.Second + fraction)
		store.now = func() time.Time { return now }
		executeStore(t, store, testDecision("decide-"+id, KindDecline, *proposal.Operation), ActorGateway, "decide-"+id)
	}
	_, result := executeStore(t, store, Command{CommandID: "history", Kind: KindInbox}, ActorGateway, "history")
	for i, id := range []string{"history-0", "history-2", "history-1"} {
		if result.History[i].OperationID != id {
			t.Fatalf("history[%d] = %s, want %s", i, result.History[i].OperationID, id)
		}
	}
}

func TestHistoryOffsetIsBoundedAndBoundToExactCommand(t *testing.T) {
	command := Command{CommandID: "history", Kind: KindInbox}
	first, err := CommandContext(command)
	if err != nil {
		t.Fatal(err)
	}
	command.HistoryOffset = maxInboxOperations
	second, err := CommandContext(command)
	if err != nil || bytes.Equal(first, second) {
		t.Fatal("history selector was not bound to the command")
	}
	for _, offset := range []int{-1, maxProposalRecords + 1} {
		command.HistoryOffset = offset
		if !errors.Is(command.Validate(), ErrInvalid) {
			t.Fatalf("accepted offset %d", offset)
		}
	}
	command = testProposal("proposal", true, 0)
	command.HistoryOffset = 1
	if !errors.Is(command.Validate(), ErrInvalid) {
		t.Fatal("accepted a history selector on a mutation")
	}
}

func TestWebHistoryAndExactLookupRequireSessionAndValidatedSelectors(t *testing.T) {
	var commands []Command
	handler := newTestWebHandler(t, func(_ context.Context, command Command) ([]byte, error) {
		commands = append(commands, command)
		return []byte(`{}`), nil
	})
	digest := "sha256:" + strings.Repeat("a", 64)
	lookup := "/api/operation?operation_id=old-proposal&proposal_digest=" + url.QueryEscape(digest)
	for _, path := range []string{"/api/inbox?history_offset=100", lookup} {
		if res := webTestRequest(t, handler, "GET", path, nil, testWebSession{}); res.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s: %d", path, res.Code)
		}
	}
	if len(commands) != 0 {
		t.Fatal("unauthenticated read reached executor")
	}
	session := loginWebTest(t, handler)
	for _, path := range []string{"/api/inbox?history_offset=100", lookup} {
		if res := webTestRequest(t, handler, "GET", path, nil, session); res.Code != http.StatusOK {
			t.Fatalf("authenticated %s: %d", path, res.Code)
		}
	}
	if len(commands) != 2 || commands[0].Kind != KindInbox || commands[0].HistoryOffset != 100 || commands[1].Kind != KindStatus || commands[1].OperationID != "old-proposal" || commands[1].ProposalDigest != digest {
		t.Fatalf("selectors changed: %+v", commands)
	}
	for _, path := range []string{
		"/api/inbox?history_offset=-1", "/api/inbox?history_offset=5001", "/api/inbox?history_offset=01", "/api/inbox?history_offset=1&history_offset=2", "/api/inbox?history_offset=1&actor=other", "/api/inbox?history_offset=1.5", "/api/inbox?history_offset=99999999999999999999999999",
		"/api/operation?operation_id=old-proposal", lookup + "&proposal_digest=" + url.QueryEscape(digest), lookup + "&history_offset=1", "/api/operation?operation_id=old-proposal&proposal_digest=invalid",
	} {
		if res := webTestRequest(t, handler, "GET", path, nil, session); res.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s: %d", path, res.Code)
		}
	}
	if len(commands) != 2 {
		t.Fatal("invalid selector reached executor")
	}
}

func TestCapacityRejectionSurvivesLiveTransportAndWeb(t *testing.T) {
	app := startLiveApp(t, privateFixtureDir(t), nil)
	if _, err := app.store.db.Exec("UPDATE setting SET revision = ?", maxSettingRevision); err != nil {
		t.Fatal(err)
	}
	_, proposed := liveResponse(t, app.agent, liveProposal("revision-limit", maxSettingRevision, true))
	decision := testDecision("limit-decision", KindApprove, *proposed.Operation)
	if _, err := app.gateway.Execute(t.Context(), decision); !errors.Is(err, ErrCapacity) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("capacity error lost in transport: %v", err)
	}
	_, unchanged := liveResponse(t, app.agent, testStatus(*proposed.Operation))
	if unchanged.Operation.State != StatePending || unchanged.Setting.Enabled || unchanged.Setting.Revision != maxSettingRevision {
		t.Fatal("capacity rejection changed state")
	}
	handler := newTestWebHandler(t, app.gateway.Execute)
	session := loginWebTest(t, handler)
	res := webTestRequest(t, handler, "POST", "/api/decision", map[string]any{"operation_id": proposed.Operation.OperationID, "proposal_digest": proposed.Operation.ProposalDigest, "expected_revision": maxSettingRevision, "decision": KindApprove}, session)
	if res.Code != http.StatusInsufficientStorage || !strings.Contains(res.Body.String(), `"code":"CAPACITY_EXCEEDED"`) || !strings.Contains(res.Body.String(), `"outcome_unknown":false`) || !strings.Contains(res.Body.String(), "storage-status") {
		t.Fatalf("capacity browser response: %d %s", res.Code, res.Body.String())
	}
}
