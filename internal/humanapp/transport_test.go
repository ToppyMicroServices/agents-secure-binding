// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
)

type liveApp struct {
	store   *Store
	server  *httptest.Server
	agent   *Client
	gateway *Client
}

func privateFixtureDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func startLiveApp(t *testing.T, dir string, drop *atomic.Bool) *liveApp {
	t.Helper()
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(dir, "state.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	core, err := NewCoreServer(dir, store)
	if err != nil {
		t.Fatal(err)
	}
	handler := core.Handler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if drop != nil && r.URL.Path == CommandPath && drop.CompareAndSwap(true, false) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		handler.ServeHTTP(w, r)
	}))
	server.TLS = core.TLSConfig()
	server.StartTLS()
	address := strings.TrimPrefix(server.URL, "https://")
	agent, err := NewClient(dir, ActorAgent, address)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewClient(dir, ActorGateway, address)
	if err != nil {
		t.Fatal(err)
	}
	app := &liveApp{store, server, agent, gateway}
	t.Cleanup(app.close)
	return app
}

func (a *liveApp) close() { a.server.Close(); _ = a.store.Close() }

func liveProposal(id string, revision uint64, enabled bool) Command {
	return Command{CommandID: "propose-" + id, Kind: KindPropose, OperationID: id, ExpectedRevision: revision, Change: &protectedchange.ChangeRequest{ChangeID: id, Tenant: Tenant, Setting: SettingName, Enabled: enabled}}
}

func liveResponse(t *testing.T, client *Client, command Command) ([]byte, Response) {
	t.Helper()
	raw, err := client.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	var result Response
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return raw, result
}

func TestLiveASBApprovalAndOriginalResultAfterRestart(t *testing.T) {
	dir := privateFixtureDir(t)
	app := startLiveApp(t, dir, nil)
	proposal := liveProposal("restart", 0, true)
	proposalRaw, proposed := liveResponse(t, app.agent, proposal)
	if proposed.Operation.State != StatePending {
		t.Fatal("proposal was not pending")
	}
	decision := Command{CommandID: "approve-restart", Kind: KindApprove, OperationID: proposal.OperationID, ProposalDigest: proposed.Operation.ProposalDigest, ExpectedRevision: proposed.Operation.Before.Revision}
	decisionRaw, approved := liveResponse(t, app.gateway, decision)
	if approved.Operation.State != StateApplied || approved.Operation.After.Revision != 1 || !approved.Operation.After.Enabled || approved.Operation.Assurance != Assurance {
		t.Fatalf("approval result = %+v", approved.Operation)
	}
	var identity string
	if err := app.store.db.QueryRow("SELECT identity FROM commands WHERE actor = ? AND command_id = ?", ActorGateway, decision.CommandID).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(identity, ActorGateway) || !strings.Contains(identity, authorityIssuer) {
		t.Fatal("real accepted ASB identity missing")
	}
	app.close()
	reopened := startLiveApp(t, dir, nil)
	retriedProposal, _ := liveResponse(t, reopened.agent, proposal)
	retriedDecision, _ := liveResponse(t, reopened.gateway, decision)
	if !bytes.Equal(proposalRaw, retriedProposal) || !bytes.Equal(decisionRaw, retriedDecision) {
		t.Fatal("fresh-proof retry did not preserve original bytes")
	}
	_, current := liveResponse(t, reopened.agent, Command{CommandID: "status-restart", Kind: KindStatus, OperationID: proposal.OperationID, ProposalDigest: proposed.Operation.ProposalDigest})
	if current.Operation.State != StateApplied || current.Setting.Revision != 1 {
		t.Fatal("status lost the original effect")
	}
}

func TestLiveASBLostApprovalResponseRecoversWithoutAnotherEffect(t *testing.T) {
	dir := privateFixtureDir(t)
	var drop atomic.Bool
	app := startLiveApp(t, dir, &drop)
	proposal := liveProposal("response-loss", 0, true)
	_, proposed := liveResponse(t, app.agent, proposal)
	decision := Command{CommandID: "approve-response-loss", Kind: KindApprove, OperationID: proposal.OperationID, ProposalDigest: proposed.Operation.ProposalDigest, ExpectedRevision: 0}
	drop.Store(true)
	if _, err := app.gateway.Execute(context.Background(), decision); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lost response = %v", err)
	}
	var original []byte
	if err := app.store.db.QueryRow("SELECT response FROM commands WHERE actor = ? AND command_id = ?", ActorGateway, decision.CommandID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	app.close()
	reopened := startLiveApp(t, dir, nil)
	recovered, result := liveResponse(t, reopened.gateway, decision)
	if !bytes.Equal(original, recovered) || result.Operation.After.Revision != 1 {
		t.Fatal("lost response recovery changed original result")
	}
	_, inbox := liveResponse(t, reopened.agent, Command{CommandID: "read-after-loss", Kind: KindInbox})
	if inbox.Setting.Revision != 1 {
		t.Fatal("recovery applied another effect")
	}
}

func TestLiveASBTransactionFailurePreservesUnknownOutcome(t *testing.T) {
	app := startLiveApp(t, privateFixtureDir(t), nil)
	proposal := liveProposal("rollback", 0, true)
	app.store.beforeCommit = func() error { return errors.New("synthetic persistence failure") }
	if _, err := app.agent.Execute(context.Background(), proposal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed commit = %v", err)
	}
	app.store.beforeCommit = nil
	_, result := liveResponse(t, app.agent, proposal)
	if result.Operation.State != StatePending || result.Setting.Revision != 0 {
		t.Fatal("failed transaction escaped into effect")
	}
}

func TestLocalCredentialInitializationPreservesKeysAndRejectsPartialState(t *testing.T) {
	dir := privateFixtureDir(t)
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	one, err := LoginToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Initialize(dir); err != nil {
		t.Fatal(err)
	}
	two, err := LoginToken(dir)
	if err != nil || one != two {
		t.Fatal("restart replaced credentials")
	}
	partial := privateFixtureDir(t)
	if err := writePrivate(partial, "incomplete", []byte("preserve")); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(partial); err == nil {
		t.Fatal("partial initialization was silently replaced")
	}
}
