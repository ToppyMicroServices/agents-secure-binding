//go:build linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/operationjournal"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/sqlitestore"
)

const (
	integrationSession   = "https://relay.example/sessions/opaque"
	integrationContent   = "https://content.example/notifications/review"
	integrationRecipient = "private-recipient@example.net"
	integrationToken     = "test-only-cloudflare-integration-token"
)

type cloudflareRelayFixture struct {
	root       string
	directory  *sqlitestore.Store
	relay      *humanrelay.FileStore
	dispatcher *Dispatcher
	worker     *humanrelay.Worker
	request    humanrelay.DispatchRequest
	server     *httptest.Server
	config     Config
}

// The loopback TLS server implements the documented send response. It is not
// Cloudflare and these tests never deliver an email or authenticate to a cloud.
func newCloudflareRelayFixture(t *testing.T, handler http.Handler) *cloudflareRelayFixture {
	t.Helper()
	f := &cloudflareRelayFixture{root: t.TempDir(), server: httptest.NewTLSServer(handler)}
	t.Cleanup(f.server.Close)
	message := Message{Subject: "ASB review available", Text: "Open your ASB inbox to review the pending request."}
	digest, err := MessageDigest(message)
	if err != nil {
		t.Fatal(err)
	}
	f.config = Config{
		AccountID: strings.Repeat("a", 32), APIToken: integrationToken,
		Sender:   "notifications@example.com",
		Routes:   map[string]string{integrationSession: integrationRecipient},
		Messages: map[string]Message{integrationContent: message},
		Timeout:  2 * time.Second, MaxInFlight: 2,
	}
	f.request = humanrelay.DispatchRequest{
		IntentID: "intent:cloudflare:review", RelaySessionRef: integrationSession,
		Channel: taskcoord.ReachabilityEmail, ContentRef: integrationContent, ContentDigest: digest,
	}
	f.open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, p := range []taskcoord.Participant{
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "human:private", Kind: taskcoord.ParticipantHuman, IdentityRef: "urn:identity:human", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:requester", Kind: taskcoord.ParticipantAgent, IdentityRef: "urn:identity:agent", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
	} {
		if err := f.directory.RegisterParticipant(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	consent := taskcoord.HumanMatchConsent{
		Schema: taskcoord.HumanMatchConsentSchemaV1, ConsentID: "consent:notification", HumanParticipantID: "human:private",
		CandidateID: "candidate:notification", RequesterParticipantID: "agent:requester", Purpose: "task-review", Capability: "review", Channel: taskcoord.ReachabilityEmail,
		ContactRequestRef: "https://relay.example/requests/opaque", ActorID: "gateway:human", AuthorizationID: "authorization:consent", ProofID: "proof:consent",
		GrantedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if err := f.directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := f.directory.IssueHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityGrantDefinition{
		GrantID: "grant:notification", ConsentID: consent.ConsentID, ApprovedByParticipantID: consent.HumanParticipantID,
		CandidateID: consent.CandidateID, RequesterParticipantID: consent.RequesterParticipantID, Purpose: consent.Purpose, Capability: consent.Capability, Channel: consent.Channel,
		RelaySessionRef: integrationSession, IssuedAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(time.Hour),
		ApprovalActorID: "gateway:human", ApprovalAuthorizationID: "authorization:grant", ApprovalProofID: "proof:grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := humanrelay.RelayIntentRequest{
		IntentID: f.request.IntentID, GrantID: grant.GrantID, RequesterParticipantID: grant.RequesterParticipantID,
		Purpose: grant.Purpose, Capability: grant.Capability, Channel: grant.Channel,
		ContentRef: integrationContent, ContentDigest: digest,
	}
	requestDigest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	// This trusted verifier projection isolates adapter/store integration. It
	// does not replace a deployment's ASB proof verification.
	commit := humanrelay.QueueCommit{Request: request, QueuedAt: now, Authorization: humanrelay.AuthenticatedRelayIntent{
		RequestDigest: requestDigest.String(), ActorID: "gateway:agent", AuthorizationID: "authorization:notification",
		ProofID: "proof:notification", VerifierNonce: "nonce:notification", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}}
	if _, err := f.relay.CommitAuthorizedIntent(ctx, commit); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *cloudflareRelayFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.directory, err = sqlitestore.Open(filepath.Join(f.root, "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	directory := f.directory
	t.Cleanup(func() { _ = directory.Close() })
	f.relay, err = humanrelay.OpenFileStore(filepath.Join(f.root, "private", "relay.json"), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	f.config.Journal, err = operationjournal.OpenFileStore(filepath.Join(f.root, "private", "cloudflare.json"))
	if err != nil {
		t.Fatal(err)
	}
	f.dispatcher, err = New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the production URL and hostname in the request. Only this test
	// transport dials the local fixture, verifying its generated certificate.
	transport := f.server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = f.server.Certificate().DNSNames[0]
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", f.server.Listener.Addr().String())
	}
	f.dispatcher.client.Transport = transport
	dispatcher := f.dispatcher
	t.Cleanup(dispatcher.Close)
	f.worker, err = humanrelay.NewWorker(f.relay, f.dispatcher)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *cloudflareRelayFixture) restart(t *testing.T) {
	t.Helper()
	f.dispatcher.Close()
	if err := f.directory.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
}

func TestCloudflareRelayTLSAcknowledgementSurvivesRestart(t *testing.T) {
	var calls atomic.Int32
	f := newCloudflareRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Host != "api.cloudflare.com" || r.URL.Path != "/client/v4/accounts/"+strings.Repeat("a", 32)+"/email/sending/send" || r.Header.Get("Authorization") != "Bearer "+integrationToken {
			t.Error("unexpected request method, destination, or credentials")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var message map[string]string
		if err := json.NewDecoder(r.Body).Decode(&message); err != nil || message["to"] != integrationRecipient || message["subject"] != "ASB review available" {
			t.Error("unexpected message payload")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"success":true,"errors":[],"messages":[],"result":{"delivered":[],"queued":["`+integrationRecipient+`"],"permanent_bounces":[],"suppressed_recipients":[],"message_id":"private-provider-message-id"}}`)
	}))
	ctx := context.Background()
	receipt, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err != nil || receipt.Status != humanrelay.StatusProviderAcknowledged {
		t.Fatalf("dispatch: status=%s error=%v", receipt.Status, err)
	}
	assertCloudflareReceiptPrivate(t, receipt)
	f.restart(t)
	retry, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err != nil || retry != receipt || calls.Load() != 1 {
		t.Fatalf("restart changed acknowledgement or resent: error=%v calls=%d", err, calls.Load())
	}
	ack, found, err := f.dispatcher.Lookup(ctx, f.request)
	if err != nil || !found || ack.IntentID != f.request.IntentID || calls.Load() != 1 {
		t.Fatalf("saved acknowledgement not recovered: found=%v error=%v calls=%d", found, err, calls.Load())
	}
	if _, err := f.directory.LoadAssignment(ctx, "assignment:notification"); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatal("a notification must not create an assignment")
	}
}

func TestCloudflareRelayLostTLSResponseRemainsUnknownAfterRestart(t *testing.T) {
	var calls atomic.Int32
	f := newCloudflareRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	ctx := context.Background()
	receipt, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err == nil || receipt.Status != humanrelay.StatusDispatching || calls.Load() != 1 {
		t.Fatalf("lost response did not preserve uncertainty: status=%s error=%v calls=%d", receipt.Status, err, calls.Load())
	}
	f.restart(t)
	retry, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err != nil || retry != receipt || calls.Load() != 1 {
		t.Fatalf("unknown delivery retried: error=%v calls=%d", err, calls.Load())
	}
	reconciled, err := f.worker.Reconcile(ctx, f.request.IntentID, f.dispatcher)
	if err != nil || reconciled != receipt || calls.Load() != 1 {
		t.Fatalf("missing evidence changed unknown: error=%v calls=%d", err, calls.Load())
	}
	assertCloudflareReceiptPrivate(t, reconciled)
}

func TestCloudflareRelayRevocationPreventsNetworkAttempt(t *testing.T) {
	var calls atomic.Int32
	f := newCloudflareRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	ctx := context.Background()
	if err := f.directory.RevokeHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityRevocation{
		Schema: taskcoord.HumanReachabilityRevocationSchemaV1, EventID: "event:notification-withdrawal", GrantID: "grant:notification", ParticipantID: "human:private",
		ActorID: "gateway:human", AuthorizationID: "authorization:withdrawal", ProofID: "proof:withdrawal", At: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	f.restart(t)
	receipt, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err != nil || receipt.Status != humanrelay.StatusCanceled || calls.Load() != 0 {
		t.Fatalf("revoked notification dispatched: status=%s error=%v calls=%d", receipt.Status, err, calls.Load())
	}
}

func TestCloudflareRelayBusyCallbackConsumesDispatchReservation(t *testing.T) {
	var calls atomic.Int32
	f := newCloudflareRelayFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	// Saturate the adapter before the worker enters its callback. The worker
	// has already persisted DISPATCHING when the adapter returns ErrBusy.
	for i := 0; i < cap(f.dispatcher.slots); i++ {
		f.dispatcher.slots <- struct{}{}
	}
	ctx := context.Background()
	receipt, err := f.worker.Dispatch(ctx, f.request.IntentID)
	for i := 0; i < cap(f.dispatcher.slots); i++ {
		<-f.dispatcher.slots
	}
	if err == nil || receipt.Status != humanrelay.StatusDispatching || calls.Load() != 0 {
		t.Fatalf("busy callback did not preserve reservation: status=%s error=%v calls=%d", receipt.Status, err, calls.Load())
	}
	retry, err := f.worker.Dispatch(ctx, f.request.IntentID)
	if err != nil || retry != receipt || calls.Load() != 0 {
		t.Fatalf("freed capacity permitted redispatch: error=%v calls=%d", err, calls.Load())
	}
	reconciled, err := f.worker.Reconcile(ctx, f.request.IntentID, f.dispatcher)
	if err != nil || reconciled != receipt || calls.Load() != 0 {
		t.Fatalf("missing busy-attempt journal permitted delivery: error=%v calls=%d", err, calls.Load())
	}
}

func assertCloudflareReceiptPrivate(t *testing.T, receipt humanrelay.Receipt) {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{integrationRecipient, integrationToken, "human:private", "notifications@example.com", integrationSession, "private-provider-message-id", "ASB review available"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("Agent-visible receipt contains private provider data")
		}
	}
}
