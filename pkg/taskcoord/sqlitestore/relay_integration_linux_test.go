// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
)

func durableRelayFixture(t *testing.T, directory *Store, path string) (*humanrelay.FileStore, humanrelay.QueueCommit) {
	t.Helper()
	grant, _ := reachabilityGrantFixture(t, directory)
	request := humanrelay.RelayIntentRequest{
		IntentID: "intent:durable", GrantID: grant.GrantID, RequesterParticipantID: grant.RequesterParticipantID,
		Purpose: grant.Purpose, Capability: grant.Capability, Channel: grant.Channel,
		ContentRef: "https://content.example/message", ContentDigest: strings.Repeat("a", 64),
	}
	digest, err := humanrelay.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	commit := humanrelay.QueueCommit{Request: request, QueuedAt: base.Add(time.Minute), Authorization: humanrelay.AuthenticatedRelayIntent{
		RequestDigest: digest.String(), ActorID: "gateway:agent", AuthorizationID: "authorization:relay", ProofID: "proof:relay", VerifierNonce: "nonce:relay", IssuedAt: base, ExpiresAt: base.Add(time.Hour),
	}}
	relay, err := humanrelay.OpenFileStore(path, directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.CommitAuthorizedIntent(ctx, commit); err != nil {
		t.Fatal(err)
	}
	return relay, commit
}

func TestSQLiteAuthorityAndDurableRelayRestartRevocation(t *testing.T) {
	root := t.TempDir()
	path, relayPath := filepath.Join(root, "coord.db"), filepath.Join(root, "private", "relay.json")
	directory := openTest(t, path, base.Add(time.Minute))
	_, commit := durableRelayFixture(t, directory, relayPath)
	_ = directory.Close()
	directory = openTest(t, path, base.Add(2*time.Minute))
	if err := revokeGrant(directory); err != nil {
		t.Fatal(err)
	}
	relay, err := humanrelay.OpenFileStore(relayPath, directory)
	if err != nil {
		t.Fatal(err)
	}
	provider := &durableRelayTestProvider{}
	receipt, err := relay.CommitAuthorizedDispatch(ctx, commit.Request.IntentID, provider, directory.now)
	if err != nil || receipt.Status != humanrelay.StatusCanceled || provider.calls != 0 {
		t.Fatalf("revoked durable intent: %+v %v calls=%d", receipt, err, provider.calls)
	}
	if retry, err := relay.CommitAuthorizedIntent(ctx, commit); err != nil || retry != receipt {
		t.Fatal("exact queue retry lost terminal outcome", err)
	}
}

func TestSQLiteAuthorityAndRelayUnknownReconciliation(t *testing.T) {
	root := t.TempDir()
	path, relayPath := filepath.Join(root, "coord.db"), filepath.Join(root, "private", "relay.json")
	directory := openTest(t, path, base.Add(time.Minute))
	relay, commit := durableRelayFixture(t, directory, relayPath)
	provider := &durableRelayTestProvider{ambiguous: true}
	receipt, err := relay.CommitAuthorizedDispatch(ctx, commit.Request.IntentID, provider, directory.now)
	if err == nil || receipt.Status != humanrelay.StatusDispatching || provider.calls != 1 {
		t.Fatalf("ambiguous dispatch was not retained: %+v %v", receipt, err)
	}
	_ = directory.Close()
	directory = openTest(t, path, base.Add(2*time.Minute))
	if err := revokeGrant(directory); err != nil {
		t.Fatal(err)
	}
	relay, err = humanrelay.OpenFileStore(relayPath, directory)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = relay.CommitAuthorizedDispatch(ctx, commit.Request.IntentID, provider, directory.now)
	if provider.calls != 1 {
		t.Fatal("unknown delivery was redispatched after restart")
	}
	provider.found = false
	receipt, err = relay.ReconcileDispatch(ctx, commit.Request.IntentID, provider, directory.now)
	if err != nil || receipt.Status != humanrelay.StatusDispatching {
		t.Fatal("missing provider history was treated as no effect", err)
	}
	provider.found = true
	receipt, err = relay.ReconcileDispatch(ctx, commit.Request.IntentID, provider, directory.now)
	if err != nil || receipt.Status != humanrelay.StatusProviderAcknowledged || provider.calls != 1 {
		t.Fatalf("historical reconciliation failed: %+v %v", receipt, err)
	}
}

// A deterministic trusted adapter tests store composition only; this does not
// qualify a real provider's persistence or request authentication.
type durableRelayTestProvider struct {
	calls     int
	ambiguous bool
	found     bool
	request   humanrelay.DispatchRequest
}

func (p *durableRelayTestProvider) Dispatch(_ context.Context, request humanrelay.DispatchRequest) (humanrelay.ProviderAck, error) {
	p.calls++
	p.request = request
	if p.ambiguous {
		return humanrelay.ProviderAck{}, errors.New("provider acknowledgement unavailable")
	}
	return humanrelay.ProviderAck{IntentID: request.IntentID, AckRef: "ack:durable"}, nil
}

func (p *durableRelayTestProvider) Lookup(_ context.Context, request humanrelay.DispatchRequest) (humanrelay.ProviderAck, bool, error) {
	if request != p.request {
		return humanrelay.ProviderAck{}, false, errors.New("provider request binding mismatch")
	}
	return humanrelay.ProviderAck{IntentID: request.IntentID, AckRef: "ack:durable"}, p.found, nil
}
