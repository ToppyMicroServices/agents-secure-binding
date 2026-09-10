// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestServiceQueuesAndDispatchesWithoutHumanOrContactLeak(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	receipt, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != StatusQueued {
		t.Fatalf("queue status = %s, want QUEUED", receipt.Status)
	}
	assertNoPrivateHumanData(t, receipt, fixture.humanID)

	acknowledged, err := fixture.worker.Dispatch(context.Background(), fixture.request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	if acknowledged.Status != StatusProviderAcknowledged {
		t.Fatalf("dispatch status = %s, want PROVIDER_ACKNOWLEDGED", acknowledged.Status)
	}
	dispatched, err := fixture.sink.Load(fixture.request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	if dispatched.RelaySessionRef != fixture.grant.RelaySessionRef || dispatched.ContentDigest != fixture.request.ContentDigest {
		t.Fatalf("dispatch = %+v", dispatched)
	}
	assertNoPrivateHumanData(t, dispatched, fixture.humanID)

	// Provider acknowledgement is transport state only. No TaskCoord
	// Assignment or Interaction was created or mutated by the relay service.
	if _, err := fixture.participants.LoadAssignment(context.Background(), "assignment:relay"); !errors.Is(err, taskcoord.ErrNotFound) {
		t.Fatalf("relay unexpectedly created an Assignment: %v", err)
	}
	if events, err := fixture.participants.ListInteractionEvents(context.Background(), "interaction:relay"); (err != nil && !errors.Is(err, taskcoord.ErrNotFound)) || len(events) != 0 {
		t.Fatalf("relay unexpectedly created Interaction events: %+v, %v", events, err)
	}
}

func TestRelayEventIDGolden(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		status Status
		want   string
	}{
		{
			status: StatusQueued,
			want:   "relay-event:v1:ac53d59295a55d0ba9367f291912277d279ef8f260723c9373eb0c48df73087c",
		},
		{
			status: StatusDispatching,
			want:   "relay-event:v1:893dd021dd5f62e75664ff83f459396e7baebc0d4f5747cea8dca1855a6bcef3",
		},
		{
			status: StatusProviderAcknowledged,
			want:   "relay-event:v1:7c9e1e0b1e0dbc8effbd7551d2eb7307e23500aa7b3d2c270e5c2153be0d73a1",
		},
		{
			status: StatusCanceled,
			want:   "relay-event:v1:5a565baab8b740d3a2c4dd445ed4eedc5604d44eb1cabf2f152aae1eb9b2dba7",
		},
	}
	for _, test := range tests {
		t.Run(string(test.status), func(t *testing.T) {
			got, err := relayEventID(test.status, "intent:golden:1")
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("relayEventID() = %q, want %q", got, test.want)
			}
			event := Event{
				Schema: RelayEventSchemaV1, EventID: got, IntentID: "intent:golden:1",
				Status: test.status, At: at,
			}
			if test.status == StatusProviderAcknowledged {
				event.ProviderAckRef = "provider-ack:golden:1"
			}
			if err := event.Validate(); err != nil {
				t.Fatalf("derived EventID is invalid: %v", err)
			}
		})
	}
	forged := Event{
		Schema:   RelayEventSchemaV1,
		EventID:  relayEventIDPrefix + strings.Repeat("0", 64),
		IntentID: "intent:golden:1",
		Status:   StatusQueued,
		At:       at,
	}
	if err := forged.Validate(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-derived EventID error = %v, want ErrInvalidRequest", err)
	}
}

func TestRelaySupportsBoundaryIntentIDs(t *testing.T) {
	t.Parallel()
	for _, size := range []int{237, 238, 243, 244, 256} {
		t.Run(fmt.Sprintf("bytes-%d", size), func(t *testing.T) {
			fixture := newRelayFixture(t)
			fixture.request.IntentID = strings.Repeat("i", size)
			fixture.refreshAuth(t)

			if _, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
				t.Fatalf("Queue() rejected %d-byte intent ID: %v", size, err)
			}
			acknowledged, err := fixture.worker.Dispatch(context.Background(), fixture.request.IntentID)
			if err != nil {
				t.Fatalf("Dispatch() rejected %d-byte intent ID: %v", size, err)
			}
			events, err := fixture.store.Events(fixture.request.IntentID)
			if err != nil {
				t.Fatal(err)
			}
			if len(events) != 3 || events[0].EventID == events[1].EventID ||
				events[1].EventID == events[2].EventID || events[0].EventID == events[2].EventID {
				t.Fatalf("relay events = %+v", events)
			}
			for _, event := range events {
				if err := event.Validate(); err != nil {
					t.Fatalf("derived event rejected: %v", err)
				}
			}
			retry, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
			if err != nil || retry != acknowledged {
				t.Fatalf("exact retry = %+v, error = %v, want %+v", retry, err, acknowledged)
			}
		})
	}
}

func TestWorkerUsesBrokerReceiptTime(t *testing.T) {
	t.Parallel()
	for _, providerAt := range []time.Time{
		{},
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		fixture := newRelayFixture(t)
		if _, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
			t.Fatal(err)
		}
		brokerAt := fixture.now.Add(7 * time.Second)
		dispatcher := staticDispatcher{ack: ProviderAck{
			IntentID: fixture.request.IntentID, AckRef: "provider-ack:stable", At: providerAt,
		}}
		worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time { return brokerAt })
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
		if err != nil {
			t.Fatalf("Dispatch() with provider time %s: %v", providerAt, err)
		}
		if !receipt.UpdatedAt.Equal(brokerAt) {
			t.Fatalf("UpdatedAt = %s, want broker time %s", receipt.UpdatedAt, brokerAt)
		}
		events, err := fixture.store.Events(fixture.request.IntentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 3 || !events[1].At.Equal(brokerAt) || !events[2].At.Equal(brokerAt) {
			t.Fatalf("acknowledgement events = %+v, want broker time %s", events, brokerAt)
		}
	}
}

func TestWorkerRejectsBrokerClockRollback(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	if _, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
		t.Fatal(err)
	}
	dispatcher := staticDispatcher{ack: ProviderAck{
		IntentID: fixture.request.IntentID, AckRef: "provider-ack:rollback", At: fixture.now,
	}}
	worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time {
		return fixture.now.Add(-time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
	if !errors.Is(err, ErrDispatchConflict) || receipt.Status != StatusQueued {
		t.Fatalf("Dispatch() receipt = %+v, error = %v", receipt, err)
	}
	events, eventsErr := fixture.store.Events(fixture.request.IntentID)
	if eventsErr != nil || len(events) != 1 || events[0].Status != StatusQueued {
		t.Fatalf("rollback mutated events: %+v, error = %v", events, eventsErr)
	}
}

func TestStorePreservesFirstProviderAcknowledgementTime(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	if _, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
		t.Fatal(err)
	}
	firstAt := fixture.now.Add(time.Second)
	firstWorker, err := NewWorkerWithClock(fixture.store, staticDispatcher{ack: ProviderAck{
		IntentID: fixture.request.IntentID, AckRef: "provider-ack:first",
	}}, func() time.Time { return firstAt })
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstWorker.Dispatch(context.Background(), fixture.request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	retryWorker, err := NewWorkerWithClock(fixture.store, staticDispatcher{ack: ProviderAck{
		IntentID: fixture.request.IntentID, AckRef: "provider-ack:changed",
	}}, func() time.Time { return fixture.now.Add(10 * time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	retry, err := retryWorker.Dispatch(context.Background(), fixture.request.IntentID)
	if err != nil || retry != first {
		t.Fatalf("acknowledgement retry = %+v, error = %v, want %+v", retry, err, first)
	}
	events, err := fixture.store.Events(fixture.request.IntentID)
	if err != nil || len(events) != 3 || !events[2].At.Equal(firstAt) ||
		events[2].ProviderAckRef != "provider-ack:first" {
		t.Fatalf("acknowledgement retry changed audit state: %+v, error = %v", events, err)
	}
}

func TestWorkerRejectsMismatchedProviderAcknowledgement(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	if _, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorkerWithClock(fixture.store, staticDispatcher{ack: ProviderAck{
		IntentID: "relay-intent:other", AckRef: "provider-ack:forged",
	}}, func() time.Time { return fixture.now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
	if !errors.Is(err, ErrDispatchConflict) || receipt.Status != StatusDispatching {
		t.Fatalf("mismatched acknowledgement receipt = %+v, error = %v", receipt, err)
	}
	_, stored, err := fixture.store.LoadIntent(context.Background(), fixture.request.IntentID)
	if err != nil || stored.Status != StatusDispatching {
		t.Fatalf("mismatched acknowledgement state: %+v, error = %v", stored, err)
	}
	events, err := fixture.store.Events(fixture.request.IntentID)
	if err != nil || len(events) != 2 || events[0].Status != StatusQueued || events[1].Status != StatusDispatching {
		t.Fatalf("mismatched acknowledgement events: %+v, error = %v", events, err)
	}
}

func TestServiceRequiresActiveExactGrantAndCollapsesFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*relayFixture)
	}{
		{name: "wrong purpose", mutate: func(f *relayFixture) { f.request.Purpose = "different-purpose"; f.refreshAuth(t) }},
		{name: "wrong requester", mutate: func(f *relayFixture) { f.request.RequesterParticipantID = "agent:other"; f.refreshAuth(t) }},
		{name: "wrong channel", mutate: func(f *relayFixture) { f.request.Channel = taskcoord.ReachabilitySNS; f.refreshAuth(t) }},
		{name: "revoked", mutate: func(f *relayFixture) {
			err := f.directory.RevokeHumanReachabilityGrant(context.Background(), taskcoord.HumanReachabilityRevocation{
				Schema: taskcoord.HumanReachabilityRevocationSchemaV1, EventID: "revoke:relay-grant",
				GrantID: f.grant.GrantID, ParticipantID: f.humanID, ActorID: "gateway:human",
				AuthorizationID: "authorization:revoke", ProofID: "proof:revoke", At: f.now.Add(time.Second),
			})
			if err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t)
			test.mutate(fixture)
			_, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Queue() error = %v, want ErrUnavailable", err)
			}
			if _, _, loadErr := fixture.store.LoadIntent(context.Background(), fixture.request.IntentID); !errors.Is(loadErr, ErrNotFound) {
				t.Fatalf("failed request was queued: %v", loadErr)
			}
		})
	}
}

func TestQueueRechecksRevocationInsideAtomicCommit(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		revoke func(*relayFixture) error
	}{
		{
			name: "reachability grant",
			revoke: func(f *relayFixture) error {
				return f.directory.RevokeHumanReachabilityGrant(context.Background(), taskcoord.HumanReachabilityRevocation{
					Schema: taskcoord.HumanReachabilityRevocationSchemaV1, EventID: "revoke:atomic-grant",
					GrantID: f.grant.GrantID, ParticipantID: f.humanID, ActorID: "gateway:human",
					AuthorizationID: "authorization:atomic-grant", ProofID: "proof:atomic-grant", At: f.now,
				})
			},
		},
		{
			name: "Human consent",
			revoke: func(f *relayFixture) error {
				return f.directory.RevokeHumanMatchConsent(context.Background(), taskcoord.HumanMatchConsentRevocation{
					Schema: taskcoord.HumanMatchConsentRevocationSchemaV1, EventID: "revoke:atomic-consent",
					ConsentID: f.consentID, HumanParticipantID: f.humanID, ActorID: "gateway:human",
					AuthorizationID: "authorization:atomic-consent", ProofID: "proof:atomic-consent", At: f.now,
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRelayFixture(t)
			transaction := &blockingGrantTransaction{
				inner: fixture.directory, entered: make(chan struct{}), release: make(chan struct{}),
			}
			store, err := NewMemoryStore(transaction)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewService(store, func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, err := service.Queue(context.Background(), fixture.request, fixture.auth)
				result <- err
			}()
			<-transaction.entered
			if err := test.revoke(fixture); err != nil {
				t.Fatal(err)
			}
			close(transaction.release)
			if err := <-result; !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Queue() error = %v, want ErrUnavailable", err)
			}
			if _, _, err := store.LoadIntent(context.Background(), fixture.request.IntentID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("revoked request was queued: %v", err)
			}
		})
	}
}

func TestServiceEnforcesOneIntentPerGrantAndExactIdempotency(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	first, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil || retry != first {
		t.Fatalf("exact retry = %+v, error = %v", retry, err)
	}

	changed := fixture.request
	changed.ContentRef = "https://content.example/objects/changed"
	changedAuth := verifiedIntent(t, changed, fixture.now)
	if _, err := fixture.service.Queue(context.Background(), changed, changedAuth); !errors.Is(err, ErrIntentConflict) {
		t.Fatalf("changed retry error = %v, want ErrIntentConflict", err)
	}

	const contenders = 12
	concurrent := newRelayFixture(t)
	var wins atomic.Int32
	var consumed atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < contenders; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			request := concurrent.request
			request.IntentID = fmt.Sprintf("relay-intent:race:%d", index)
			auth := verifiedIntent(t, request, concurrent.now)
			_, err := concurrent.service.Queue(context.Background(), request, auth)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrGrantConsumed):
				consumed.Add(1)
			default:
				t.Errorf("unexpected contender error: %v", err)
			}
		}(index)
	}
	group.Wait()
	if wins.Load() != 1 || consumed.Load() != contenders-1 {
		t.Fatalf("wins=%d consumed=%d", wins.Load(), consumed.Load())
	}
}

func TestQueueDoesNotRevealIntentExistenceBeforeGrantAuthorization(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	first, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil {
		t.Fatal(err)
	}

	// Exact recovery is not a new operation and remains available even when
	// the authoritative grant is no longer active.
	if err := fixture.directory.RevokeHumanReachabilityGrant(
		context.Background(),
		taskcoord.HumanReachabilityRevocation{
			Schema:  taskcoord.HumanReachabilityRevocationSchemaV1,
			EventID: "revoke:relay:oracle", GrantID: fixture.grant.GrantID,
			ParticipantID: fixture.humanID, ActorID: "gateway:human",
			AuthorizationID: "authorization:revoke:oracle", ProofID: "proof:revoke:oracle",
			At: fixture.now,
		},
	); err != nil {
		t.Fatal(err)
	}
	recovered, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil || recovered != first {
		t.Fatalf("exact retry after revocation = %+v, %v", recovered, err)
	}

	known := fixture.request
	known.GrantID = "grant:relay:unavailable"
	known.ContentRef = "https://content.example/objects/changed"
	knownAuth := verifiedIntent(t, known, fixture.now)
	_, knownErr := fixture.service.Queue(context.Background(), known, knownAuth)

	unknown := known
	unknown.IntentID = "relay-intent:unknown"
	unknownAuth := verifiedIntent(t, unknown, fixture.now)
	_, unknownErr := fixture.service.Queue(context.Background(), unknown, unknownAuth)

	if !errors.Is(knownErr, ErrUnavailable) || !errors.Is(unknownErr, ErrUnavailable) ||
		knownErr.Error() != unknownErr.Error() {
		t.Fatalf("known/unknown authorization errors differ: known=%v unknown=%v", knownErr, unknownErr)
	}
}

func TestServiceFreshProofRetryReturnsOriginalReceipt(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	first, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil {
		t.Fatal(err)
	}

	retryAt := fixture.now.Add(time.Second)
	retryAuth := verifiedIntent(t, fixture.request, retryAt)
	retryAuth.ActorID = "gateway:agent:retry"
	retryAuth.AuthorizationID = "authorization:relay:retry"
	retryAuth.ProofID = "proof:relay:retry"
	retryAuth.VerifierNonce = "nonce:relay:retry"
	retryService, err := NewService(
		fixture.store, func() time.Time { return retryAt },
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := retryService.Queue(context.Background(), fixture.request, retryAuth)
	if err != nil {
		t.Fatalf("fresh-proof retry error = %v", err)
	}
	if recovered != first {
		t.Fatalf("fresh-proof retry receipt = %+v, want original %+v", recovered, first)
	}
	events, err := fixture.store.Events(fixture.request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Status != StatusQueued {
		t.Fatalf("fresh-proof retry appended relay state: %+v", events)
	}
	stored, _, err := fixture.store.LoadIntent(context.Background(), fixture.request.IntentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ProofID != fixture.auth.ProofID || !stored.QueuedAt.Equal(first.QueuedAt) {
		t.Fatalf("fresh-proof retry replaced original audit record: %+v", stored)
	}
}

func TestDispatchFailureLeavesIntentDispatching(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	failing := &failingDispatcher{}
	service, err := NewService(fixture.store, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(fixture.store, failing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
		t.Fatal(err)
	}
	receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
	if !errors.Is(err, ErrDispatchUnavailable) || strings.Contains(err.Error(), "private-recipient") || receipt.Status != StatusDispatching {
		t.Fatalf("Dispatch() receipt=%+v error=%v", receipt, err)
	}
	_, stored, err := fixture.store.LoadIntent(context.Background(), fixture.request.IntentID)
	if err != nil || stored.Status != StatusDispatching {
		t.Fatalf("stored receipt=%+v error=%v", stored, err)
	}
}

type relayFixture struct {
	now          time.Time
	humanID      string
	consentID    string
	participants *taskcoord.MemoryStore
	directory    *taskcoord.MemoryReachabilityDirectory
	grant        taskcoord.HumanReachabilityGrant
	store        *MemoryStore
	sink         *LocalGatewaySink
	service      *Service
	worker       *Worker
	request      RelayIntentRequest
	auth         AuthenticatedRelayIntent
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	humanID := "human:private:relay"
	agentID := "agent:relay-requester"
	participants := taskcoord.NewMemoryStore()
	for _, participant := range []taskcoord.Participant{
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: humanID, Kind: taskcoord.ParticipantHuman, IdentityRef: "identity:private-human", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
		{Schema: taskcoord.ParticipantSchemaV1, ParticipantID: agentID, Kind: taskcoord.ParticipantAgent, IdentityRef: "identity:relay-agent", Status: taskcoord.ParticipantActive, RegisteredAt: now.Add(-time.Hour)},
	} {
		if err := participants.RegisterParticipant(ctx, participant); err != nil {
			t.Fatal(err)
		}
	}
	directory := taskcoord.NewMemoryReachabilityDirectory(participants)
	consent := taskcoord.HumanMatchConsent{
		Schema: taskcoord.HumanMatchConsentSchemaV1, ConsentID: "consent:relay:1",
		HumanParticipantID: humanID, CandidateID: "candidate:pairwise:relay-1",
		RequesterParticipantID: agentID, Purpose: "task-consultation", Capability: "translation",
		Channel: taskcoord.ReachabilityEmail, ContactRequestRef: "https://relay.example/contact-requests/opaque-1",
		ActorID: "gateway:human", AuthorizationID: "authorization:consent", ProofID: "proof:consent",
		GrantedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	if err := directory.RegisterHumanMatchConsent(ctx, consent); err != nil {
		t.Fatal(err)
	}
	grant, err := directory.IssueHumanReachabilityGrant(ctx, taskcoord.HumanReachabilityGrantDefinition{
		GrantID: "grant:relay:1", ConsentID: consent.ConsentID, ApprovedByParticipantID: humanID,
		CandidateID: consent.CandidateID, RequesterParticipantID: agentID,
		Purpose: consent.Purpose, Capability: consent.Capability, Channel: consent.Channel,
		RelaySessionRef: "https://relay.example/sessions/opaque-session-1",
		IssuedAt:        now.Add(-30 * time.Second), ExpiresAt: now.Add(30 * time.Minute),
		ApprovalActorID: "gateway:human", ApprovalAuthorizationID: "authorization:grant", ApprovalProofID: "proof:grant",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := RelayIntentRequest{
		IntentID: "relay-intent:1", GrantID: grant.GrantID, RequesterParticipantID: agentID,
		Purpose: grant.Purpose, Capability: grant.Capability, Channel: grant.Channel,
		ContentRef: "https://content.example/objects/message-1", ContentDigest: strings.Repeat("a", 64),
	}
	store, err := NewMemoryStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	sink := NewLocalGatewaySink(func() time.Time { return now.Add(2 * time.Second) })
	service, err := NewService(store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(store, sink)
	if err != nil {
		t.Fatal(err)
	}
	return &relayFixture{
		now: now, humanID: humanID, consentID: consent.ConsentID, participants: participants, directory: directory, grant: grant,
		store: store, sink: sink, service: service, worker: worker, request: request, auth: verifiedIntent(t, request, now),
	}
}

func (f *relayFixture) refreshAuth(t *testing.T) {
	t.Helper()
	f.auth = verifiedIntent(t, f.request, f.now)
}

func verifiedIntent(t *testing.T, request RelayIntentRequest, now time.Time) AuthenticatedRelayIntent {
	t.Helper()
	digest, err := RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	return AuthenticatedRelayIntent{
		RequestDigest: digest.String(), ActorID: "gateway:agent", AuthorizationID: "authorization:relay",
		ProofID: "proof:relay", VerifierNonce: "nonce:relay", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
	}
}

func assertNoPrivateHumanData(t *testing.T, value any, humanID string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(raw)
	for _, forbidden := range []string{humanID, "human_participant_id", "consent_id", "candidate_id", "approval_actor", "mailto:", "tel:"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("serialized value leaked %q: %s", forbidden, serialized)
		}
	}
}

type failingDispatcher struct{}

func (*failingDispatcher) Dispatch(context.Context, DispatchRequest) (ProviderAck, error) {
	return ProviderAck{}, errors.New("gateway unavailable for private-recipient@example.test")
}

type staticDispatcher struct {
	ack ProviderAck
}

func (d staticDispatcher) Dispatch(context.Context, DispatchRequest) (ProviderAck, error) {
	return d.ack, nil
}

func TestRejectsTypedNilDependencies(t *testing.T) {
	t.Parallel()
	var store *MemoryStore
	if _, err := NewService(store, nil); !errors.Is(err, ErrMissingStore) {
		t.Fatalf("NewService() error = %v, want %v", err, ErrMissingStore)
	}
	var dispatcher *failingDispatcher
	if _, err := NewWorker(store, dispatcher); !errors.Is(err, ErrMissingStore) {
		t.Fatalf("NewWorker() store error = %v, want %v", err, ErrMissingStore)
	}
	fixture := newRelayFixture(t)
	if _, err := NewWorker(fixture.store, dispatcher); !errors.Is(err, ErrMissingDispatcher) {
		t.Fatalf("NewWorker() dispatcher error = %v, want %v", err, ErrMissingDispatcher)
	}
	var directory *taskcoord.MemoryReachabilityDirectory
	if _, err := NewMemoryStore(directory); !errors.Is(err, ErrMissingDirectory) {
		t.Fatalf("NewMemoryStore() error = %v, want %v", err, ErrMissingDirectory)
	}
	if _, err := fixture.store.CommitAuthorizedDispatch(
		context.Background(), fixture.request.IntentID, dispatcher, time.Now,
	); !errors.Is(err, ErrMissingDispatcher) {
		t.Fatalf("CommitAuthorizedDispatch() error = %v, want %v", err, ErrMissingDispatcher)
	}
}

type blockingGrantTransaction struct {
	inner   GrantTransaction
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingGrantTransaction) CommitWithActiveHumanReachabilityGrantForDispatch(
	ctx context.Context,
	access taskcoord.HumanReachabilityDispatchAccess,
	dispatch func(taskcoord.HumanReachabilityGrant) error,
) error {
	return b.inner.CommitWithActiveHumanReachabilityGrantForDispatch(ctx, access, dispatch)
}

func (b *blockingGrantTransaction) CommitWithActiveHumanReachabilityGrant(
	ctx context.Context,
	access taskcoord.AuthenticatedReachabilityAccess,
	commit func(taskcoord.HumanReachabilityGrant) error,
) error {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.release:
	}
	return b.inner.CommitWithActiveHumanReachabilityGrant(ctx, access, commit)
}
