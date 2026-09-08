// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestDispatchCancelsWithoutProviderCallAfterReachabilityWithdrawal(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		revoke func(*relayFixture) error
	}{
		{
			name: "grant revoked",
			revoke: func(f *relayFixture) error {
				return revokeRelayGrantForDispatchTest(f, "revoke:dispatch-before-call")
			},
		},
		{
			name: "consent revoked",
			revoke: func(f *relayFixture) error {
				return f.directory.RevokeHumanMatchConsent(context.Background(), taskcoord.HumanMatchConsentRevocation{
					Schema:             taskcoord.HumanMatchConsentRevocationSchemaV1,
					EventID:            "revoke-consent:dispatch-before-call",
					ConsentID:          f.consentID,
					HumanParticipantID: f.humanID,
					ActorID:            "gateway:human",
					AuthorizationID:    "authorization:dispatch-before-call",
					ProofID:            "proof:dispatch-before-call",
					At:                 f.now.Add(time.Second),
				})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRelayFixture(t)
			queueRelayForDispatchTest(t, fixture)
			if err := test.revoke(fixture); err != nil {
				t.Fatal(err)
			}

			dispatcher := &countingRelayDispatcher{}
			worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time {
				return fixture.now.Add(2 * time.Second)
			})
			if err != nil {
				t.Fatal(err)
			}
			canceled, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
			if err != nil {
				t.Fatalf("Dispatch() error = %v", err)
			}
			if canceled.Status != StatusCanceled {
				t.Fatalf("Dispatch() status = %s, want CANCELED", canceled.Status)
			}
			if dispatcher.calls.Load() != 0 {
				t.Fatalf("provider calls = %d, want 0", dispatcher.calls.Load())
			}
			assertDispatchEventStatuses(t, fixture.store, fixture.request.IntentID, StatusQueued, StatusCanceled)

			// A canceled record is terminal. Retrying cannot recreate the
			// reachability decision or call the provider.
			retry, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
			if err != nil || retry != canceled {
				t.Fatalf("canceled retry = %+v, error = %v, want %+v", retry, err, canceled)
			}
			if dispatcher.calls.Load() != 0 {
				t.Fatalf("provider calls after canceled retry = %d, want 0", dispatcher.calls.Load())
			}
		})
	}
}

func TestDispatchRevocationWinsBeforeAuthorizationGate(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	transaction := &dispatchEntryGate{
		inner:   fixture.directory,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	releaseOnce := sync.Once{}
	defer releaseOnce.Do(func() { close(transaction.release) })
	store, err := NewMemoryStore(transaction)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Queue(context.Background(), fixture.request, fixture.auth); err != nil {
		t.Fatal(err)
	}
	dispatcher := &countingRelayDispatcher{}
	worker, err := NewWorkerWithClock(store, dispatcher, func() time.Time {
		return fixture.now.Add(2 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan dispatchResult, 1)
	go func() {
		receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
		result <- dispatchResult{receipt: receipt, err: err}
	}()
	<-transaction.entered
	if err := revokeRelayGrantForDispatchTest(fixture, "revoke:dispatch-gate-wins"); err != nil {
		t.Fatal(err)
	}
	releaseOnce.Do(func() { close(transaction.release) })
	got := <-result
	if got.err != nil || got.receipt.Status != StatusCanceled {
		t.Fatalf("Dispatch() receipt = %+v, error = %v, want CANCELED", got.receipt, got.err)
	}
	if dispatcher.calls.Load() != 0 {
		t.Fatalf("provider calls = %d, want 0", dispatcher.calls.Load())
	}
	assertDispatchEventStatuses(t, store, fixture.request.IntentID, StatusQueued, StatusCanceled)
}

func TestDispatchGateBlocksRevocationThroughProviderAcknowledgement(t *testing.T) {
	fixture := newRelayFixture(t)
	queueRelayForDispatchTest(t, fixture)
	releaseOnce := sync.Once{}
	dispatcher := &countingRelayDispatcher{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	defer releaseOnce.Do(func() { close(dispatcher.release) })
	worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time {
		return fixture.now.Add(2 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}

	dispatched := make(chan dispatchResult, 1)
	go func() {
		receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
		dispatched <- dispatchResult{receipt: receipt, err: err}
	}()
	<-dispatcher.entered

	revocationStarted := make(chan struct{})
	revoked := make(chan error, 1)
	go func() {
		close(revocationStarted)
		revoked <- revokeRelayGrantForDispatchTest(fixture, "revoke:dispatch-after-call-start")
	}()
	<-revocationStarted
	select {
	case err := <-revoked:
		t.Fatalf("revocation completed while provider callback was blocked: %v", err)
	case <-time.After(50 * time.Millisecond):
		// The provider callback is inside the grant-scoped serialization
		// boundary, so revocation cannot commit yet.
	}

	releaseOnce.Do(func() { close(dispatcher.release) })
	result := <-dispatched
	if result.err != nil || result.receipt.Status != StatusProviderAcknowledged {
		t.Fatalf("Dispatch() receipt = %+v, error = %v", result.receipt, result.err)
	}
	if err := <-revoked; err != nil {
		t.Fatalf("revocation after dispatch completion error = %v", err)
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", dispatcher.calls.Load())
	}
	assertDispatchEventStatuses(
		t,
		fixture.store,
		fixture.request.IntentID,
		StatusQueued,
		StatusDispatching,
		StatusProviderAcknowledged,
	)
}

func TestConcurrentDispatchWorkersCallProviderExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	queueRelayForDispatchTest(t, fixture)
	dispatcher := &countingRelayDispatcher{}
	worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time {
		return fixture.now.Add(2 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 24
	results := make(chan dispatchResult, workers)
	var group sync.WaitGroup
	for index := 0; index < workers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
			results <- dispatchResult{receipt: receipt, err: err}
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.receipt.Status != StatusProviderAcknowledged {
			t.Errorf("concurrent Dispatch() receipt = %+v, error = %v", result.receipt, result.err)
		}
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", dispatcher.calls.Load())
	}
	assertDispatchEventStatuses(
		t,
		fixture.store,
		fixture.request.IntentID,
		StatusQueued,
		StatusDispatching,
		StatusProviderAcknowledged,
	)
}

func TestProviderFailureLeavesUnknownDispatchTerminal(t *testing.T) {
	t.Parallel()
	fixture := newRelayFixture(t)
	queueRelayForDispatchTest(t, fixture)
	dispatcher := &countingRelayDispatcher{
		err: errors.New("gateway failed for private-recipient@example.test"),
	}
	worker, err := NewWorkerWithClock(fixture.store, dispatcher, func() time.Time {
		return fixture.now.Add(2 * time.Second)
	})
	if err != nil {
		t.Fatal(err)
	}

	receipt, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
	if !errors.Is(err, ErrDispatchUnavailable) || strings.Contains(err.Error(), "private-recipient") {
		t.Fatalf("Dispatch() receipt = %+v, error = %v", receipt, err)
	}
	if receipt.Status != StatusDispatching {
		t.Fatalf("Dispatch() status = %s, want DISPATCHING", receipt.Status)
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want 1", dispatcher.calls.Load())
	}
	assertDispatchEventStatuses(t, fixture.store, fixture.request.IntentID, StatusQueued, StatusDispatching)

	if err := revokeRelayGrantForDispatchTest(fixture, "revoke:dispatch-after-provider-error"); err != nil {
		t.Fatal(err)
	}
	retry, err := worker.Dispatch(context.Background(), fixture.request.IntentID)
	if err != nil || retry != receipt {
		t.Fatalf("DISPATCHING retry = %+v, error = %v, want %+v", retry, err, receipt)
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("provider calls after retry = %d, want 1", dispatcher.calls.Load())
	}
	assertDispatchEventStatuses(t, fixture.store, fixture.request.IntentID, StatusQueued, StatusDispatching)
}

type dispatchResult struct {
	receipt Receipt
	err     error
}

type countingRelayDispatcher struct {
	calls   atomic.Int32
	err     error
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *countingRelayDispatcher) Dispatch(ctx context.Context, request DispatchRequest) (ProviderAck, error) {
	d.calls.Add(1)
	if d.entered != nil {
		d.once.Do(func() { close(d.entered) })
	}
	if d.release != nil {
		select {
		case <-ctx.Done():
			return ProviderAck{}, ctx.Err()
		case <-d.release:
		}
	}
	if d.err != nil {
		return ProviderAck{}, d.err
	}
	return ProviderAck{IntentID: request.IntentID, AckRef: "provider-ack:dispatch-gate"}, nil
}

type dispatchEntryGate struct {
	inner   GrantTransaction
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *dispatchEntryGate) CommitWithActiveHumanReachabilityGrant(
	ctx context.Context,
	access taskcoord.AuthenticatedReachabilityAccess,
	commit func(taskcoord.HumanReachabilityGrant) error,
) error {
	return g.inner.CommitWithActiveHumanReachabilityGrant(ctx, access, commit)
}

func (g *dispatchEntryGate) CommitWithActiveHumanReachabilityGrantForDispatch(
	ctx context.Context,
	access taskcoord.HumanReachabilityDispatchAccess,
	dispatch func(taskcoord.HumanReachabilityGrant) error,
) error {
	g.once.Do(func() { close(g.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.release:
	}
	return g.inner.CommitWithActiveHumanReachabilityGrantForDispatch(ctx, access, dispatch)
}

func queueRelayForDispatchTest(t *testing.T, fixture *relayFixture) Receipt {
	t.Helper()
	receipt, err := fixture.service.Queue(context.Background(), fixture.request, fixture.auth)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != StatusQueued {
		t.Fatalf("Queue() status = %s, want QUEUED", receipt.Status)
	}
	return receipt
}

func revokeRelayGrantForDispatchTest(fixture *relayFixture, eventID string) error {
	return fixture.directory.RevokeHumanReachabilityGrant(context.Background(), taskcoord.HumanReachabilityRevocation{
		Schema:          taskcoord.HumanReachabilityRevocationSchemaV1,
		EventID:         eventID,
		GrantID:         fixture.grant.GrantID,
		ParticipantID:   fixture.humanID,
		ActorID:         "gateway:human",
		AuthorizationID: "authorization:" + eventID,
		ProofID:         "proof:" + eventID,
		At:              fixture.now.Add(time.Second),
	})
}

func assertDispatchEventStatuses(t *testing.T, store *MemoryStore, intentID string, want ...Status) {
	t.Helper()
	events, err := store.Events(intentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(want) {
		t.Fatalf("event count = %d, want %d: %+v", len(events), len(want), events)
	}
	for index, status := range want {
		if events[index].Status != status {
			t.Fatalf("event[%d].Status = %s, want %s: %+v", index, events[index].Status, status, events)
		}
	}
}
