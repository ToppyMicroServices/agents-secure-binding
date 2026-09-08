// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestMemoryStoreRejectsSecondActionForAssignmentWithoutPartialWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	acceptedAt := base.Add(2 * time.Second)
	assignment := acceptedAssignment(t, "assignment:cardinality", "task:cardinality", "agent:owner", base)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment},
		nil,
		func() time.Time { return acceptedAt },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return acceptedAt })
	if err != nil {
		t.Fatal(err)
	}

	first := cardinalityAcceptRequest(t, assignment, acceptedAt, "first", '1')
	second := cardinalityAcceptRequest(t, assignment, acceptedAt, "second", '2')
	firstView, err := service.Accept(ctx, first)
	if err != nil {
		t.Fatalf("first Accept() error = %v", err)
	}
	if _, err := service.Accept(ctx, second); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Accept() error = %v, want ErrAlreadyExists", err)
	}

	if _, err := store.Load(ctx, second.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing Action was partially stored: %v", err)
	}
	if _, err := store.LoadBinding(ctx, second.ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing Binding was partially stored: %v", err)
	}
	if retry, err := service.Accept(ctx, first); err != nil {
		t.Fatalf("exact same-Action retry error = %v", err)
	} else if !sameJSON(retry, firstView) {
		t.Fatalf("exact same-Action retry view changed: got %+v, want %+v", retry, firstView)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	if got := store.actionByAssignment[assignment.AssignmentID]; got != first.ActionID {
		t.Fatalf("Assignment index = %q, want %q", got, first.ActionID)
	}
	if len(store.actions) != 1 || len(store.bindings) != 1 || len(store.events) != 1 {
		t.Fatalf(
			"stored records after rejected Action = actions:%d bindings:%d events:%d",
			len(store.actions),
			len(store.bindings),
			len(store.events),
		)
	}
}

func TestMemoryStoreConcurrentBindingHasOneWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 13, 30, 0, 0, time.UTC)
	acceptedAt := base.Add(2 * time.Second)
	assignment := acceptedAssignment(t, "assignment:cardinality-race", "task:cardinality-race", "agent:owner", base)
	store, err := NewMemoryStoreWithClock(
		[]taskcoord.Assignment{assignment},
		nil,
		func() time.Time { return acceptedAt },
	)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, func() time.Time { return acceptedAt })
	if err != nil {
		t.Fatal(err)
	}
	requests := []AcceptRequest{
		cardinalityAcceptRequest(t, assignment, acceptedAt, "race-a", 'a'),
		cardinalityAcceptRequest(t, assignment, acceptedAt, "race-b", 'b'),
	}

	type result struct {
		index int
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, len(requests))
	var workers sync.WaitGroup
	for index := range requests {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := service.Accept(ctx, requests[index])
			results <- result{index: index, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	winner := -1
	loser := -1
	for result := range results {
		switch {
		case result.err == nil:
			if winner != -1 {
				t.Fatalf("multiple concurrent winners: %d and %d", winner, result.index)
			}
			winner = result.index
		case errors.Is(result.err, ErrAlreadyExists):
			if loser != -1 {
				t.Fatalf("multiple concurrent losers: %d and %d", loser, result.index)
			}
			loser = result.index
		default:
			t.Fatalf("Accept(%d) error = %v, want nil or ErrAlreadyExists", result.index, result.err)
		}
	}
	if winner == -1 || loser == -1 {
		t.Fatalf("concurrent result winner=%d loser=%d", winner, loser)
	}
	if _, err := store.Load(ctx, requests[loser].ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing Action was partially stored: %v", err)
	}
	if _, err := store.LoadBinding(ctx, requests[loser].ActionID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing Binding was partially stored: %v", err)
	}
	if _, err := store.Load(ctx, requests[winner].ActionID); err != nil {
		t.Fatalf("winning Action was not stored: %v", err)
	}
	if _, err := store.LoadBinding(ctx, requests[winner].ActionID); err != nil {
		t.Fatalf("winning Binding was not stored: %v", err)
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	if got := store.actionByAssignment[assignment.AssignmentID]; got != requests[winner].ActionID {
		t.Fatalf("Assignment index = %q, want winner %q", got, requests[winner].ActionID)
	}
	if len(store.actions) != 1 || len(store.bindings) != 1 || len(store.events) != 1 {
		t.Fatalf(
			"concurrent records = actions:%d bindings:%d events:%d, want one each",
			len(store.actions),
			len(store.bindings),
			len(store.events),
		)
	}
}

func TestMemoryStoreConcurrentExactAcceptanceRetriesShareCanonicalView(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)
	assignment := acceptedAssignment(t, "assignment:exact-race", "task:exact-race", "agent:owner", base)
	var clockMu sync.Mutex
	clockCalls := 0
	transactionClock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clockCalls++
		return base.Add(time.Duration(clockCalls) * time.Second)
	}
	store, err := NewMemoryStoreWithClock([]taskcoord.Assignment{assignment}, nil, transactionClock)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, transactionClock)
	if err != nil {
		t.Fatal(err)
	}
	request := cardinalityAcceptRequest(t, assignment, base.Add(time.Second), "exact-race", '7')

	type result struct {
		view View
		err  error
	}
	const workerCount = 16
	start := make(chan struct{})
	results := make(chan result, workerCount)
	var workers sync.WaitGroup
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			view, err := service.Accept(ctx, request)
			results <- result{view: view, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var canonical *View
	for result := range results {
		if result.err != nil {
			t.Fatalf("exact concurrent retry error = %v", result.err)
		}
		if canonical == nil {
			view := result.view
			canonical = &view
			continue
		}
		if !sameJSON(result.view, *canonical) {
			t.Fatalf("concurrent retry returned a different View: %+v, want %+v", result.view, *canonical)
		}
	}
	clockMu.Lock()
	gotClockCalls := clockCalls
	clockMu.Unlock()
	if gotClockCalls != 1 {
		t.Fatalf("transaction clock calls = %d, want 1 first-commit timestamp", gotClockCalls)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if len(store.actions) != 1 || len(store.bindings) != 1 || len(store.events) != 1 {
		t.Fatalf(
			"exact retry records = actions:%d bindings:%d events:%d, want one each",
			len(store.actions), len(store.bindings), len(store.events),
		)
	}
}

func cardinalityAcceptRequest(
	t *testing.T,
	assignment taskcoord.Assignment,
	at time.Time,
	suffix string,
	digestRune rune,
) AcceptRequest {
	t.Helper()
	request := AcceptRequest{
		AssignmentID: assignment.AssignmentID,
		EventID:      "event:accept:cardinality:" + suffix,
		ActionID:     "action:cardinality:" + suffix,
		ActionDigest: "sha256:" + strings.Repeat(string(digestRune), 64),
		RecoveryPolicy: actionlifecycle.RecoveryPolicy{
			Mode:           actionlifecycle.RecoveryRestartIdempotent,
			MaxAttempts:    2,
			IdempotencyKey: "idempotency:cardinality:" + suffix,
		},
	}
	bindTestAcceptance(t, assignment, at, &request)
	return request
}
