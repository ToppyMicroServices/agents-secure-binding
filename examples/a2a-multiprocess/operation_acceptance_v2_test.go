// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/operationjournal"
)

func TestApplicationOperationV2ExcludesAuthenticationAttemptData(t *testing.T) {
	request := newTaskRequestV2()
	request.Message.MessageID = "stable-message-id"
	contexts, err := canonicalRequestContextsV2(request)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := applicationOperationV2(request, contexts)
	if err != nil {
		t.Fatal(err)
	}

	authChanged := request
	authChanged.Message.Metadata = map[string]json.RawMessage{
		securityBindingExtensionV2:   json.RawMessage(`{"verifier_nonce":"another-nonce","session_binding":"another-proof"}`),
		attestationResultExtensionV2: json.RawMessage(`"another-attestation-result"`),
	}
	authContexts, err := canonicalRequestContextsV2(authChanged)
	if err != nil {
		t.Fatal(err)
	}
	authReservation, err := applicationOperationV2(authChanged, authContexts)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(authReservation, baseline) {
		t.Fatalf("authentication-only change produced %+v, want stable %+v", authReservation, baseline)
	}

	contentChanged := request
	contentChanged.Message.Parts = append([]a2aPart(nil), request.Message.Parts...)
	contentChanged.Message.Parts[0].Text = "A different application request"
	contentContexts, err := canonicalRequestContextsV2(contentChanged)
	if err != nil {
		t.Fatal(err)
	}
	contentReservation, err := applicationOperationV2(contentChanged, contentContexts)
	if err != nil {
		t.Fatal(err)
	}
	if contentReservation.OperationID != baseline.OperationID || contentReservation.RequestDigest == baseline.RequestDigest {
		t.Fatalf("content change produced %+v, want same ID and different digest from %+v", contentReservation, baseline)
	}

	identityChanged := request
	identityChanged.Message.MessageID = "different-message-id"
	identityContexts, err := canonicalRequestContextsV2(identityChanged)
	if err != nil {
		t.Fatal(err)
	}
	identityReservation, err := applicationOperationV2(identityChanged, identityContexts)
	if err != nil {
		t.Fatal(err)
	}
	if identityReservation.OperationID == baseline.OperationID {
		t.Fatal("message identity change did not change operation ID")
	}

	contextChanged := request
	contextChanged.Message.ContextID = "different-context-id"
	contextContexts, err := canonicalRequestContextsV2(contextChanged)
	if err != nil {
		t.Fatal(err)
	}
	contextReservation, err := applicationOperationV2(contextChanged, contextContexts)
	if err != nil {
		t.Fatal(err)
	}
	if contextReservation.OperationID == baseline.OperationID {
		t.Fatal("context identity change did not change operation ID")
	}
}

func TestOperationSessionV2ExecutesAtMostOnceAcrossFreshAuthentication(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("1", 64), RequestDigest: "sha256:" + strings.Repeat("2", 64),
	}
	now := time.Now().UTC()
	first := newOperationSessionV2(context.Background(), client, reservation)
	if err := first.MarkUsed(testReplayKeyV2("first"), now.Add(time.Minute)); err != nil {
		t.Fatalf("first MarkUsed() error = %v", err)
	}
	// A fresh verifier nonce can authenticate an exact application retry. It
	// observes the same operation reservation, not permission to run twice.
	retry := newOperationSessionV2(context.Background(), client, reservation)
	if err := retry.MarkUsed(testReplayKeyV2("retry"), now.Add(time.Minute)); err != nil {
		t.Fatalf("retry MarkUsed() error = %v", err)
	}

	var calls atomic.Int32
	acceptedUntil := now.Add(time.Minute)
	clock := func() time.Time { return now }
	want := testOperationResultV2(t, "model response")
	got, err := first.executeOnce(context.Background(), acceptedUntil, clock, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return want, nil
	})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("first executeOnce() = (%+v, %v)", got, err)
	}
	recovered, err := retry.executeOnce(context.Background(), acceptedUntil, clock, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return testOperationResultV2(t, "duplicate response"), nil
	})
	if err != nil || !reflect.DeepEqual(recovered, want) {
		t.Fatalf("retry executeOnce() = (%+v, %v), want recovered exact response", recovered, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", calls.Load())
	}
	record, err := store.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || record.State != operationjournal.StateSucceeded || record.OutcomeDigest != operationOutcomeDigestV2(want) {
		t.Fatalf("durable result = (%+v, %v)", record, err)
	}
}

func TestOperationSessionV2RecoversLostCompletionResponseWithoutReexecution(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	baseTransport := client.client.Transport
	var responseLost atomic.Bool
	client.client.Transport = roundTripperFuncV2(func(request *http.Request) (*http.Response, error) {
		response, err := baseTransport.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		if request.URL.Path == operationCompletePathV2 && responseLost.CompareAndSwap(false, true) {
			_ = response.Body.Close()
			return nil, errors.New("injected lost completion response")
		}
		return response, nil
	})
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("f", 64), RequestDigest: "sha256:" + strings.Repeat("1", 64),
	}
	now := time.Now().UTC()
	first := newOperationSessionV2(context.Background(), client, reservation)
	if err := first.MarkUsed(testReplayKeyV2("lost-response-first"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	want := testOperationResultV2(t, "persist this exact response")
	var calls atomic.Int32
	_, err := first.executeOnce(context.Background(), now.Add(time.Minute), func() time.Time { return now }, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return want, nil
	})
	if !errors.Is(err, operationjournal.ErrUnavailable) {
		t.Fatalf("first executeOnce() error = %v, want lost completion response", err)
	}
	record, sealed, err := store.LookupResult(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || record.State != operationjournal.StateSucceeded || sealed.OutcomeDigest != record.OutcomeDigest {
		t.Fatalf("atomic result after lost response = (%+v, %+v, %v)", record, sealed, err)
	}

	retry := newOperationSessionV2(context.Background(), client, reservation)
	if err := retry.MarkUsed(testReplayKeyV2("lost-response-retry"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	recovered, err := retry.executeOnce(context.Background(), now.Add(time.Minute), func() time.Time { return now }, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return testOperationResultV2(t, "must not execute"), nil
	})
	if err != nil || !reflect.DeepEqual(recovered, want) {
		t.Fatalf("retry executeOnce() = (%+v, %v), want exact stored response", recovered, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", calls.Load())
	}
}

func TestOperationSessionV2MarksExecutionFailureIndeterminate(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("3", 64), RequestDigest: "sha256:" + strings.Repeat("4", 64),
	}
	now := time.Now().UTC()
	first := newOperationSessionV2(context.Background(), client, reservation)
	if err := first.MarkUsed(testReplayKeyV2("indeterminate-first"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	acceptedUntil := now.Add(time.Minute)
	clock := func() time.Time { return now }
	_, err := first.executeOnce(context.Background(), acceptedUntil, clock, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return operationResultV2{}, errors.New("provider response was lost")
	})
	var executionErr *operationExecutionV2Error
	if !errors.As(err, &executionErr) {
		t.Fatalf("executeOnce() error = %v, want operationExecutionV2Error", err)
	}

	retry := newOperationSessionV2(context.Background(), client, reservation)
	if err := retry.MarkUsed(testReplayKeyV2("indeterminate-retry"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err = retry.executeOnce(context.Background(), acceptedUntil, clock, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return testOperationResultV2(t, "must not run"), nil
	})
	var stateErr *operationStateV2Error
	if !errors.As(err, &stateErr) || stateErr.Record.State != operationjournal.StateIndeterminate {
		t.Fatalf("retry executeOnce() error = %v, want INDETERMINATE state", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", calls.Load())
	}
}

func TestOperationSessionV2DoesNotStartAfterAcceptanceExpiry(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("b", 64), RequestDigest: "sha256:" + strings.Repeat("c", 64),
	}
	now := time.Now().UTC()
	session := newOperationSessionV2(context.Background(), client, reservation)
	if err := session.MarkUsed(testReplayKeyV2("expired-before-start"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	_, err := session.executeOnce(context.Background(), now, func() time.Time { return now }, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return testOperationResultV2(t, "must not run"), nil
	})
	if !errors.Is(err, errOperationAcceptanceExpiredV2) {
		t.Fatalf("executeOnce() error = %v, want %v", err, errOperationAcceptanceExpiredV2)
	}
	if calls.Load() != 0 {
		t.Fatalf("executor calls = %d, want 0", calls.Load())
	}
	record, err := store.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || record.State != operationjournal.StateAccepted {
		t.Fatalf("expired operation record = (%+v, %v), want ACCEPTED", record, err)
	}
}

func TestOperationSessionV2CancelsWhenAcceptanceExpiresDuringStart(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("d", 64), RequestDigest: "sha256:" + strings.Repeat("e", 64),
	}
	now := time.Now().UTC()
	acceptedUntil := now.Add(time.Second)
	session := newOperationSessionV2(context.Background(), client, reservation)
	if err := session.MarkUsed(testReplayKeyV2("expires-during-start"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return now
		}
		return acceptedUntil
	}
	var calls atomic.Int32
	_, err := session.executeOnce(context.Background(), acceptedUntil, clock, func(context.Context) (operationResultV2, error) {
		calls.Add(1)
		return testOperationResultV2(t, "must not run"), nil
	})
	if !errors.Is(err, errOperationAcceptanceExpiredV2) {
		t.Fatalf("executeOnce() error = %v, want %v", err, errOperationAcceptanceExpiredV2)
	}
	if calls.Load() != 0 {
		t.Fatalf("executor calls = %d, want 0", calls.Load())
	}
	record, err := store.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest)
	if err != nil || record.State != operationjournal.StateCanceled {
		t.Fatalf("expired operation record = (%+v, %v), want CANCELED", record, err)
	}
}

func TestOperationSessionV2AcceptanceFailureDoesNotBlockRetry(t *testing.T) {
	base := openOperationAcceptanceTestStore(t)
	store := &failFirstAcceptanceStore{ResultStore: base}
	client := newOperationAcceptanceTestClient(t, store)
	reservation := operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("5", 64), RequestDigest: "sha256:" + strings.Repeat("6", 64),
	}
	session := newOperationSessionV2(context.Background(), client, reservation)
	replayKey := testReplayKeyV2("retry-after-failure")
	retainUntil := time.Now().UTC().Add(time.Minute)
	if err := session.MarkUsed(replayKey, retainUntil); !errors.Is(err, operationjournal.ErrUnavailable) {
		t.Fatalf("first MarkUsed() error = %v, want %v", err, operationjournal.ErrUnavailable)
	}
	if _, err := base.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest); !errors.Is(err, operationjournal.ErrNotFound) {
		t.Fatalf("Lookup() after failed acceptance = %v, want %v", err, operationjournal.ErrNotFound)
	}
	if err := session.MarkUsed(replayKey, retainUntil); err != nil {
		t.Fatalf("retry MarkUsed() error = %v", err)
	}
	if _, err := base.Lookup(context.Background(), reservation.OperationID, reservation.RequestDigest); err != nil {
		t.Fatalf("Lookup() after retry error = %v", err)
	}
}

func TestOperationSessionV2MapsAtomicReplayRejection(t *testing.T) {
	store := openOperationAcceptanceTestStore(t)
	client := newOperationAcceptanceTestClient(t, store)
	now := time.Now().UTC()
	replayKey := testReplayKeyV2("same-nonce")
	first := newOperationSessionV2(context.Background(), client, operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("7", 64), RequestDigest: "sha256:" + strings.Repeat("8", 64),
	})
	if err := first.MarkUsed(replayKey, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second := newOperationSessionV2(context.Background(), client, operationjournal.Reservation{
		OperationID: "a2a-v2:" + strings.Repeat("9", 64), RequestDigest: "sha256:" + strings.Repeat("a", 64),
	})
	if err := second.MarkUsed(replayKey, now.Add(time.Minute)); !errors.Is(err, identitypolicy.ErrReplayDetected) {
		t.Fatalf("replayed MarkUsed() error = %v, want %v", err, identitypolicy.ErrReplayDetected)
	}
}

type failFirstAcceptanceStore struct {
	operationjournal.ResultStore
	failed atomic.Bool
}

func (s *failFirstAcceptanceStore) ReserveAcceptance(ctx context.Context, request operationjournal.AcceptanceReservation) (operationjournal.Record, bool, error) {
	if s.failed.CompareAndSwap(false, true) {
		return operationjournal.Record{}, false, operationjournal.ErrUnavailable
	}
	return s.ResultStore.ReserveAcceptance(ctx, request)
}

func openOperationAcceptanceTestStore(t *testing.T) *operationjournal.FileStore {
	t.Helper()
	store, err := operationjournal.OpenFileStore(filepath.Join(t.TempDir(), "acceptance.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func newOperationAcceptanceTestClient(t *testing.T, store operationjournal.ResultStore) *httpOperationJournalClientV2 {
	t.Helper()
	mux := http.NewServeMux()
	registerOperationJournalV2(mux, store)
	client := &http.Client{Transport: roundTripperFuncV2(func(r *http.Request) (*http.Response, error) {
		request := r.Clone(r.Context())
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: demoAudience}}}}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}
	sealer, err := newResultSealerV2(bytes.Repeat([]byte{0x42}, resultSealingKeyBytesV2), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &httpOperationJournalClientV2{client: client, url: "https://operation-store.test", sealer: sealer}
}

type roundTripperFuncV2 func(*http.Request) (*http.Response, error)

func (f roundTripperFuncV2) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testReplayKeyV2(value string) string {
	return "sbaip-replay-v2:" + strings.TrimPrefix(sha256String([]byte(value)), "sha256:")
}

func testOperationResultV2(t *testing.T, text string) operationResultV2 {
	t.Helper()
	result, err := completedOperationResultV2(newTaskRequestV2(), text, time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return result
}
