// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/operationjournal"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	testAccount      = "0123456789abcdef0123456789abcdef"
	testToken        = "test-cloudflare-token"
	testSender       = "notify@example.com"
	testRecipient    = "human@example.net"
	testSession      = "https://gateway.example/relay/session-1"
	testContent      = "https://content.example/notification/1"
	testSessionField = "session"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type closeTrackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func testConfig(t *testing.T) (Config, humanrelay.DispatchRequest, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.json")
	journal, err := operationjournal.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	message := Message{Subject: "ASB review requested", Text: "Open ASB to review the pending request."}
	digest, err := MessageDigest(message)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		AccountID:   testAccount,
		APIToken:    testToken,
		Sender:      testSender,
		Routes:      map[string]string{testSession: testRecipient},
		Messages:    map[string]Message{testContent: message},
		Journal:     journal,
		Timeout:     time.Second,
		MaxInFlight: 8,
	}, humanrelay.DispatchRequest{
		IntentID:        "intent:cloudflare:1",
		RelaySessionRef: testSession,
		Channel:         taskcoord.ReachabilityEmail,
		ContentRef:      testContent,
		ContentDigest:   digest,
	}, path
}

func newTestDispatcher(t *testing.T, cfg Config, transport http.RoundTripper) *Dispatcher {
	t.Helper()
	dispatcher, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.client.Transport = transport
	t.Cleanup(dispatcher.Close)
	return dispatcher
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func acceptedResponse() *http.Response {
	return response(http.StatusOK, `{"success":true,"errors":[],"messages":[],"result":{"delivered":[],"queued":["human@example.net"],"permanent_bounces":[],"suppressed_recipients":[],"message_id":"provider-private-id"}}`)
}

func awaitProviderCall(t *testing.T, entered <-chan struct{}, result <-chan error) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-entered:
	case err := <-result:
		t.Fatalf("dispatch returned before reaching provider: %v", err)
	case <-timer.C:
		t.Fatal("dispatch did not reach provider within the test deadline")
	}
}

func assertPrivateValuesAbsent(t *testing.T, value string) {
	t.Helper()
	for _, private := range []string{testToken, testSender, testRecipient, testSession, testContent, "provider-private-id", "Open ASB to review"} {
		if strings.Contains(value, private) {
			t.Errorf("private value appeared in outward evidence: %q", private)
		}
	}
}

func TestDispatchUsesPinnedAPIAndPersistsOpaqueAcknowledgement(t *testing.T) {
	cfg, request, path := testConfig(t)
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(wire *http.Request) (*http.Response, error) {
		calls.Add(1)
		if wire.Method != http.MethodPost || wire.URL.String() != "https://api.cloudflare.com/client/v4/accounts/"+testAccount+"/email/sending/send" {
			t.Errorf("unexpected request target: %s %s", wire.Method, wire.URL)
		}
		if wire.Header.Get("Authorization") != "Bearer "+testToken || wire.Header.Get("Content-Type") != "application/json" {
			t.Error("missing expected authentication or content type")
		}
		var payload map[string]json.RawMessage
		if err := json.NewDecoder(wire.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload) != 4 {
			t.Errorf("unexpected email fields: %v", payload)
		}
		for field, want := range map[string]string{"from": testSender, "subject": cfg.Messages[testContent].Subject, "text": cfg.Messages[testContent].Text} {
			var got string
			if err := json.Unmarshal(payload[field], &got); err != nil || got != want {
				t.Errorf("unexpected %s value", field)
			}
		}
		var to string
		if err := json.Unmarshal(payload["to"], &to); err != nil {
			var addresses []string
			if err := json.Unmarshal(payload["to"], &addresses); err != nil || len(addresses) != 1 || addresses[0] != testRecipient {
				t.Error("recipient does not match the private route")
			}
		} else if to != testRecipient {
			t.Error("recipient does not match the private route")
		}
		return acceptedResponse(), nil
	}))
	ack, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil || ack.IntentID != request.IntentID || ack.AckRef == "" {
		t.Fatalf("dispatch: ack=%+v err=%v", ack, err)
	}
	raw, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateValuesAbsent(t, string(raw))
	journal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivateValuesAbsent(t, string(journal))
	if calls.Load() != 1 {
		t.Fatalf("wire attempts = %d", calls.Load())
	}
}

func TestDuplicateDispatchAndReopenDoNotResend(t *testing.T) {
	cfg, request, path := testConfig(t)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return acceptedResponse(), nil
	})
	dispatcher := newTestDispatcher(t, cfg, transport)
	first, err := dispatcher.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := dispatcher.Dispatch(context.Background(), request)
		if err != nil || got != first {
			t.Fatalf("retry changed acknowledgement: %+v, %v", got, err)
		}
	}
	reopened, err := operationjournal.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Journal = reopened
	cfg.APIToken = "rotated-test-cloudflare-token"
	next := newTestDispatcher(t, cfg, transport)
	got, err := next.Dispatch(context.Background(), request)
	if err != nil || got != first || calls.Load() != 1 {
		t.Fatalf("reopen/credential rotation resent or changed result: %+v, %v, calls=%d", got, err, calls.Load())
	}
	lookedUp, found, err := next.Lookup(context.Background(), request)
	if err != nil || !found || lookedUp != first || calls.Load() != 1 {
		t.Fatalf("lookup did not recover exact saved acknowledgement: %+v, %t, %v", lookedUp, found, err)
	}
}

func TestConcurrentDispatchReservesOnlyOneAttempt(t *testing.T) {
	cfg, request, _ := testConfig(t)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(wire *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
			return acceptedResponse(), nil
		case <-wire.Context().Done():
			return nil, wire.Context().Err()
		}
	}))
	first := make(chan error, 1)
	go func() { _, err := dispatcher.Dispatch(context.Background(), request); first <- err }()
	awaitProviderCall(t, entered, first)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := dispatcher.Dispatch(context.Background(), request)
			if err == nil || (!errors.Is(err, ErrOutcomeUnknown) && !errors.Is(err, ErrBusy)) {
				t.Errorf("in-flight duplicate outcome = %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent wire attempts = %d", calls.Load())
	}
}

func TestBoundedConcurrencyRejectsBeforeReservingAnotherIntent(t *testing.T) {
	cfg, request, _ := testConfig(t)
	cfg.MaxInFlight = 1
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(wire *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-wire.Context().Done():
				return nil, wire.Context().Err()
			}
		}
		return acceptedResponse(), nil
	}))
	first := make(chan error, 1)
	go func() { _, err := dispatcher.Dispatch(context.Background(), request); first <- err }()
	awaitProviderCall(t, entered, first)
	other := request
	other.IntentID = "intent:cloudflare:2"
	_, err := dispatcher.Dispatch(context.Background(), other)
	close(release)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("backpressure error = %v", err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if _, err := dispatcher.Dispatch(context.Background(), other); err != nil || calls.Load() != 2 {
		t.Fatalf("busy rejection reserved or consumed unsent intent: %v, calls=%d", err, calls.Load())
	}
}

func TestUnknownAttemptSurvivesReopenWithoutResend(t *testing.T) {
	cfg, request, path := testConfig(t)
	var calls atomic.Int32
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("private transport diagnostic: " + testToken + " " + testRecipient)
	})
	dispatcher := newTestDispatcher(t, cfg, transport)
	_, err := dispatcher.Dispatch(context.Background(), request)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost response outcome = %v", err)
	}
	assertPrivateValuesAbsent(t, err.Error())
	cfg.Journal, err = operationjournal.OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	next := newTestDispatcher(t, cfg, transport)
	if _, err := next.Dispatch(context.Background(), request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("unknown retry outcome = %v", err)
	}
	if _, found, err := next.Lookup(context.Background(), request); found || (err != nil && !errors.Is(err, ErrOutcomeUnknown)) {
		t.Fatalf("unknown lookup = found:%t err:%v", found, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unknown attempt was resent %d times", calls.Load())
	}
}

func TestDispatchTimeoutIsBoundedAndDoesNotRetry(t *testing.T) {
	cfg, request, _ := testConfig(t)
	cfg.Timeout = 200 * time.Millisecond
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(wire *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-wire.Context().Done()
		return nil, wire.Context().Err()
	}))
	started := time.Now()
	_, err := dispatcher.Dispatch(context.Background(), request)
	if !errors.Is(err, ErrOutcomeUnknown) || time.Since(started) > 2*time.Second {
		t.Fatalf("timeout outcome = %v after %v", err, time.Since(started))
	}
	_, _ = dispatcher.Dispatch(context.Background(), request)
	if calls.Load() != 1 {
		t.Fatal("timeout caused another wire attempt")
	}
}

func TestCanceledContextDoesNotConsumeIntent(t *testing.T) {
	cfg, request, _ := testConfig(t)
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return acceptedResponse(), nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dispatcher.Dispatch(ctx, request); err == nil || calls.Load() != 0 {
		t.Fatalf("canceled input sent request: %v", err)
	}
	if _, err := dispatcher.Dispatch(context.Background(), request); err != nil || calls.Load() != 1 {
		t.Fatalf("canceled input consumed intent: %v", err)
	}
}

func TestRedirectNeverForwardsCredentialsOrResends(t *testing.T) {
	cfg, request, _ := testConfig(t)
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		resp := response(http.StatusTemporaryRedirect, "")
		resp.Header.Set("Location", "https://untrusted.example/collect")
		return resp, nil
	}))
	if _, err := dispatcher.Dispatch(context.Background(), request); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("redirect outcome = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("redirect was followed")
	}
}

func TestProviderResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		accept bool
	}{
		{"delivered", 200, `{"success":true,"errors":[],"result":{"delivered":["human@example.net"],"queued":[],"permanent_bounces":[]}}`, true},
		{"queued", 200, `{"success":true,"errors":[],"result":{"delivered":[],"queued":["human@example.net"],"permanent_bounces":[]}}`, true},
		{"wrong-recipient", 200, `{"success":true,"errors":[],"result":{"delivered":["other@example.net"],"queued":[],"permanent_bounces":[]}}`, false},
		{"extra-recipient", 200, `{"success":true,"errors":[],"result":{"delivered":["human@example.net","other@example.net"],"queued":[],"permanent_bounces":[]}}`, false},
		{"duplicate-recipient", 200, `{"success":true,"errors":[],"result":{"delivered":["human@example.net"],"queued":["human@example.net"],"permanent_bounces":[]}}`, false},
		{"bounce", 200, `{"success":true,"errors":[],"result":{"delivered":[],"queued":[],"permanent_bounces":["human@example.net"]}}`, false},
		{"suppressed", 200, `{"success":true,"errors":[],"result":{"delivered":[],"queued":["human@example.net"],"permanent_bounces":[],"suppressed_recipients":["human@example.net"]}}`, false},
		{"no-acceptance", 200, `{"success":true,"errors":[],"result":{"delivered":[],"queued":[],"permanent_bounces":[]}}`, false},
		{"false-success", 200, `{"success":false,"errors":[],"result":{"queued":["human@example.net"]}}`, false},
		{"provider-error", 200, `{"success":true,"errors":[{"message":"private","code":1}],"result":{"queued":["human@example.net"]}}`, false},
		{"unauthorized", 401, `{"success":false,"errors":[{"message":"private","code":1}]}`, false},
		{"throttled", 429, `{"success":false}`, false},
		{"unavailable", 503, `{"success":false}`, false},
		{"missing-result", 200, `{"success":true,"errors":[]}`, false},
		{"duplicate-key", 200, `{"success":false,"success":true,"errors":[],"result":{"queued":["human@example.net"]}}`, false},
		{"trailing-json", 200, `{"success":true,"errors":[],"result":{"queued":["human@example.net"]}}{}`, false},
		{"truncated-json", 200, `{"success":true`, false},
		{"oversized", 200, strings.Repeat(" ", (64<<10)+1) + `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, request, _ := testConfig(t)
			var calls atomic.Int32
			body := &closeTrackingBody{Reader: strings.NewReader(tc.body)}
			dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				resp := response(tc.status, "")
				resp.Body = body
				return resp, nil
			}))
			_, err := dispatcher.Dispatch(context.Background(), request)
			if tc.accept && err != nil {
				t.Fatalf("valid acceptance rejected: %v", err)
			}
			if !tc.accept && !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("invalid response outcome = %v", err)
			}
			if !body.closed.Load() {
				t.Error("response body was not closed")
			}
			_, _ = dispatcher.Dispatch(context.Background(), request)
			if calls.Load() != 1 {
				t.Fatal("duplicate provider call after response")
			}
		})
	}
}

func TestChangedRequestOrRoutingCannotReuseIntent(t *testing.T) {
	for _, change := range []string{testSessionField, "content-ref", "message", "recipient", "sender", "account"} {
		t.Run(change, func(t *testing.T) {
			cfg, request, _ := testConfig(t)
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return acceptedResponse(), nil
			})
			dispatcher := newTestDispatcher(t, cfg, transport)
			if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			switch change {
			case testSessionField:
				request.RelaySessionRef = "https://gateway.example/relay/session-2"
				cfg.Routes[request.RelaySessionRef] = testRecipient
			case "content-ref":
				request.ContentRef = "https://content.example/notification/2"
				cfg.Messages[request.ContentRef] = cfg.Messages[testContent]
			case "message":
				cfg.Messages[testContent] = Message{Subject: "Changed request", Text: "Changed content"}
				var err error
				request.ContentDigest, err = MessageDigest(cfg.Messages[testContent])
				if err != nil {
					t.Fatal(err)
				}
			case "recipient":
				cfg.Routes[testSession] = "another@example.net"
			case "sender":
				cfg.Sender = "other-sender@example.com"
			case "account":
				cfg.AccountID = strings.Repeat("b", 32)
			}
			changed := newTestDispatcher(t, cfg, transport)
			if _, err := changed.Dispatch(context.Background(), request); !errors.Is(err, humanrelay.ErrDispatchConflict) {
				t.Fatalf("changed %s did not conflict: %v", change, err)
			}
			if _, found, err := changed.Lookup(context.Background(), request); found || !errors.Is(err, humanrelay.ErrDispatchConflict) {
				t.Fatalf("changed lookup = found:%t err:%v", found, err)
			}
			if calls.Load() != 1 {
				t.Fatal("changed request made another wire attempt")
			}
		})
	}
}

func TestConstructorCopiesPrivateConfiguration(t *testing.T) {
	cfg, request, _ := testConfig(t)
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(wire *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(wire.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "mutated") {
			t.Error("caller mutated the active dispatcher configuration")
		}
		return acceptedResponse(), nil
	}))
	cfg.Routes[testSession] = "mutated@example.net"
	cfg.Messages[testContent] = Message{Subject: "mutated", Text: "mutated"}
	if _, err := dispatcher.Dispatch(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidRequestDoesNotReachProvider(t *testing.T) {
	for _, kind := range []string{"channel", testSessionField, "content", "digest", "intent"} {
		t.Run(kind, func(t *testing.T) {
			cfg, request, _ := testConfig(t)
			var calls atomic.Int32
			dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return acceptedResponse(), nil
			}))
			switch kind {
			case "channel":
				request.Channel = taskcoord.ReachabilitySNS
			case testSessionField:
				request.RelaySessionRef = "https://unregistered.example/session"
			case "content":
				request.ContentRef = "https://unregistered.example/content"
			case "digest":
				request.ContentDigest = strings.Repeat("0", 64)
			case "intent":
				request.IntentID = "contains\ncontrol"
			}
			if _, err := dispatcher.Dispatch(context.Background(), request); err == nil || calls.Load() != 0 {
				t.Fatalf("invalid request dispatched: %v", err)
			}
		})
	}
}

func TestLookupMissingIntentNeverSends(t *testing.T) {
	cfg, request, _ := testConfig(t)
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return acceptedResponse(), nil
	}))
	if _, found, err := dispatcher.Lookup(context.Background(), request); found || err != nil {
		t.Fatalf("missing lookup = found:%t err:%v", found, err)
	}
	if calls.Load() != 0 {
		t.Fatal("read-only lookup sent a notification")
	}
}

func TestCloseRejectsFurtherDispatchAndLookup(t *testing.T) {
	cfg, request, _ := testConfig(t)
	var calls atomic.Int32
	dispatcher := newTestDispatcher(t, cfg, roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return acceptedResponse(), nil
	}))
	dispatcher.Close()
	dispatcher.Close()
	if _, err := dispatcher.Dispatch(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("dispatch after close = %v", err)
	}
	if _, found, err := dispatcher.Lookup(context.Background(), request); found || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("lookup after close = found:%t err:%v", found, err)
	}
	if calls.Load() != 0 {
		t.Fatal("closed dispatcher made a wire attempt")
	}
}

type faultJournal struct {
	operationjournal.Store
	phase string
}

func (s *faultJournal) Reserve(ctx context.Context, r operationjournal.Reservation) (operationjournal.Record, bool, error) {
	if s.phase == "reserve" {
		return operationjournal.Record{}, false, errors.New("private reserve diagnostic " + testRecipient)
	}
	return s.Store.Reserve(ctx, r)
}

func (s *faultJournal) MarkRunning(ctx context.Context, id, digest string) (operationjournal.Record, bool, error) {
	if s.phase == "running" {
		return operationjournal.Record{}, false, errors.New("private running diagnostic " + testToken)
	}
	return s.Store.MarkRunning(ctx, id, digest)
}

func (s *faultJournal) Finalize(ctx context.Context, f operationjournal.Finalization) (operationjournal.Record, error) {
	if s.phase == "finalize" {
		return operationjournal.Record{}, errors.New("private finalize diagnostic " + testSender)
	}
	r, err := s.Store.Finalize(ctx, f)
	if err == nil && s.phase == "after-commit" {
		return operationjournal.Record{}, errors.New("private lost commit acknowledgement " + testToken)
	}
	return r, err
}

func TestJournalFailuresDoNotAuthorizeBlindRetry(t *testing.T) {
	for _, phase := range []string{"reserve", "running", "finalize", "after-commit"} {
		t.Run(phase, func(t *testing.T) {
			cfg, request, _ := testConfig(t)
			underlying := cfg.Journal
			cfg.Journal = &faultJournal{Store: underlying, phase: phase}
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return acceptedResponse(), nil
			})
			dispatcher := newTestDispatcher(t, cfg, transport)
			if _, err := dispatcher.Dispatch(context.Background(), request); err == nil {
				t.Fatal("journal error released an acknowledgement")
			} else {
				assertPrivateValuesAbsent(t, err.Error())
			}
			if phase == "reserve" || phase == "running" {
				if calls.Load() != 0 {
					t.Fatal("provider called before durable reservation")
				}
				return
			}
			cfg.Journal = underlying
			recovered := newTestDispatcher(t, cfg, transport)
			ack, found, err := recovered.Lookup(context.Background(), request)
			if phase == "after-commit" {
				if err != nil || !found || ack.IntentID != request.IntentID {
					t.Fatalf("saved provider evidence not recovered: %+v, %t, %v", ack, found, err)
				}
			} else if found {
				t.Fatal("uncommitted provider evidence treated as durable")
			}
			_, _ = recovered.Dispatch(context.Background(), request)
			if calls.Load() != 1 {
				t.Fatal("post-send journal error caused another wire attempt")
			}
		})
	}
}

func TestRejectUnsafeConfiguration(t *testing.T) {
	for _, kind := range []string{"account", "token", "sender", "recipient", testSessionField, "content", "journal", "typed-nil-journal", "subject"} {
		t.Run(kind, func(t *testing.T) {
			cfg, _, _ := testConfig(t)
			switch kind {
			case "account":
				cfg.AccountID = "../other-account"
			case "token":
				cfg.APIToken = "token\r\nInjected: yes"
			case "sender":
				cfg.Sender = "Sender <notify@example.com>"
			case "recipient":
				cfg.Routes[testSession] = "one@example.net,two@example.net"
			case testSessionField:
				cfg.Routes["https://gateway.example/relay?token=secret"] = testRecipient
			case "content":
				cfg.Messages["http://content.example/plain"] = cfg.Messages[testContent]
			case "journal":
				cfg.Journal = nil
			case "typed-nil-journal":
				var journal *operationjournal.FileStore
				cfg.Journal = journal
			case "subject":
				cfg.Messages[testContent] = Message{Subject: "subject\r\nBcc: other@example.net", Text: "body"}
			}
			if d, err := New(cfg); err == nil {
				d.Close()
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
