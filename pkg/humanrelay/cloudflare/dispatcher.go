// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package cloudflare sends bounded, plain-text Human relay notifications using
// Cloudflare Email Sending. It belongs to the trusted worker, not an Agent API.
// A provider acknowledgement never authorizes an action or proves Human receipt.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/operationjournal"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	maxEntries       = 1_000
	maxTextBytes     = 16 << 10
	maxResponseBytes = 64 << 10
	defaultTimeout   = 10 * time.Second
)

var (
	ErrConfig         = errors.New("cloudflare relay: invalid configuration")
	ErrRequest        = errors.New("cloudflare relay: invalid or unmapped request")
	ErrUnavailable    = errors.New("cloudflare relay: journal or dispatcher unavailable")
	ErrOutcomeUnknown = errors.New("cloudflare relay: dispatch outcome unknown; do not resend")
	ErrBusy           = errors.New("cloudflare relay: concurrent operation limit reached")
)

// Message is administrator-controlled content. No content URL is fetched.
type Message struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// Config is private deployment configuration, never Agent-supplied input.
// Routes maps opaque relay sessions to one bare email address. Messages maps
// opaque content references to approved text. Both maps are copied by New.
// Journal must be durable and serialize every writer for its deployment scope.
// A dedicated operationjournal.FileStore supports ONE worker process, including
// restart. Multiple processes require a journal with cross-process atomicity.
type Config struct {
	AccountID   string
	APIToken    string
	Sender      string
	Routes      map[string]string
	Messages    map[string]Message
	Journal     operationjournal.Store
	Timeout     time.Duration
	MaxInFlight int
}

// Dispatcher implements one-attempt dispatch and read-only recovery of locally
// committed acknowledgements. Its journal must never be reset or rolled back to
// permit a resend. It has no provider-event collector or remote recovery query.
type Dispatcher struct {
	account  string
	token    string
	sender   string
	routes   map[string]string
	messages map[string]Message
	journal  operationjournal.Store
	client   *http.Client
	timeout  time.Duration
	slots    chan struct{}
	closed   atomic.Bool
}

var (
	_ humanrelay.SessionDispatcher  = (*Dispatcher)(nil)
	_ humanrelay.ProviderReconciler = (*Dispatcher)(nil)
)

// New constructs a dispatcher without sending anything. Only the fixed HTTPS
// Cloudflare API origin receives credentials. Proxies, redirects, SDK retries,
// HTTP/2 stream retries and replayable request bodies are not enabled.
func New(config Config) (*Dispatcher, error) {
	if len(config.AccountID) != 32 || !lowerHex(config.AccountID) || !validToken(config.APIToken) || !validAddress(config.Sender) || nilStore(config.Journal) {
		return nil, ErrConfig
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}
	if config.MaxInFlight == 0 {
		config.MaxInFlight = 4
	}
	if config.Timeout < time.Millisecond || config.Timeout > 20*time.Second || config.MaxInFlight < 1 || config.MaxInFlight > 32 {
		return nil, ErrConfig
	}
	if len(config.Routes) == 0 || len(config.Routes) > maxEntries || len(config.Messages) == 0 || len(config.Messages) > maxEntries {
		return nil, ErrConfig
	}
	routes := make(map[string]string, len(config.Routes))
	for session, recipient := range config.Routes {
		if !validReference(session) || !validAddress(recipient) {
			return nil, ErrConfig
		}
		routes[session] = recipient
	}
	messages := make(map[string]Message, len(config.Messages))
	for ref, message := range config.Messages {
		if _, err := MessageDigest(message); !validReference(ref) || err != nil {
			return nil, ErrConfig
		}
		messages[ref] = message
	}
	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  config.Timeout,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           config.MaxInFlight,
		MaxIdleConnsPerHost:    config.MaxInFlight,
		MaxConnsPerHost:        config.MaxInFlight,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true,
		TLSNextProto:           make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Dispatcher{
		account: config.AccountID, token: config.APIToken, sender: config.Sender,
		routes: routes, messages: messages, journal: config.Journal,
		client: client, timeout: config.Timeout, slots: make(chan struct{}, config.MaxInFlight),
	}, nil
}

// Close rejects new calls and closes idle connections. Calls already admitted
// finish within their context deadline. The caller owns and closes the journal.
func (d *Dispatcher) Close() {
	d.closed.Store(true)
	d.client.CloseIdleConnections()
}

// MessageDigest binds the exact UTF-8 subject and plain text to the relay's
// ContentDigest. It is hex SHA-256 of the compact JSON content envelope below.
func MessageDigest(message Message) (string, error) {
	if !validText(message.Subject, 256, false) || !validText(message.Text, maxTextBytes, true) {
		return "", ErrRequest
	}
	return digestJSON(struct {
		Schema  string  `json:"schema"`
		Message Message `json:"message"`
	}{"asb.cloudflare-email-content/v1", message})
}

type email struct {
	From    string `json:"from"`
	To      string `json:"to"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

type prepared struct {
	id, digest string
	message    email
}

func (d *Dispatcher) prepare(request humanrelay.DispatchRequest) (prepared, error) {
	if !validText(request.IntentID, 256, false) || strings.TrimSpace(request.IntentID) != request.IntentID || request.Channel != taskcoord.ReachabilityEmail {
		return prepared{}, ErrRequest
	}
	to, routed := d.routes[request.RelaySessionRef]
	message, resolved := d.messages[request.ContentRef]
	if !routed || !resolved {
		return prepared{}, ErrRequest
	}
	digest, err := MessageDigest(message)
	if err != nil || request.ContentDigest != digest {
		return prepared{}, ErrRequest
	}
	payload := email{From: d.sender, To: to, Subject: message.Subject, Text: message.Text}
	bound, err := digestJSON(struct {
		Schema  string                     `json:"schema"`
		Account string                     `json:"account"`
		Request humanrelay.DispatchRequest `json:"request"`
		Email   email                      `json:"email"`
	}{"asb.cloudflare-email-dispatch/v1", d.account, request, payload})
	if err != nil {
		return prepared{}, ErrRequest
	}
	id := sha256.Sum256([]byte(request.IntentID))
	return prepared{id: fmt.Sprintf("cloudflare-email:%x", id), digest: "sha256:" + bound, message: payload}, nil
}

func (d *Dispatcher) enter(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if d.closed.Load() {
		return nil, nil, ErrUnavailable
	}
	select {
	case d.slots <- struct{}{}:
		bounded, cancel := context.WithTimeout(ctx, d.timeout)
		return bounded, func() { cancel(); <-d.slots }, nil
	default:
		return nil, nil, ErrBusy
	}
}

// Dispatch reserves the exact request and persists RUNNING before the HTTP
// attempt. Only the MarkRunning winner sends. An ambiguous outcome remains
// reserved forever; repeating the request cannot cause another send.
func (d *Dispatcher) Dispatch(ctx context.Context, request humanrelay.DispatchRequest) (humanrelay.ProviderAck, error) {
	ctx, release, err := d.enter(ctx)
	if err != nil {
		return humanrelay.ProviderAck{}, err
	}
	defer release()
	p, err := d.prepare(request)
	if err != nil {
		return humanrelay.ProviderAck{}, err
	}
	record, _, err := d.journal.Reserve(ctx, operationjournal.Reservation{OperationID: p.id, RequestDigest: p.digest})
	if err != nil {
		return humanrelay.ProviderAck{}, journalError(err)
	}
	if record.State != operationjournal.StateAccepted {
		return acknowledgement(request, p, record)
	}
	_, started, err := d.journal.MarkRunning(ctx, p.id, p.digest)
	if err != nil || !started {
		// Another call may already have committed the acknowledgement. Recovery
		// is read-only; neither a race nor a failed commit permits another send.
		record, lookupErr := d.journal.Lookup(ctx, p.id, p.digest)
		if lookupErr != nil {
			return humanrelay.ProviderAck{}, journalError(lookupErr)
		}
		return acknowledgement(request, p, record)
	}
	if ctx.Err() != nil {
		return humanrelay.ProviderAck{}, ErrOutcomeUnknown
	}
	outcome, err := d.send(ctx, p.message, p.digest)
	if err != nil {
		return humanrelay.ProviderAck{}, ErrOutcomeUnknown
	}
	record, err = d.journal.Finalize(ctx, operationjournal.Finalization{
		OperationID: p.id, RequestDigest: p.digest, State: operationjournal.StateSucceeded, OutcomeDigest: outcome,
	})
	if err != nil {
		return humanrelay.ProviderAck{}, ErrOutcomeUnknown
	}
	return acknowledgement(request, p, record)
}

// Lookup reads only a locally committed acknowledgement with the exact request
// and current routing/content configuration. Missing or RUNNING state proves
// nothing about remote delivery. This method never calls the Cloudflare API.
func (d *Dispatcher) Lookup(ctx context.Context, request humanrelay.DispatchRequest) (humanrelay.ProviderAck, bool, error) {
	ctx, release, err := d.enter(ctx)
	if err != nil {
		return humanrelay.ProviderAck{}, false, err
	}
	defer release()
	p, err := d.prepare(request)
	if err != nil {
		return humanrelay.ProviderAck{}, false, err
	}
	record, err := d.journal.Lookup(ctx, p.id, p.digest)
	if errors.Is(err, operationjournal.ErrNotFound) {
		return humanrelay.ProviderAck{}, false, nil
	}
	if err != nil {
		return humanrelay.ProviderAck{}, false, journalError(err)
	}
	ack, err := acknowledgement(request, p, record)
	if errors.Is(err, ErrOutcomeUnknown) {
		return humanrelay.ProviderAck{}, false, nil
	}
	return ack, err == nil, err
}

func acknowledgement(request humanrelay.DispatchRequest, p prepared, record operationjournal.Record) (humanrelay.ProviderAck, error) {
	if record.OperationID != p.id || record.RequestDigest != p.digest {
		return humanrelay.ProviderAck{}, humanrelay.ErrDispatchConflict
	}
	if record.State != operationjournal.StateSucceeded {
		return humanrelay.ProviderAck{}, ErrOutcomeUnknown
	}
	if !strings.HasPrefix(record.OutcomeDigest, "sha256:") || len(record.OutcomeDigest) != 71 || !lowerHex(record.OutcomeDigest[7:]) || record.CompletedAt.IsZero() {
		return humanrelay.ProviderAck{}, ErrUnavailable
	}
	return humanrelay.ProviderAck{IntentID: request.IntentID, AckRef: "cloudflare:" + record.OutcomeDigest[7:], At: record.CompletedAt}, nil
}

func (d *Dispatcher) send(ctx context.Context, message email, requestDigest string) (string, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return "", ErrOutcomeUnknown
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.cloudflare.com/client/v4/accounts/"+d.account+"/email/sending/send", bytes.NewReader(body))
	if err != nil {
		return "", ErrOutcomeUnknown
	}
	req.GetBody = nil // Do not replay POST bytes on a transport retry.
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := d.client.Do(req)
	if err != nil {
		return "", ErrOutcomeUnknown
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return "", ErrOutcomeUnknown
	}
	raw, err := strictjson.ReadDocument(response.Body, maxResponseBytes)
	if err != nil || !accepted(raw, message.To) {
		return "", ErrOutcomeUnknown
	}
	// Persist only an opaque binding of the authenticated response and request,
	// never provider IDs, addresses, message text or raw response diagnostics.
	digest := sha256.Sum256(append([]byte(requestDigest+"\n"), raw...))
	return fmt.Sprintf("sha256:%x", digest), nil
}

func accepted(raw []byte, recipient string) bool {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return false
	}
	var success bool
	var failures []json.RawMessage
	if json.Unmarshal(envelope["success"], &success) != nil || !success ||
		json.Unmarshal(envelope["errors"], &failures) != nil || failures == nil || len(failures) != 0 {
		return false
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(envelope["result"], &result) != nil || result == nil {
		return false
	}
	positive := 0
	for _, key := range []string{"delivered", "queued", "permanent_bounces", "suppressed_recipients"} {
		value, present := result[key]
		if !present {
			continue
		}
		var addresses []string
		if json.Unmarshal(value, &addresses) != nil || addresses == nil {
			return false
		}
		for _, address := range addresses {
			if address != recipient || (key != "delivered" && key != "queued") {
				return false
			}
			positive++
		}
	}
	return positive == 1
}

func journalError(err error) error {
	if errors.Is(err, operationjournal.ErrConflict) {
		return humanrelay.ErrDispatchConflict
	}
	return ErrUnavailable
}

func digestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func lowerHex(value string) bool {
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func validAddress(value string) bool {
	if !validText(value, 254, false) || strings.TrimSpace(value) != value {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && address.Name == ""
}

func validReference(value string) bool {
	if !validText(value, 2048, false) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validText(value string, limit int, multiline bool) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) && !(multiline && (c == '\n' || c == '\r' || c == '\t')) {
			return false
		}
	}
	return true
}

func nilStore(store operationjournal.Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
