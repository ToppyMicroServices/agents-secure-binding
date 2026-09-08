// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

var ingressRequestIDPattern = regexp.MustCompile(`^asbreq-[0-9a-f]{32}$`)

func TestIngressSuccessResponseContract(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	requestIDs := []string{
		"asbreq-11111111111111111111111111111111",
		"asbreq-22222222222222222222222222222222",
	}
	nextRequestID := 0
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
		ingress.RequestIDGenerator = func() string {
			requestID := requestIDs[nextRequestID]
			nextRequestID++
			return requestID
		}
	})
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:accept",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}

	challengeBody := mustJSON(t, ChallengeRequest{
		Operation: OperationAssignmentTransition,
		Request:   mustJSON(t, request),
	})
	challengeResponse, challengeRaw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressChallengePath,
		"application/json; charset=utf-8", "caller-selected-request-id", challengeBody,
	)
	assertIngressContractSuccess(t, challengeResponse, http.StatusCreated, requestIDs[0])
	if bytes.Contains(challengeRaw, []byte("caller-selected-request-id")) {
		t.Fatalf("challenge response echoed the inbound request ID: %s", challengeRaw)
	}

	var challenge ChallengeResponse
	if err := json.Unmarshal(challengeRaw, &challenge); err != nil {
		t.Fatal(err)
	}
	live := liveChallenge{ChallengeResponse: challenge}
	operation, err := decodeOperation(OperationAssignmentTransition, mustJSON(t, request))
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || len(transport.TLSClientConfig.Certificates) == 0 ||
		transport.TLSClientConfig.Certificates[0].Leaf == nil || challengeResponse.TLS == nil {
		t.Fatal("test client does not expose TLS binding material")
	}
	live.binding, err = BindingFromTLS(
		challengeResponse.TLS,
		transport.TLSClientConfig.Certificates[0].Leaf,
		operation.digest,
		challenge.Nonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, operation.digest, live)
	executeBody := mustJSON(t, ExecuteRequest{
		ChallengeID: challenge.ChallengeID,
		Operation:   OperationAssignmentTransition,
		Request:     mustJSON(t, request),
		GrantJWT:    grant, SessionBindingJWT: proof,
	})
	executeResponse, executeRaw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressExecutePath,
		"application/json", "another-caller-selected-id", executeBody,
	)
	assertIngressContractSuccess(t, executeResponse, http.StatusOK, requestIDs[1])
	if bytes.Contains(executeRaw, []byte("another-caller-selected-id")) {
		t.Fatalf("execute response echoed the inbound request ID: %s", executeRaw)
	}
	var result ExecuteResponse
	if err := json.Unmarshal(executeRaw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Operation != OperationAssignmentTransition || result.Assignment == nil ||
		result.Assignment.Status != taskcoord.AssignmentAccepted {
		t.Fatalf("execute response = %+v", result)
	}
}

func TestIngressErrorResponseKeepsLegacyErrorAndRejectsInboundRequestID(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
		// An invalid generator result must not become a peer-controlled or malformed
		// correlation identifier. The ingress falls back to a safe server value.
		ingress.RequestIDGenerator = func() string { return "invalid-generator-result" }
	})
	response, raw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressChallengePath,
		"application/json", "caller-secret-request-id", []byte(`{}`),
	)
	payload := assertIngressContractError(
		t, response, raw, http.StatusBadRequest, IngressCodeInvalidRequest,
		"request is invalid", false,
	)
	if payload.RequestID == "caller-secret-request-id" ||
		bytes.Contains(raw, []byte("caller-secret-request-id")) {
		t.Fatalf("response echoed the inbound request ID: header=%q body=%s",
			response.Header.Get("X-Request-ID"), raw)
	}
	var legacy struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("legacy error client could not decode response: %v", err)
	}
	if legacy.Error != "request is invalid" {
		t.Fatalf("legacy error = %q, want %q", legacy.Error, "request is invalid")
	}
}

func TestIngressRouteMethodAndMediaTypeContract(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), nil)
	validRequest := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:media",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	validChallenge := mustJSON(t, ChallengeRequest{
		Operation: OperationAssignmentTransition,
		Request:   mustJSON(t, validRequest),
	})

	tests := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        []byte
		status      int
		code        IngressErrorCode
		message     string
	}{
		{
			name: "wrong method", method: http.MethodGet, path: IngressChallengePath,
			status: http.StatusMethodNotAllowed, code: IngressCodeMethodNotAllowed,
			message: "method is not allowed",
		},
		{
			name: "unknown route", method: http.MethodPost, path: "/v1/human-operations/unknown",
			contentType: "application/json", body: []byte(`{}`), status: http.StatusNotFound,
			code: IngressCodeNotFound, message: "resource was not found",
		},
		{
			name: "missing media type", method: http.MethodPost, path: IngressChallengePath,
			body: validChallenge, status: http.StatusUnsupportedMediaType,
			code: IngressCodeUnsupportedMediaType, message: "Content-Type must be application/json",
		},
		{
			name: "wrong media type", method: http.MethodPost, path: IngressChallengePath,
			contentType: "text/plain", body: validChallenge, status: http.StatusUnsupportedMediaType,
			code: IngressCodeUnsupportedMediaType, message: "Content-Type must be application/json",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, raw := doIngressContractRequest(
				t, client, test.method, server.URL+test.path, test.contentType, "", test.body,
			)
			assertIngressContractError(
				t, response, raw, test.status, test.code, test.message, false,
			)
		})
	}

	response, _ := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressChallengePath,
		"application/json; charset=utf-8", "", validChallenge,
	)
	assertIngressContractSuccess(t, response, http.StatusCreated, "")
}

func TestIngressRejectsEndpointMismatchedEnvelopes(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), nil)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:endpoint-shape",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challengeShape := mustJSON(t, ChallengeRequest{
		Operation: OperationAssignmentTransition,
		Request:   mustJSON(t, request),
	})
	executeShape := mustJSON(t, ExecuteRequest{
		ChallengeID: "challenge:not-for-challenge-endpoint",
		Operation:   OperationAssignmentTransition,
		Request:     mustJSON(t, request),
		GrantJWT:    "grant", SessionBindingJWT: "proof",
	})

	for _, test := range []struct {
		name string
		path string
		body []byte
	}{
		{name: "challenge body on execute", path: IngressExecutePath, body: challengeShape},
		{name: "execute body on challenge", path: IngressChallengePath, body: executeShape},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, raw := doIngressContractRequest(
				t, client, http.MethodPost, server.URL+test.path, "application/json", "", test.body,
			)
			assertIngressContractError(
				t, response, raw, http.StatusBadRequest, IngressCodeInvalidRequest,
				"request is invalid", false,
			)
		})
	}
}

func TestIngressRedactsRandomAndCommitErrors(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:backend",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	challengeBody := mustJSON(t, ChallengeRequest{
		Operation: OperationAssignmentTransition,
		Request:   mustJSON(t, request),
	})

	t.Run("random source", func(t *testing.T) {
		const canary = "rng-secret-canary"
		server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
			ingress.Random = ingressContractErrorReader{err: errors.New(canary)}
			ingress.RequestIDGenerator = func() string {
				return "asbreq-33333333333333333333333333333333"
			}
		})
		response, raw := doIngressContractRequest(
			t, client, http.MethodPost, server.URL+IngressChallengePath,
			"application/json", "", challengeBody,
		)
		assertIngressContractError(
			t, response, raw, http.StatusInternalServerError, IngressCodeInternalError,
			"internal service error", false,
		)
		assertIngressContractRedacted(t, raw, canary)
	})

	t.Run("commit outcome", func(t *testing.T) {
		const canary = "commit-storage-secret-canary"
		baseStore := seededIngressStore(t, now)
		store := &ingressContractCommitFailingStore{
			Store: baseStore,
			err:   errors.New(canary),
		}
		server, client := newLiveIngressWithStore(t, now, store, nil)
		challenge := requestChallenge(
			t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated,
		)
		digest, err := TransitionDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		grant, proof := signedIngressEvidence(t, now, digest, challenge)
		executeBody := mustJSON(t, ExecuteRequest{
			ChallengeID: challenge.ChallengeID,
			Operation:   OperationAssignmentTransition,
			Request:     mustJSON(t, request),
			GrantJWT:    grant, SessionBindingJWT: proof,
		})
		response, raw := doIngressContractRequest(
			t, client, http.MethodPost, server.URL+IngressExecutePath,
			"application/json", "", executeBody,
		)
		assertIngressContractError(
			t, response, raw, http.StatusServiceUnavailable, IngressCodeOperationOutcomeUnknown,
			"operation outcome is unknown", false,
		)
		assertIngressContractRedacted(t, raw, canary)
	})

	t.Run("store read", func(t *testing.T) {
		const canary = "load-storage-secret-canary"
		baseStore := seededIngressStore(t, now)
		store := &ingressContractLoadFailingStore{
			Store: baseStore,
			err:   errors.New(canary),
		}
		server, client := newLiveIngressWithStore(t, now, store, nil)
		challenge := requestChallenge(
			t, client, server.URL, OperationAssignmentTransition, request, http.StatusCreated,
		)
		digest, err := TransitionDigest(request)
		if err != nil {
			t.Fatal(err)
		}
		grant, proof := signedIngressEvidence(t, now, digest, challenge)
		response, raw := doIngressContractRequest(
			t, client, http.MethodPost, server.URL+IngressExecutePath, "application/json", "",
			mustJSON(t, ExecuteRequest{
				ChallengeID: challenge.ChallengeID,
				Operation:   OperationAssignmentTransition,
				Request:     mustJSON(t, request),
				GrantJWT:    grant, SessionBindingJWT: proof,
			}),
		)
		assertIngressContractError(
			t, response, raw, http.StatusServiceUnavailable, IngressCodeOperationOutcomeUnknown,
			"operation outcome is unknown", false,
		)
		assertIngressContractRedacted(t, raw, canary)
	})
}

func TestIngressRedactsDelegationVerifierError(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store, parent, target := seededDelegationIngressStore(t, now)
	const canary = "delegation-policy-secret-canary"
	server, client := newLiveIngressWithStore(t, now, store, func(ingress *Ingress) {
		ingress.Policy.DelegationVerifier = DelegationDecisionVerifierFunc(func(
			context.Context,
			taskcoord.Assignment,
			DelegationRequest,
			time.Time,
		) (taskcoord.VerifiedDelegation, error) {
			return taskcoord.VerifiedDelegation{}, errors.New(canary)
		})
	})
	request := liveDelegationRequest(parent, target.ParticipantID)
	request.EventID = "event:contract:delegation"
	request.ChildEventID = "event:contract:delegation-child"
	request.ChildTaskID = "task:contract:delegation-child"
	request.ChildAssignmentID = "assignment:contract:delegation-child"
	challenge := requestChallenge(
		t, client, server.URL, OperationAssignmentDelegation, request, http.StatusCreated,
	)
	digest, err := DelegationDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	grant, proof := signedIngressEvidence(t, now, digest, challenge)
	response, raw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressExecutePath, "application/json", "",
		mustJSON(t, ExecuteRequest{
			ChallengeID: challenge.ChallengeID,
			Operation:   OperationAssignmentDelegation,
			Request:     mustJSON(t, request),
			GrantJWT:    grant, SessionBindingJWT: proof,
		}),
	)
	assertIngressContractError(
		t, response, raw, http.StatusForbidden, IngressCodeOperationRejected,
		"operation is not authorized", false,
	)
	assertIngressContractRedacted(t, raw, canary)
}

func TestIngressNotFoundConflictAndChallengeErrors(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), nil)

	tests := []struct {
		name    string
		request TransitionRequest
		status  int
		code    IngressErrorCode
		message string
	}{
		{
			name: "not found",
			request: TransitionRequest{
				ParticipantID: "human:alice", EventID: "event:contract:not-found",
				TaskID: "task:contract:missing", AssignmentID: "assignment:contract:missing",
				Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
			},
			status: http.StatusNotFound, code: IngressCodeNotFound,
			message: "resource was not found",
		},
		{
			name: "state conflict",
			request: TransitionRequest{
				ParticipantID: "human:alice", EventID: "event:contract:conflict",
				TaskID: "task:human:1", AssignmentID: "assignment:human:1",
				Operation: taskcoord.OperationAccept, ExpectedRevision: 2,
			},
			status: http.StatusConflict, code: IngressCodeStateConflict,
			message: "operation conflicts with current state",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challenge := requestChallenge(
				t, client, server.URL, OperationAssignmentTransition, test.request, http.StatusCreated,
			)
			digest, err := TransitionDigest(test.request)
			if err != nil {
				t.Fatal(err)
			}
			grant, proof := signedIngressEvidence(t, now, digest, challenge)
			response, raw := doIngressContractRequest(
				t, client, http.MethodPost, server.URL+IngressExecutePath, "application/json", "",
				mustJSON(t, ExecuteRequest{
					ChallengeID: challenge.ChallengeID,
					Operation:   OperationAssignmentTransition,
					Request:     mustJSON(t, test.request),
					GrantJWT:    grant, SessionBindingJWT: proof,
				}),
			)
			assertIngressContractError(
				t, response, raw, test.status, test.code, test.message, false,
			)
		})
	}

	unknownChallengeRequest := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:unknown-challenge",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	response, raw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressExecutePath, "application/json", "",
		mustJSON(t, ExecuteRequest{
			ChallengeID: strings.Repeat("a", 64),
			Operation:   OperationAssignmentTransition,
			Request:     mustJSON(t, unknownChallengeRequest),
			GrantJWT:    "not-inspected", SessionBindingJWT: "not-inspected",
		}),
	)
	assertIngressContractError(
		t, response, raw, http.StatusUnauthorized, IngressCodeChallengeRejected,
		"challenge is invalid or unavailable", false,
	)
}

func TestIngressRateLimitContract(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server, client := newLiveIngressWithStore(t, now, seededIngressStore(t, now), func(ingress *Ingress) {
		ingress.MaxPending = 1
		ingress.MaxTotalPending = 4
	})
	request := TransitionRequest{
		ParticipantID: "human:alice", EventID: "event:contract:rate-limit",
		TaskID: "task:human:1", AssignmentID: "assignment:human:1",
		Operation: taskcoord.OperationAccept, ExpectedRevision: 1,
	}
	body := mustJSON(t, ChallengeRequest{
		Operation: OperationAssignmentTransition,
		Request:   mustJSON(t, request),
	})
	first, _ := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressChallengePath,
		"application/json", "", body,
	)
	assertIngressContractSuccess(t, first, http.StatusCreated, "")
	second, raw := doIngressContractRequest(
		t, client, http.MethodPost, server.URL+IngressChallengePath,
		"application/json", "", body,
	)
	assertIngressContractError(
		t, second, raw, http.StatusTooManyRequests, IngressCodeRateLimited,
		"too many outstanding challenges", true,
	)
	if got := second.Header.Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
}

func TestIngressAuthenticationErrorContract(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	handler := mustIngressHandler(
		t, now, seededIngressStore(t, now), identitypolicy.NewMemoryReplayCache(),
	)
	request := httptest.NewRequest(
		http.MethodPost,
		IngressChallengePath,
		strings.NewReader(`{"operation":"ASSIGNMENT_TRANSITION","request":{}}`),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertIngressContractError(
		t, response, raw, http.StatusUnauthorized, IngressCodeAuthenticationRequired,
		"authenticated TLS client is required", false,
	)
}

func TestIngressErrorCodeClassifier(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want IngressErrorCode
	}{
		{name: "invalid request", err: ErrInvalidRequest, want: IngressCodeInvalidRequest},
		{name: "TLS required", err: ErrTLSRequired, want: IngressCodeAuthenticationRequired},
		{name: "unknown challenge", err: ErrUnknownChallenge, want: IngressCodeChallengeRejected},
		{name: "challenge connection", err: ErrChallengeConnection, want: IngressCodeChallengeRejected},
		{name: "challenge request", err: ErrChallengeRequest, want: IngressCodeChallengeRejected},
		{name: "operation rejected", err: errOperationAuthorization, want: IngressCodeOperationRejected},
		{
			name: "authentication required by TaskCoord", err: taskcoord.ErrAuthenticationRequired,
			want: IngressCodeOperationRejected,
		},
		{name: "not found", err: taskcoord.ErrNotFound, want: IngressCodeNotFound},
		{name: "revision conflict", err: taskcoord.ErrRevisionConflict, want: IngressCodeStateConflict},
		{name: "event conflict", err: taskcoord.ErrEventConflict, want: IngressCodeStateConflict},
		{name: "already exists", err: taskcoord.ErrAlreadyExists, want: IngressCodeStateConflict},
		{name: "invalid transition", err: taskcoord.ErrInvalidTransition, want: IngressCodeStateConflict},
		{name: "participant unavailable", err: taskcoord.ErrParticipantUnavailable, want: IngressCodeStateConflict},
		{name: "rate limited", err: ErrChallengeLimit, want: IngressCodeRateLimited},
		{name: "challenge collision", err: errChallengeCollision, want: IngressCodeInternalError},
		{
			name: "store unavailable", err: taskcoord.ErrStoreUnavailable,
			want: IngressCodeOperationOutcomeUnknown,
		},
		{
			name: "unknown execution error", err: errors.New("classifier-canary"),
			want: IngressCodeOperationOutcomeUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ingressCodeForError(test.err); got != test.want {
				t.Fatalf("ingressCodeForError(%v) = %q, want %q", test.err, got, test.want)
			}
			wrapped := errors.Join(errors.New("outer error"), test.err)
			if got := ingressCodeForError(wrapped); got != test.want {
				t.Fatalf("ingressCodeForError(wrapped %v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}

func TestIngressStableFailureMatrix(t *testing.T) {
	tests := []struct {
		code      IngressErrorCode
		status    int
		message   string
		retryable bool
	}{
		{IngressCodeInvalidRequest, http.StatusBadRequest, "request is invalid", false},
		{
			IngressCodeUnsupportedMediaType, http.StatusUnsupportedMediaType,
			"Content-Type must be application/json", false,
		},
		{
			IngressCodeAuthenticationRequired, http.StatusUnauthorized,
			"authenticated TLS client is required", false,
		},
		{
			IngressCodeChallengeRejected, http.StatusUnauthorized,
			"challenge is invalid or unavailable", false,
		},
		{
			IngressCodeOperationRejected, http.StatusForbidden,
			"operation is not authorized", false,
		},
		{IngressCodeNotFound, http.StatusNotFound, "resource was not found", false},
		{
			IngressCodeStateConflict, http.StatusConflict,
			"operation conflicts with current state", false,
		},
		{
			IngressCodeMethodNotAllowed, http.StatusMethodNotAllowed,
			"method is not allowed", false,
		},
		{
			IngressCodeRateLimited, http.StatusTooManyRequests,
			"too many outstanding challenges", true,
		},
		{
			IngressCodeOperationOutcomeUnknown, http.StatusServiceUnavailable,
			"operation outcome is unknown", false,
		},
		{
			IngressCodeInternalError, http.StatusInternalServerError,
			"internal service error", false,
		},
	}
	for _, test := range tests {
		t.Run(string(test.code), func(t *testing.T) {
			got := ingressFailureForCode(test.code)
			if got.status != test.status || got.message != test.message || got.retryable != test.retryable {
				t.Fatalf(
					"ingressFailureForCode(%q) = %+v, want status=%d message=%q retryable=%t",
					test.code, got, test.status, test.message, test.retryable,
				)
			}
		})
	}
}

func TestIngressErrorCodeWireValues(t *testing.T) {
	tests := []struct {
		got  IngressErrorCode
		want string
	}{
		{IngressCodeInvalidRequest, "INVALID_REQUEST"},
		{IngressCodeUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE"},
		{IngressCodeAuthenticationRequired, "AUTHENTICATION_REQUIRED"},
		{IngressCodeChallengeRejected, "CHALLENGE_REJECTED"},
		{IngressCodeOperationRejected, "OPERATION_REJECTED"},
		{IngressCodeNotFound, "NOT_FOUND"},
		{IngressCodeStateConflict, "STATE_CONFLICT"},
		{IngressCodeMethodNotAllowed, "METHOD_NOT_ALLOWED"},
		{IngressCodeRateLimited, "RATE_LIMITED"},
		{IngressCodeOperationOutcomeUnknown, "OPERATION_OUTCOME_UNKNOWN"},
		{IngressCodeInternalError, "INTERNAL_ERROR"},
	}
	for _, test := range tests {
		if string(test.got) != test.want {
			t.Errorf("IngressErrorCode = %q, want %q", test.got, test.want)
		}
	}
}

type ingressContractCommitFailingStore struct {
	taskcoord.Store
	err error
}

func (s *ingressContractCommitFailingStore) CommitAssignment(
	context.Context,
	uint64,
	taskcoord.Assignment,
	taskcoord.TransitionRecord,
) error {
	return s.err
}

type ingressContractLoadFailingStore struct {
	taskcoord.Store
	err error
}

func (s *ingressContractLoadFailingStore) LoadAssignment(
	context.Context,
	string,
) (taskcoord.Assignment, error) {
	return taskcoord.Assignment{}, s.err
}

type ingressContractErrorReader struct {
	err error
}

func (r ingressContractErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func doIngressContractRequest(
	t *testing.T,
	client *http.Client,
	method string,
	url string,
	contentType string,
	inboundRequestID string,
	body []byte,
) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if inboundRequestID != "" {
		request.Header.Set("X-Request-ID", inboundRequestID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, raw
}

func assertIngressContractSuccess(
	t *testing.T,
	response *http.Response,
	wantStatus int,
	wantRequestID string,
) {
	t.Helper()
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d", response.StatusCode, wantStatus)
	}
	assertIngressContractHeaders(t, response, wantRequestID)
}

func assertIngressContractError(
	t *testing.T,
	response *http.Response,
	raw []byte,
	wantStatus int,
	wantCode IngressErrorCode,
	wantMessage string,
	wantRetryable bool,
) IngressErrorResponse {
	t.Helper()
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d, body = %s", response.StatusCode, wantStatus, raw)
	}
	requestID := assertIngressContractHeaders(t, response, "")
	var payload IngressErrorResponse
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode error response: %v; body = %s", err, raw)
	}
	if payload.Error != wantMessage || payload.Code != wantCode ||
		payload.Retryable != wantRetryable || payload.RequestID != requestID {
		t.Fatalf(
			"error response = %+v, want error=%q code=%q retryable=%t request_id=%q",
			payload, wantMessage, wantCode, wantRetryable, requestID,
		)
	}
	return payload
}

func assertIngressContractHeaders(
	t *testing.T,
	response *http.Response,
	wantRequestID string,
) string {
	t.Helper()
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := response.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}
	requestID := response.Header.Get("X-Request-ID")
	if !ingressRequestIDPattern.MatchString(requestID) {
		t.Fatalf("X-Request-ID = %q, want asbreq-<32 lowercase hex>", requestID)
	}
	if wantRequestID != "" && requestID != wantRequestID {
		t.Fatalf("X-Request-ID = %q, want %q", requestID, wantRequestID)
	}
	return requestID
}

func assertIngressContractRedacted(t *testing.T, raw []byte, canary string) {
	t.Helper()
	if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(canary))) {
		t.Fatalf("response exposed internal canary %q: %s", canary, raw)
	}
}
