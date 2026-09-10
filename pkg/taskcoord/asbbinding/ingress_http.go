// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	// IngressRequestIDHeader carries the server-generated correlation identifier.
	// Inbound values are never trusted or reflected.
	IngressRequestIDHeader = "X-Request-ID"

	ingressRequestIDPrefix = "asbreq-"
)

// IngressErrorCode is the stable machine-readable HTTP failure classification.
type IngressErrorCode string

const (
	IngressCodeInvalidRequest          IngressErrorCode = "INVALID_REQUEST"
	IngressCodeUnsupportedMediaType    IngressErrorCode = "UNSUPPORTED_MEDIA_TYPE"
	IngressCodeAuthenticationRequired  IngressErrorCode = "AUTHENTICATION_REQUIRED"
	IngressCodeChallengeRejected       IngressErrorCode = "CHALLENGE_REJECTED"
	IngressCodeOperationRejected       IngressErrorCode = "OPERATION_REJECTED"
	IngressCodeNotFound                IngressErrorCode = "NOT_FOUND"
	IngressCodeStateConflict           IngressErrorCode = "STATE_CONFLICT"
	IngressCodeMethodNotAllowed        IngressErrorCode = "METHOD_NOT_ALLOWED"
	IngressCodeRateLimited             IngressErrorCode = "RATE_LIMITED"
	IngressCodeOperationOutcomeUnknown IngressErrorCode = "OPERATION_OUTCOME_UNKNOWN"
	IngressCodeInternalError           IngressErrorCode = "INTERNAL_ERROR"
)

// IngressErrorResponse preserves the v1 error string while adding stable
// machine-readable fields. Retryable means the same HTTP request is safe to
// retry automatically; it does not mean a caller may repeat the operation with
// fresh proof material.
type IngressErrorResponse struct {
	Error     string           `json:"error"`
	Code      IngressErrorCode `json:"code"`
	Retryable bool             `json:"retryable"`
	RequestID string           `json:"request_id"`
}

type ingressFailure struct {
	status    int
	message   string
	retryable bool
}

func ingressFailureForCode(code IngressErrorCode) ingressFailure {
	switch code {
	case IngressCodeInvalidRequest:
		return ingressFailure{http.StatusBadRequest, "request is invalid", false}
	case IngressCodeUnsupportedMediaType:
		return ingressFailure{http.StatusUnsupportedMediaType, "Content-Type must be application/json", false}
	case IngressCodeAuthenticationRequired:
		return ingressFailure{http.StatusUnauthorized, "authenticated TLS client is required", false}
	case IngressCodeChallengeRejected:
		return ingressFailure{http.StatusUnauthorized, "challenge is invalid or unavailable", false}
	case IngressCodeOperationRejected:
		return ingressFailure{http.StatusForbidden, "operation is not authorized", false}
	case IngressCodeNotFound:
		return ingressFailure{http.StatusNotFound, "resource was not found", false}
	case IngressCodeStateConflict:
		return ingressFailure{http.StatusConflict, "operation conflicts with current state", false}
	case IngressCodeMethodNotAllowed:
		return ingressFailure{http.StatusMethodNotAllowed, "method is not allowed", false}
	case IngressCodeRateLimited:
		return ingressFailure{http.StatusTooManyRequests, "too many outstanding challenges", true}
	case IngressCodeOperationOutcomeUnknown:
		return ingressFailure{http.StatusServiceUnavailable, "operation outcome is unknown", false}
	case IngressCodeInternalError:
		return ingressFailure{http.StatusInternalServerError, "internal service error", false}
	default:
		return ingressFailure{http.StatusInternalServerError, "internal service error", false}
	}
}

func ingressCodeForError(err error) IngressErrorCode {
	switch {
	case errors.Is(err, taskcoord.ErrNotFound):
		return IngressCodeNotFound
	case errors.Is(err, taskcoord.ErrRevisionConflict),
		errors.Is(err, taskcoord.ErrEventConflict),
		errors.Is(err, taskcoord.ErrAlreadyExists),
		errors.Is(err, taskcoord.ErrInvalidTransition),
		errors.Is(err, taskcoord.ErrInvalidDelegation),
		errors.Is(err, taskcoord.ErrInvalidInteraction),
		errors.Is(err, taskcoord.ErrParticipantUnavailable),
		errors.Is(err, taskcoord.ErrDelegationNotPermitted):
		return IngressCodeStateConflict
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrTranscriptSize),
		errors.Is(err, ErrUnsupportedOperationKind):
		return IngressCodeInvalidRequest
	case errors.Is(err, ErrTLSRequired):
		return IngressCodeAuthenticationRequired
	case errors.Is(err, ErrUnknownChallenge), errors.Is(err, ErrChallengeConnection),
		errors.Is(err, ErrChallengeRequest):
		return IngressCodeChallengeRejected
	case errors.Is(err, ErrChallengeLimit):
		return IngressCodeRateLimited
	case errors.Is(err, errChallengeCollision):
		return IngressCodeInternalError
	case errors.Is(err, errOperationAuthorization),
		errors.Is(err, ErrMissingDelegationVerifier),
		errors.Is(err, taskcoord.ErrAuthenticationRequired):
		return IngressCodeOperationRejected
	case errors.Is(err, taskcoord.ErrStoreUnavailable):
		return IngressCodeOperationOutcomeUnknown
	default:
		// Store adapters and verifier callbacks can return implementation-specific
		// errors. Once execution has started, conservatively report an unknown
		// outcome without exposing those details or inviting a blind retry.
		return IngressCodeOperationOutcomeUnknown
	}
}

var ingressRequestIDSequence atomic.Uint64

func (s *Ingress) newRequestID() string {
	if s != nil && s.RequestIDGenerator != nil {
		if candidate := s.RequestIDGenerator(); validIngressRequestID(candidate) {
			return candidate
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return ingressRequestIDPrefix + hex.EncodeToString(random[:])
	}
	sequence := ingressRequestIDSequence.Add(1)
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d:%d", time.Now().UnixNano(), sequence)))
	return ingressRequestIDPrefix + hex.EncodeToString(digest[:16])
}

func validIngressRequestID(value string) bool {
	if len(value) != len(ingressRequestIDPrefix)+32 || !strings.HasPrefix(value, ingressRequestIDPrefix) {
		return false
	}
	for _, char := range value[len(ingressRequestIDPrefix):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func setIngressResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
}

func (s *Ingress) writeIngressError(w http.ResponseWriter, code IngressErrorCode) {
	setIngressResponseHeaders(w)
	requestID := w.Header().Get(IngressRequestIDHeader)
	if !validIngressRequestID(requestID) {
		requestID = s.newRequestID()
		w.Header().Set(IngressRequestIDHeader, requestID)
	}
	failure := ingressFailureForCode(code)
	if code == IngressCodeRateLimited {
		w.Header().Set("Retry-After", "1")
	}
	writeIngressJSON(w, failure.status, IngressErrorResponse{
		Error:     failure.message,
		Code:      code,
		Retryable: failure.retryable,
		RequestID: requestID,
	})
}

func acceptsIngressJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && strings.EqualFold(mediaType, "application/json")
}
