// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	eaattestation "github.com/thinksyncs/agents-secure-binding/pkg/atls/eaattestation"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
	"github.com/thinksyncs/agents-secure-binding/schemas"
)

const (
	IngressChallengePath = "/v1/human-operations/challenge"
	IngressExecutePath   = "/v1/human-operations/execute"

	OperationAssignmentTransition = "ASSIGNMENT_TRANSITION"
	OperationInteractionAppend    = "INTERACTION_APPEND"

	challengeBytes = 32
)

var (
	ErrTLSRequired              = errors.New("asbbinding ingress: verified TLS 1.3 client connection required")
	ErrMissingStore             = errors.New("asbbinding ingress: missing TaskCoord store")
	ErrMissingReplayCache       = errors.New("asbbinding ingress: missing shared replay cache")
	ErrMissingVerifierPolicy    = errors.New("asbbinding ingress: missing verifier policy")
	ErrUnsupportedOperationKind = errors.New("asbbinding ingress: unsupported operation kind")
	ErrUnknownChallenge         = errors.New("asbbinding ingress: unknown or expired challenge")
	ErrChallengeConnection      = errors.New("asbbinding ingress: challenge belongs to another TLS connection")
	ErrChallengeRequest         = errors.New("asbbinding ingress: challenge does not match request")
	ErrChallengeLimit           = errors.New("asbbinding ingress: too many outstanding challenges")
)

// IngressPolicy is verifier-controlled configuration. No field is read from
// the HTTP request.
type IngressPolicy struct {
	Grant          clients.JWTVerifyOptions
	SessionBinding clients.JWTVerifyOptions
	Identity       identitypolicy.Policy
	ReplayCache    identitypolicy.ReplayCache
	AcceptedUntil  func(context.Context, RequestKind, Digest) (time.Time, error)
}

// Ingress is the single external boundary for Human TaskCoord operations. It
// terminates TLS, derives the channel binding, loads current state, calls the
// exact-request profile, and commits through Store CAS.
type Ingress struct {
	Store        taskcoord.Store
	Policy       IngressPolicy
	Now          func() time.Time
	ChallengeTTL time.Duration
	MaxPending   int
	Random       io.Reader

	mu          sync.Mutex
	pending     map[string]pendingChallenge
	connections map[string]int
}

type pendingChallenge struct {
	connectionKey   string
	requestKind     RequestKind
	digest          Digest
	expiresAt       time.Time
	expectedBinding identitypolicy.Binding
}

type ChallengeRequest struct {
	Operation string          `json:"operation"`
	Request   json.RawMessage `json:"request"`
}

type ChallengeResponse struct {
	ChallengeID   string `json:"challenge_id"`
	Nonce         string `json:"nonce"`
	ExpiresAt     string `json:"expires_at"`
	RequestDigest string `json:"request_digest"`
}

type ExecuteRequest struct {
	ChallengeID       string          `json:"challenge_id"`
	Operation         string          `json:"operation"`
	Request           json.RawMessage `json:"request"`
	GrantJWT          string          `json:"grant_jwt"`
	SessionBindingJWT string          `json:"session_binding_jwt"`
}

type ExecuteResponse struct {
	Operation   string                      `json:"operation"`
	Assignment  *taskcoord.Assignment       `json:"assignment,omitempty"`
	Record      *taskcoord.TransitionRecord `json:"record,omitempty"`
	Interaction *taskcoord.InteractionEvent `json:"interaction,omitempty"`
}

type operationEnvelope struct {
	kind        RequestKind
	digest      Digest
	transition  *TransitionRequest
	interaction *InteractionRequest
}

// Handler returns a no-store HTTP API. The enclosing http.Server must use a
// TLSConfig that verifies client certificates.
func (s *Ingress) Handler() (http.Handler, error) {
	if s.Store == nil {
		return nil, ErrMissingStore
	}
	if s.Policy.ReplayCache == nil {
		return nil, ErrMissingReplayCache
	}
	if strings.TrimSpace(s.Policy.Grant.ExpectedIssuer) == "" ||
		strings.TrimSpace(s.Policy.Grant.ExpectedAudience) == "" ||
		strings.TrimSpace(s.Policy.SessionBinding.ExpectedIssuer) == "" ||
		strings.TrimSpace(s.Policy.SessionBinding.ExpectedAudience) == "" ||
		s.Policy.Grant.ExpectedAudience != s.Policy.SessionBinding.ExpectedAudience {
		return nil, ErrMissingVerifierPolicy
	}
	if err := clients.ValidateJWTVerifyOptions(s.Policy.Grant); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid grant verifier: %w", err)
	}
	if err := clients.ValidateJWTVerifyOptions(s.Policy.SessionBinding); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid session verifier: %w", err)
	}
	if err := s.Policy.Identity.ValidateMode(); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: invalid identity policy: %w", err)
	}
	if s.Policy.Identity.Mode == identitypolicy.ModeDisabled ||
		s.Policy.Identity.SetMode == identitypolicy.SetModeContainsAll ||
		len(s.Policy.Identity.Expected.AuthorizationDetails) != 0 {
		return nil, ErrMissingVerifierPolicy
	}
	if err := schemas.PrepareHumanIngressValidator(); err != nil {
		return nil, fmt.Errorf("asbbinding ingress: prepare JSON validator: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+IngressChallengePath, s.handleChallenge)
	mux.HandleFunc("POST "+IngressExecutePath, s.handleExecute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		mux.ServeHTTP(w, r)
	}), nil
}

func (s *Ingress) handleChallenge(w http.ResponseWriter, r *http.Request) {
	state, leaf, err := verifiedTLSState(r)
	if err != nil {
		writeIngressError(w, http.StatusUnauthorized, err)
		return
	}
	var input ChallengeRequest
	if err := decodeIngressEnvelope(r.Body, &input); err != nil {
		writeIngressError(w, http.StatusBadRequest, err)
		return
	}
	operation, err := decodeOperation(input.Operation, input.Request)
	if err != nil {
		writeIngressError(w, http.StatusBadRequest, err)
		return
	}
	now := s.currentTime()
	challengeID, nonce, err := s.randomChallengeValues()
	if err != nil {
		writeIngressError(w, http.StatusInternalServerError, err)
		return
	}
	binding, err := BindingFromTLS(state, leaf, operation.digest, nonce)
	if err != nil {
		writeIngressError(w, http.StatusUnauthorized, err)
		return
	}
	entry := pendingChallenge{
		connectionKey: connectionKey(state), requestKind: operation.kind,
		digest: operation.digest, expiresAt: now.Add(s.challengeTTL()),
		expectedBinding: binding,
	}
	if err := s.putChallenge(challengeID, entry, now); err != nil {
		writeIngressError(w, http.StatusTooManyRequests, err)
		return
	}
	writeIngressJSON(w, http.StatusCreated, ChallengeResponse{
		ChallengeID: challengeID, Nonce: nonce, ExpiresAt: entry.expiresAt.Format(time.RFC3339Nano),
		RequestDigest: operation.digest.String(),
	})
}

func (s *Ingress) handleExecute(w http.ResponseWriter, r *http.Request) {
	state, _, err := verifiedTLSState(r)
	if err != nil {
		writeIngressError(w, http.StatusUnauthorized, err)
		return
	}
	var input ExecuteRequest
	if err := decodeIngressEnvelope(r.Body, &input); err != nil {
		writeIngressError(w, http.StatusBadRequest, err)
		return
	}
	operation, err := decodeOperation(input.Operation, input.Request)
	if err != nil {
		writeIngressError(w, http.StatusBadRequest, err)
		return
	}
	now := s.currentTime()
	challenge, err := s.takeChallenge(input.ChallengeID, connectionKey(state), operation.kind, operation.digest, now)
	if err != nil {
		writeIngressError(w, http.StatusUnauthorized, err)
		return
	}
	acceptedUntil := challenge.expiresAt
	if s.Policy.AcceptedUntil != nil {
		policyExpiry, err := s.Policy.AcceptedUntil(r.Context(), operation.kind, operation.digest)
		if err != nil {
			writeIngressError(w, http.StatusForbidden, err)
			return
		}
		if !policyExpiry.IsZero() && policyExpiry.Before(acceptedUntil) {
			acceptedUntil = policyExpiry
		}
	}
	evidence := Evidence{
		GrantJWT: input.GrantJWT, SessionBindingJWT: input.SessionBindingJWT,
		AcceptedUntil: acceptedUntil,
		Options: clients.SessionIdentityJWTOptions{
			Grant: s.Policy.Grant, SessionBinding: s.Policy.SessionBinding,
			Policy: s.Policy.Identity, ExpectedBinding: challenge.expectedBinding,
			ReplayCache: s.Policy.ReplayCache,
		},
	}
	profile := Profile{Participants: s.Store, Now: func() time.Time { return now }}
	switch operation.kind {
	case RequestKindAssignmentTransition:
		s.executeTransition(w, r, profile, *operation.transition, evidence)
	case RequestKindInteractionAppend:
		s.executeInteraction(w, r, profile, *operation.interaction, evidence)
	default:
		writeIngressError(w, http.StatusBadRequest, ErrUnsupportedOperationKind)
	}
}

func (s *Ingress) executeTransition(
	w http.ResponseWriter,
	r *http.Request,
	profile Profile,
	request TransitionRequest,
	evidence Evidence,
) {
	current, err := s.Store.LoadAssignment(r.Context(), request.AssignmentID)
	if err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	if current.TaskID != request.TaskID || current.Revision != request.ExpectedRevision {
		writeIngressError(w, http.StatusConflict, taskcoord.ErrRevisionConflict)
		return
	}
	transition, err := profile.Apply(r.Context(), current, request, evidence)
	if err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	if err := s.Store.CommitAssignment(r.Context(), request.ExpectedRevision, transition.Assignment, transition.Record); err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	writeIngressJSON(w, http.StatusOK, ExecuteResponse{
		Operation: OperationAssignmentTransition, Assignment: &transition.Assignment, Record: &transition.Record,
	})
}

func (s *Ingress) executeInteraction(
	w http.ResponseWriter,
	r *http.Request,
	profile Profile,
	request InteractionRequest,
	evidence Evidence,
) {
	current, err := s.Store.LoadAssignment(r.Context(), request.AssignmentID)
	if err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	if current.TaskID != request.TaskID {
		writeIngressError(w, http.StatusConflict, taskcoord.ErrRevisionConflict)
		return
	}
	event, err := profile.NewInteractionEvent(r.Context(), request, evidence)
	if err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	if err := s.Store.AppendInteractionEvent(r.Context(), event); err != nil {
		writeIngressError(w, statusForIngressError(err), err)
		return
	}
	writeIngressJSON(w, http.StatusOK, ExecuteResponse{Operation: OperationInteractionAppend, Interaction: &event})
}

func decodeOperation(kind string, raw json.RawMessage) (operationEnvelope, error) {
	if len(raw) == 0 {
		return operationEnvelope{}, errors.New("asbbinding ingress: missing operation request")
	}
	switch kind {
	case OperationAssignmentTransition:
		var request TransitionRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := TransitionDigest(request)
		return operationEnvelope{kind: RequestKindAssignmentTransition, digest: digest, transition: &request}, err
	case OperationInteractionAppend:
		var request InteractionRequest
		if err := decodeIngressJSON(bytes.NewReader(raw), &request); err != nil {
			return operationEnvelope{}, err
		}
		digest, err := InteractionDigest(request)
		return operationEnvelope{kind: RequestKindInteractionAppend, digest: digest, interaction: &request}, err
	default:
		return operationEnvelope{}, ErrUnsupportedOperationKind
	}
}

func verifiedTLSState(r *http.Request) (*tls.ConnectionState, *x509.Certificate, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 {
		return nil, nil, ErrTLSRequired
	}
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 ||
		len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil, nil, ErrTLSRequired
	}
	return r.TLS, r.TLS.PeerCertificates[0], nil
}

// BindingFromTLS derives the expected binding from a verified mTLS client and
// the current TLS 1.3 connection. It never accepts peer-provided hash values.
func BindingFromTLS(state *tls.ConnectionState, leaf *x509.Certificate, digest Digest, nonce string) (identitypolicy.Binding, error) {
	if state == nil || leaf == nil || strings.TrimSpace(nonce) == "" {
		return identitypolicy.Binding{}, ErrTLSRequired
	}
	contextBytes := RequestContext(digest)
	exported, err := state.ExportKeyingMaterial(
		eaattestation.ExporterLabelAttestation,
		contextBytes,
		eaattestation.ExportedAttestationValueLen,
	)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("asbbinding ingress: derive TLS exporter: %w", err)
	}
	leafBytes, err := eaattestation.PublicKeyBytes(leaf)
	if err != nil {
		return identitypolicy.Binding{}, fmt.Errorf("asbbinding ingress: encode client public key: %w", err)
	}
	leafHash := sha256.Sum256(leafBytes)
	exporterHash := sha256.Sum256(exported)
	return identitypolicy.Binding{
		LeafPublicKeySHA256:  hex.EncodeToString(leafHash[:]),
		TLSExporterSHA256:    hex.EncodeToString(exporterHash[:]),
		RequestContextSHA256: RequestContextSHA256(digest),
		Nonce:                nonce,
	}, nil
}

func connectionKey(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	exported, err := state.ExportKeyingMaterial("EXPORTER-ASB-TaskCoord-connection-v1", nil, 32)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(exported)
	return hex.EncodeToString(sum[:])
}

func (s *Ingress) putChallenge(id string, entry pendingChallenge, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]pendingChallenge)
		s.connections = make(map[string]int)
	}
	s.pruneLocked(now)
	if entry.connectionKey == "" {
		return ErrTLSRequired
	}
	if s.connections[entry.connectionKey] >= s.maxPending() {
		return ErrChallengeLimit
	}
	s.pending[id] = entry
	s.connections[entry.connectionKey]++
	return nil
}

func (s *Ingress) takeChallenge(id, connection string, kind RequestKind, digest Digest, now time.Time) (pendingChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	entry, ok := s.pending[id]
	if !ok {
		return pendingChallenge{}, ErrUnknownChallenge
	}
	delete(s.pending, id)
	s.connections[entry.connectionKey]--
	if entry.connectionKey != connection || connection == "" {
		return pendingChallenge{}, ErrChallengeConnection
	}
	if entry.requestKind != kind || entry.digest != digest {
		return pendingChallenge{}, ErrChallengeRequest
	}
	if !now.Before(entry.expiresAt) {
		return pendingChallenge{}, ErrUnknownChallenge
	}
	return entry, nil
}

func (s *Ingress) pruneLocked(now time.Time) {
	for id, entry := range s.pending {
		if !now.Before(entry.expiresAt) {
			delete(s.pending, id)
			s.connections[entry.connectionKey]--
		}
	}
}

func (s *Ingress) randomChallengeValues() (string, string, error) {
	source := s.Random
	if source == nil {
		source = rand.Reader
	}
	var challenge [challengeBytes]byte
	var nonce [challengeBytes]byte
	if _, err := io.ReadFull(source, challenge[:]); err != nil {
		return "", "", fmt.Errorf("asbbinding ingress: generate challenge ID: %w", err)
	}
	if _, err := io.ReadFull(source, nonce[:]); err != nil {
		return "", "", fmt.Errorf("asbbinding ingress: generate nonce: %w", err)
	}
	return hex.EncodeToString(challenge[:]), hex.EncodeToString(nonce[:]), nil
}

func (s *Ingress) currentTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Ingress) challengeTTL() time.Duration {
	if s.ChallengeTTL > 0 {
		return s.ChallengeTTL
	}
	return 2 * time.Minute
}

func (s *Ingress) maxPending() int {
	if s.MaxPending > 0 {
		return s.MaxPending
	}
	return 8
}

func decodeIngressJSON(reader io.Reader, target any) error {
	raw, err := readIngressJSON(reader)
	if err != nil {
		return err
	}
	return decodeIngressJSONBytes(raw, target)
}

func decodeIngressEnvelope(reader io.Reader, target any) error {
	raw, err := readIngressJSON(reader)
	if err != nil {
		return err
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	if err := schemas.ValidateHumanIngressJSON(raw); err != nil {
		return fmt.Errorf("asbbinding ingress: %w", err)
	}
	return decodeIngressJSONBytes(raw, target)
}

func readIngressJSON(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("asbbinding ingress: missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, taskcoord.MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("asbbinding ingress: read JSON: %w", err)
	}
	if len(raw) > taskcoord.MaxDocumentBytes {
		return nil, fmt.Errorf("asbbinding ingress: JSON exceeds %d bytes", taskcoord.MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("asbbinding ingress: JSON is not valid UTF-8")
	}
	return raw, nil
}

func decodeIngressJSONBytes(raw []byte, target any) error {
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("asbbinding ingress: decode JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("asbbinding ingress: trailing JSON value")
	}
	return nil
}

func writeIngressJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func writeIngressError(w http.ResponseWriter, status int, err error) {
	writeIngressJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: err.Error()})
}

func statusForIngressError(err error) int {
	switch {
	case errors.Is(err, taskcoord.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, taskcoord.ErrRevisionConflict),
		errors.Is(err, taskcoord.ErrEventConflict),
		errors.Is(err, taskcoord.ErrAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, ErrInvalidRequest):
		return http.StatusBadRequest
	default:
		return http.StatusForbidden
	}
}
