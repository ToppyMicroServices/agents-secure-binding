// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const (
	// HTTPExporterLabel separates this profile from other ASB TLS consumers.
	HTTPExporterLabel = "EXPORTER-ASB-LeastPrivilege-HTTP-v1"
	maxHTTPBodyBytes  = 1 << 20
)

// HTTPConfig configures the direct mTLS endpoint. Registry state is process
// local: a restart invalidates outstanding challenges. No challenge is durable
// execution authority; Service still commits ASB replay protection durably.
type HTTPConfig struct {
	Service       *Service
	MaxChallenges int
	ChallengeTTL  time.Duration
}

type HTTPChallengeRequest struct {
	Mode      string    `json:"mode"`
	Operation Operation `json:"operation"`
}

// HTTPChallenge exposes verifier-derived values for the client to sign. The
// followup never accepts this object back as trusted transport evidence.
// ChallengeID is the same nonce as Binding.VerifierNonce; send it in the
// followup's challenge_id field together with the signed proof and operation.
type HTTPChallenge struct {
	ChallengeID                 string                   `json:"challenge_id"`
	Mode                        string                   `json:"mode"`
	Binding                     identitypolicy.BindingV2 `json:"binding"`
	EndpointCredentialExpiresAt time.Time                `json:"endpoint_credential_expires_at"`
	ExpiresAt                   time.Time                `json:"expires_at"`
}

type HTTPAuthorizeRequest struct {
	ChallengeID string      `json:"challenge_id"`
	Operation   Operation   `json:"operation"`
	Proof       Proof       `json:"proof"`
	Candidate   lp.Solution `json:"candidate"`
}
type HTTPExecuteRequest struct {
	ChallengeID string        `json:"challenge_id"`
	Operation   Operation     `json:"operation"`
	Proof       Proof         `json:"proof"`
	Capability  lp.Capability `json:"capability"`
}
type HTTPReconcileRequest struct {
	ChallengeID string    `json:"challenge_id"`
	Operation   Operation `json:"operation"`
	Proof       Proof     `json:"proof"`
}
type HTTPResponse struct {
	Capability *lp.Capability      `json:"capability,omitempty"`
	Execution  *lp.ExecutionRecord `json:"execution,omitempty"`
	Error      string              `json:"error,omitempty"`
	State      lp.ExecutionState   `json:"state,omitempty"`
}

type httpChallengeEntry struct {
	mode      string
	transport Transport
}
type httpHandler struct {
	service    *Service
	capacity   int
	ttl        time.Duration
	mu         sync.Mutex
	challenges map[string]httpChallengeEntry
}

// NewHTTPHandler serves POST /challenge, /authorize, /execute and /reconcile.
// The operator must attach it directly to an http.Server configured with TLS
// 1.3, ClientAuth=tls.RequireAndVerifyClientCert, trusted ClientCAs, and bounded
// read/header/write/idle timeouts. Do not terminate TLS at a proxy or replace
// Request.TLS from headers. This handler reads only the actual TLS connection.
// Clients must retain the same connection between challenge and followup.
// There is no HTTP policy-installation or arbitrary completion endpoint.
func NewHTTPHandler(c HTTPConfig) (http.Handler, error) {
	if c.Service == nil || c.Service.clock == nil || c.Service.store == nil || c.Service.policies == nil {
		return nil, ErrPolicy
	}
	if c.MaxChallenges == 0 {
		c.MaxChallenges = 1024
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = 30 * time.Second
	}
	if c.MaxChallenges < 1 || c.MaxChallenges > 10_000 || c.ChallengeTTL < time.Second || c.ChallengeTTL > time.Minute {
		return nil, ErrPolicy
	}
	return &httpHandler{service: c.Service, capacity: c.MaxChallenges, ttl: c.ChallengeTTL, challenges: make(map[string]httpChallengeEntry)}, nil
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTP(w, http.StatusMethodNotAllowed, HTTPResponse{Error: "method_not_allowed"})
		return
	}
	if r.URL.RawQuery != "" {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	if _, _, err := verifiedHTTPBinding(r, "", h.service.clock()); err != nil {
		writeHTTP(w, http.StatusForbidden, HTTPResponse{Error: "mutual_tls_required"})
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeHTTP(w, http.StatusUnsupportedMediaType, HTTPResponse{Error: "json_required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHTTPBodyBytes)
	switch r.URL.Path {
	case "/challenge":
		h.challenge(w, r)
	case "/authorize":
		h.authorize(w, r)
	case "/execute":
		h.execute(w, r)
	case "/reconcile":
		h.reconcile(w, r)
	default:
		writeHTTP(w, http.StatusNotFound, HTTPResponse{Error: "not_found"})
	}
}

func (h *httpHandler) challenge(w http.ResponseWriter, r *http.Request) {
	var input HTTPChallengeRequest
	if err := decodeHTTP(r, &input); err != nil {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	digest, err := ContextDigest(input.Mode, input.Operation)
	if err != nil {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	now := h.service.clock()
	binding, endpointExpiry, err := verifiedHTTPBinding(r, digest, now)
	if err != nil {
		writeHTTP(w, http.StatusForbidden, HTTPResponse{Error: "mutual_tls_required"})
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		writeHTTP(w, http.StatusServiceUnavailable, HTTPResponse{Error: "unavailable"})
		return
	}
	id := base64.RawURLEncoding.EncodeToString(nonce)
	expiry := now.Add(h.ttl)
	if endpointExpiry.Before(expiry) {
		expiry = endpointExpiry
	}
	binding.VerifierNonce = id
	binding.IssuedAt, binding.ExpiresAt = now.UTC(), expiry.UTC()
	entry := httpChallengeEntry{mode: input.Mode, transport: Transport{Binding: binding, EndpointCredentialExpiresAt: endpointExpiry, ChallengeExpiresAt: expiry}}
	h.mu.Lock()
	for key, existing := range h.challenges {
		if !now.Before(existing.transport.ChallengeExpiresAt) {
			delete(h.challenges, key)
		}
	}
	if len(h.challenges) >= h.capacity {
		h.mu.Unlock()
		writeHTTP(w, http.StatusServiceUnavailable, HTTPResponse{Error: "unavailable"})
		return
	}
	if _, exists := h.challenges[id]; exists {
		h.mu.Unlock()
		writeHTTP(w, http.StatusServiceUnavailable, HTTPResponse{Error: "unavailable"})
		return
	}
	h.challenges[id] = entry
	h.mu.Unlock()
	writeHTTP(w, http.StatusOK, HTTPChallenge{ChallengeID: id, Mode: input.Mode, Binding: binding, EndpointCredentialExpiresAt: endpointExpiry, ExpiresAt: expiry})
}

func (h *httpHandler) take(r *http.Request, id, mode string, op Operation) (Transport, error) {
	if len(id) != 43 {
		return Transport{}, ErrTransport
	}
	digest, err := ContextDigest(mode, op)
	if err != nil {
		return Transport{}, err
	}
	now := h.service.clock()
	actual, expiry, err := verifiedHTTPBinding(r, digest, now)
	if err != nil {
		return Transport{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, ok := h.challenges[id]
	if !ok {
		return Transport{}, lp.ErrReplay
	}
	if !now.Before(entry.transport.ChallengeExpiresAt) {
		delete(h.challenges, id)
		return Transport{}, lp.ErrExpired
	}
	want := entry.transport.Binding
	if now.Before(want.IssuedAt) || entry.mode != mode || want.BindingContextSHA256 != digest ||
		want.AcceptedEndpointSPKISHA256 != actual.AcceptedEndpointSPKISHA256 || want.TLSExporterSHA256 != actual.TLSExporterSHA256 ||
		!entry.transport.EndpointCredentialExpiresAt.Equal(expiry) {
		return Transport{}, ErrTransport
	}
	// Consume before signature verification. A malformed signed submission on
	// the correct connection cannot reuse this challenge for another attempt.
	delete(h.challenges, id)
	return entry.transport, nil
}

func (h *httpHandler) authorize(w http.ResponseWriter, r *http.Request) {
	var input HTTPAuthorizeRequest
	if err := decodeHTTP(r, &input); err != nil {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	transport, err := h.take(r, input.ChallengeID, "authorize", input.Operation)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	capability, err := h.service.Authorize(r.Context(), input.Operation, input.Proof, transport, input.Candidate)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeHTTP(w, http.StatusOK, HTTPResponse{Capability: &capability})
}

func (h *httpHandler) execute(w http.ResponseWriter, r *http.Request) {
	var input HTTPExecuteRequest
	if err := decodeHTTP(r, &input); err != nil {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	transport, err := h.take(r, input.ChallengeID, "execute", input.Operation)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	result, err := h.service.Execute(r.Context(), input.Operation, input.Proof, transport, input.Capability)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeHTTP(w, http.StatusOK, HTTPResponse{Execution: &result})
}

func (h *httpHandler) reconcile(w http.ResponseWriter, r *http.Request) {
	var input HTTPReconcileRequest
	if err := decodeHTTP(r, &input); err != nil {
		writeHTTP(w, http.StatusBadRequest, HTTPResponse{Error: "invalid_request"})
		return
	}
	transport, err := h.take(r, input.ChallengeID, "reconcile", input.Operation)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	result, err := h.service.Reconcile(r.Context(), input.Operation, input.Proof, transport)
	if err != nil {
		writeHTTPError(w, err)
		return
	}
	writeHTTP(w, http.StatusOK, HTTPResponse{Execution: &result})
}

func verifiedHTTPBinding(r *http.Request, digest string, now time.Time) (identitypolicy.BindingV2, time.Time, error) {
	if r == nil || r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || now.IsZero() ||
		len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return identitypolicy.BindingV2{}, time.Time{}, ErrTransport
	}
	peer := r.TLS.PeerCertificates[0]
	if peer == nil || r.TLS.VerifiedChains[0][0] == nil || !bytes.Equal(peer.Raw, r.TLS.VerifiedChains[0][0].Raw) {
		return identitypolicy.BindingV2{}, time.Time{}, ErrTransport
	}
	expiry := peer.NotAfter
	for _, certificate := range r.TLS.VerifiedChains[0] {
		if certificate == nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return identitypolicy.BindingV2{}, time.Time{}, ErrTransport
		}
		if certificate.NotAfter.Before(expiry) {
			expiry = certificate.NotAfter
		}
	}
	exported, err := r.TLS.ExportKeyingMaterial(HTTPExporterLabel, []byte(digest), 32)
	if err != nil {
		return identitypolicy.BindingV2{}, time.Time{}, ErrTransport
	}
	spki := sha256.Sum256(peer.RawSubjectPublicKeyInfo)
	exporter := sha256.Sum256(exported)
	return identitypolicy.BindingV2{EndpointRole: "client-tls-endpoint", InteractionType: "agent-to-tool", AcceptedEndpointSPKISHA256: "sha256:" + hex.EncodeToString(spki[:]), TLSExporterSHA256: "sha256:" + hex.EncodeToString(exporter[:]), BindingContextSHA256: digest}, expiry.UTC(), nil
}

func decodeHTTP(r *http.Request, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxHTTPBodyBytes || !boundedHTTPDepth(raw) {
		return ErrTransport
	}
	if err := strictjson.ValidateDocument(raw, maxHTTPBodyBytes); err != nil {
		return err
	}
	// encoding/json accepts case-insensitive field aliases. Require exact JSON
	// member spellings so an alias cannot bypass duplicate/unknown-field checks.
	if err := exactHTTPFields(raw, reflect.TypeOf(out)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func boundedHTTPDepth(raw []byte) bool {
	depth := 0
	quoted, escaped := false, false
	for _, b := range raw {
		if quoted {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				quoted = false
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > 32 {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}

func exactHTTPFields(raw json.RawMessage, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if typ.Kind() == reflect.Slice {
			return nil
		}
		return ErrTransport
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return err
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok {
				return ErrTransport
			}
			if err := exactHTTPFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactHTTPFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeHTTPError(w http.ResponseWriter, err error) {
	status, body := http.StatusForbidden, HTTPResponse{Error: "authorization_denied"}
	switch {
	case errors.Is(err, lp.ErrOutcomeUnknown):
		status = http.StatusConflict
		body = HTTPResponse{Error: "outcome_unknown", State: lp.ExecutionUnknown}
	case errors.Is(err, lp.ErrReplay):
		status = http.StatusConflict
		body.Error = "replay"
	case errors.Is(err, lp.ErrHumanRequired):
		body.Error = "human_approval_required"
	case errors.Is(err, lp.ErrExpired):
		body.Error = "authorization_expired"
	case errors.Is(err, lp.ErrStoreUnavailable), errors.Is(err, lp.ErrCapacity):
		status = http.StatusServiceUnavailable
		body.Error = "unavailable"
	}
	writeHTTP(w, status, body)
}

func writeHTTP(w http.ResponseWriter, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		status = http.StatusInternalServerError
		raw = []byte(`{"error":"unavailable"}`)
	}
	raw = append(raw, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(raw); err != nil {
		// A disconnected peer must recover through a fresh challenge and the
		// durable operation record. Never append another HTTP response here.
		return
	}
}
