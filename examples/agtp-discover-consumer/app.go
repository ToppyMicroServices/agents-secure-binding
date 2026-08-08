// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package agtpdiscover is an ASB-protected consumer for AGTP population
// discovery. It verifies the caller before forwarding an exact DISCOVER query
// to a locally configured AGTP coordinator.
package agtpdiscover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/production"
)

const (
	IdentityGrantHeader  = "ASB-Identity-Grant"
	SessionBindingHeader = "ASB-Session-Binding"
	DiscoverPath         = "/v1/discover"
	PopulationPath       = "/population"
	maxRequestBytes      = 32 << 10
	maxCapabilityBytes   = 64
)

var (
	ErrInvalidQuery       = errors.New("agtp discover: invalid query")
	ErrMissingTLSIdentity = errors.New("agtp discover: missing authenticated TLS peer")
	ErrMissingNonce       = errors.New("agtp discover: missing verifier nonce")
	ErrUpstream           = errors.New("agtp discover: upstream failure")
)

// Query is the exact AGTP population query authorized by ASB.
type Query struct {
	Capability string `json:"capability"`
	Limit      int    `json:"limit"`
}

type canonicalQuery struct {
	Profile    string `json:"profile"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Capability string `json:"capability"`
	Limit      int    `json:"limit"`
}

// Result is the upstream AGTP response. Body remains byte-identical so an
// upstream response signature can still be checked by the caller.
type Result struct {
	StatusCode int
	StatusText string
	Body       []byte
}

// Upstream executes one already-authorized AGTP query.
type Upstream interface {
	Discover(context.Context, Query) (Result, error)
}

// NonceSource returns the verifier-issued nonce for the exact query.
type NonceSource interface {
	ExpectedNonce(context.Context, Query) (string, error)
}

// Application verifies ASB identity and then forwards DISCOVER to Upstream.
// This local reference consumer uses the ASB software-only profile: mTLS,
// session/action binding, local policy, freshness, and replay are required,
// while hardware attestation is deliberately outside this example.
type Application struct {
	Profile       production.SoftwareOnlyProfile
	Nonces        NonceSource
	Upstream      Upstream
	ExpectedAgent string
	AuditFailure  func(context.Context, error)
}

// ServeHTTP accepts the local ASB-protected discovery endpoint.
func (a Application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != DiscoverPath {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	query, err := decodeQuery(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if a.Nonces == nil || a.Upstream == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := a.Nonces.ExpectedNonce(r.Context(), query)
	if err != nil || strings.TrimSpace(nonce) == "" {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	actionContext, err := CanonicalActionContext(query)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(r.Header.Get(IdentityGrantHeader)) > maxRequestBytes || len(r.Header.Get(SessionBindingHeader)) > maxRequestBytes {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	expectedBinding, err := production.SoftwareBindingFromTLS(
		r.TLS,
		r.TLS.PeerCertificates[0],
		actionContext,
		nonce,
	)
	if err != nil {
		a.authenticationFailure(w, r, err)
		return
	}
	profile := a.Profile
	if !usesDiscoverSigningAuthorities(profile.GrantAuthority, profile.BindingAuthority) {
		a.authenticationFailure(w, r, production.ErrInvalidAuthority)
		return
	}
	profile.IdentityPolicy = ExpectedPolicy(query, a.ExpectedAgent)
	if _, err := profile.Verify(r.Context(), production.SoftwareOnlyVerifyRequest{
		GrantJWT:          r.Header.Get(IdentityGrantHeader),
		SessionBindingJWT: r.Header.Get(SessionBindingHeader),
		ExpectedBinding:   expectedBinding,
	}); err != nil {
		a.authenticationFailure(w, r, err)
		return
	}

	result, err := a.Upstream.Discover(r.Context(), query)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

func (a Application) authenticationFailure(w http.ResponseWriter, r *http.Request, err error) {
	if a.AuditFailure != nil {
		a.AuditFailure(r.Context(), err)
	}
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}

// CanonicalActionContext returns the exact bytes bound into the TLS exporter
// and request-context digest for one DISCOVER query.
func CanonicalActionContext(query Query) ([]byte, error) {
	if err := validateQuery(query); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalQuery{
		Profile:    "asb.agtp-discover/v1",
		Method:     "DISCOVER",
		Path:       PopulationPath,
		Capability: query.Capability,
		Limit:      query.Limit,
	})
}

// ExpectedPolicy constructs verifier-local D3, D4, and D6 policy for one
// capability query. The identifiers below form the example's local canonical
// namespace; peers cannot substitute aliases during acceptance.
func ExpectedPolicy(query Query, agent string) identitypolicy.Policy {
	return identitypolicy.Policy{
		Mode:    identitypolicy.ModeRequired,
		SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L6: true},
		Expected: identitypolicy.Values{
			Service:       "agtp-discovery",
			Agent:         agent,
			CapabilityRef: capabilityReference(query.Capability),
			OntologyID:    "agtp:capability-method:v1",
			Scopes:        []string{"agtp.discover"},
			Resources:     []string{"agtp:/population"},
		},
	}
}

func decodeQuery(body io.ReadCloser) (Query, error) {
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, maxRequestBytes+1))
	if err != nil || len(raw) > maxRequestBytes {
		return Query{}, ErrInvalidQuery
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var query Query
	if err := decoder.Decode(&query); err != nil {
		return Query{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Query{}, ErrInvalidQuery
	}
	if err := validateQuery(query); err != nil {
		return Query{}, err
	}
	return query, nil
}

func validateQuery(query Query) error {
	if query.Capability == "" || len(query.Capability) > maxCapabilityBytes || query.Limit < 1 || query.Limit > 100 {
		return ErrInvalidQuery
	}
	for _, r := range query.Capability {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return ErrInvalidQuery
		}
	}
	return nil
}

func capabilityReference(capability string) string {
	return "agtp:capability:" + capability
}

func usesDiscoverSigningAuthorities(grant production.AuthorityPolicy, binding production.AuthorityPolicy) bool {
	return len(grant.ValidMethods) == 1 && grant.ValidMethods[0] == "EdDSA" &&
		len(binding.ValidMethods) == 1 && binding.ValidMethods[0] == "EdDSA"
}
