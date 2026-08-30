// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package protectedchange is an HTTP consumer of the ASB production verifier.
// It applies a tenant configuration change only after the exact request is
// bound to the accepted TLS session and every production gate succeeds.
package protectedchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const (
	IdentityGrantHeader  = "ASB-Identity-Grant"
	SessionBindingHeader = "ASB-Session-Binding"
	AttestationHeader    = "ASB-Attestation-Result"
	ChangePath           = "/v1/changes"
	maxRequestBytes      = 32 << 10
)

var (
	ErrInvalidChange      = errors.New("protected change: invalid request")
	ErrMissingTLSIdentity = errors.New("protected change: missing authenticated TLS peer")
	ErrMissingNonce       = errors.New("protected change: missing verifier nonce")
	ErrChangeConflict     = errors.New("protected change: change identifier conflict")
)

// ChangeRequest is the protected application action.
type ChangeRequest struct {
	ChangeID string `json:"change_id"`
	Tenant   string `json:"tenant"`
	Setting  string `json:"setting"`
	Enabled  bool   `json:"enabled"`
}

type canonicalChange struct {
	Profile  string `json:"profile"`
	Method   string `json:"method"`
	Resource string `json:"resource"`
	ChangeID string `json:"change_id"`
	Enabled  bool   `json:"enabled"`
}

// NonceSource returns the verifier-issued nonce for the exact change.
type NonceSource interface {
	ExpectedNonce(context.Context, ChangeRequest) (string, error)
}

// ChangeStore durably applies an accepted change. Implementations must be
// idempotent for an identical ChangeID and reject conflicting reuse.
type ChangeStore interface {
	Apply(context.Context, ChangeRequest, production.AcceptedIdentity) error
}

// Application is the protected-change HTTP consumer.
type Application struct {
	Profile         production.Profile
	SoftwareProfile *production.SoftwareOnlyProfile
	Nonces          NonceSource
	Store           ChangeStore
	ExpectedAgent   string
	AuditFailure    func(context.Context, error)
}

// ServeHTTP accepts only the protected change endpoint.
func (a Application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != ChangePath {
		http.NotFound(w, r)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	change, err := decodeChange(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if a.Nonces == nil || a.Store == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := a.Nonces.ExpectedNonce(r.Context(), change)
	if err != nil || strings.TrimSpace(nonce) == "" {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	actionContext, err := CanonicalActionContext(change)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(r.Header.Get(IdentityGrantHeader)) > maxRequestBytes || len(r.Header.Get(SessionBindingHeader)) > maxRequestBytes {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	accepted, err := a.verifyIdentity(r, change, actionContext, nonce)
	if err != nil {
		if a.AuditFailure != nil {
			a.AuditFailure(r.Context(), err)
		}
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	if err := a.Store.Apply(r.Context(), change, accepted); err != nil {
		http.Error(w, "change not applied", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a Application) verifyIdentity(r *http.Request, change ChangeRequest, actionContext []byte, nonce string) (production.AcceptedIdentity, error) {
	if a.SoftwareProfile != nil {
		if hasAttestedProfileConfiguration(a.Profile) || r.Header.Get(AttestationHeader) != "" {
			return production.AcceptedIdentity{}, production.ErrUnexpectedAttestationBinding
		}
		expectedBinding, err := production.SoftwareBindingFromTLS(r.TLS, r.TLS.PeerCertificates[0], actionContext, nonce)
		if err != nil {
			return production.AcceptedIdentity{}, err
		}
		profile := *a.SoftwareProfile
		if !usesProtectedChangeSigningAuthorities(profile.GrantAuthority, profile.BindingAuthority) {
			return production.AcceptedIdentity{}, production.ErrInvalidAuthority
		}
		profile.IdentityPolicy = ExpectedPolicy(change, a.ExpectedAgent)
		return profile.Verify(r.Context(), production.SoftwareOnlyVerifyRequest{
			GrantJWT:          r.Header.Get(IdentityGrantHeader),
			SessionBindingJWT: r.Header.Get(SessionBindingHeader),
			ExpectedBinding:   expectedBinding,
		})
	}

	expectedBinding, err := production.BindingFromTLS(r.TLS, r.TLS.PeerCertificates[0], actionContext, nonce)
	if err != nil {
		return production.AcceptedIdentity{}, err
	}
	attestation, err := decodeAttestation(r.Header.Get(AttestationHeader))
	if err != nil {
		return production.AcceptedIdentity{}, err
	}
	profile := a.Profile
	if !usesProtectedChangeSigningAuthorities(profile.GrantAuthority, profile.BindingAuthority) {
		return production.AcceptedIdentity{}, production.ErrInvalidAuthority
	}
	profile.IdentityPolicy = ExpectedPolicy(change, a.ExpectedAgent)
	return profile.Verify(r.Context(), production.VerifyRequest{
		GrantJWT:          r.Header.Get(IdentityGrantHeader),
		SessionBindingJWT: r.Header.Get(SessionBindingHeader),
		ExpectedBinding:   expectedBinding,
		Attestation:       attestation,
	})
}

// CanonicalActionContext returns the exact bytes bound into the TLS exporter
// and request-context digest for one protected change.
func CanonicalActionContext(change ChangeRequest) ([]byte, error) {
	if err := validateChange(change); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalChange{
		Profile:  "asb.protected-change/v1",
		Method:   http.MethodPost,
		Resource: changeResource(change),
		ChangeID: change.ChangeID,
		Enabled:  change.Enabled,
	})
}

// ExpectedPolicy constructs verifier-local D3-D6 policy for one action.
func ExpectedPolicy(change ChangeRequest, agent string) identitypolicy.Policy {
	return identitypolicy.Policy{
		Mode:    identitypolicy.ModeRequired,
		SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service:              "protected-change",
			Agent:                agent,
			TaskID:               change.ChangeID,
			IntentRef:            "change:intent:apply",
			CapabilityRef:        "change:capability:write",
			Scopes:               []string{"change.write"},
			Resources:            []string{changeResource(change)},
			AuthorizationDetails: []string{"change:set-enabled"},
		},
	}
}

// MemoryChangeStore is a concurrency-safe idempotent store used by the
// reference consumer and its integration tests.
type MemoryChangeStore struct {
	mu      sync.Mutex
	records map[string]AppliedChange
}

// AppliedChange is the durable outcome projection for one accepted change.
// Production stores should persist this identity projection with the action so
// retries cannot silently change the actor attributed to an existing outcome.
type AppliedChange struct {
	Change   ChangeRequest
	Identity production.AcceptedIdentity
}

// NewMemoryChangeStore returns an empty change store.
func NewMemoryChangeStore() *MemoryChangeStore {
	return &MemoryChangeStore{records: make(map[string]AppliedChange)}
}

// Apply records an accepted change exactly once.
func (s *MemoryChangeStore) Apply(_ context.Context, change ChangeRequest, identity production.AcceptedIdentity) error {
	if s == nil {
		return ErrChangeConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.records[change.ChangeID]; ok {
		if existing.Change == change && acceptedIdentityEqual(existing.Identity, identity) {
			return nil
		}
		return ErrChangeConflict
	}
	s.records[change.ChangeID] = AppliedChange{Change: change, Identity: cloneAcceptedIdentity(identity)}
	return nil
}

// Lookup returns an applied change.
func (s *MemoryChangeStore) Lookup(changeID string) (ChangeRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[changeID]
	return record.Change, ok
}

// LookupApplied returns the action and accepted identity stored for one outcome.
func (s *MemoryChangeStore) LookupApplied(changeID string) (AppliedChange, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[changeID]
	record.Identity = cloneAcceptedIdentity(record.Identity)
	return record, ok
}

func acceptedIdentityEqual(left, right production.AcceptedIdentity) bool {
	return left.Issuer == right.Issuer &&
		left.Agent == right.Agent &&
		left.TaskID == right.TaskID &&
		left.DelegationID == right.DelegationID &&
		left.IntentRef == right.IntentRef &&
		left.CapabilityRef == right.CapabilityRef &&
		slices.Equal(left.Scopes, right.Scopes) &&
		slices.Equal(left.Resources, right.Resources) &&
		slices.Equal(left.AuthorizationDetails, right.AuthorizationDetails)
}

func cloneAcceptedIdentity(identity production.AcceptedIdentity) production.AcceptedIdentity {
	identity.Scopes = append([]string(nil), identity.Scopes...)
	identity.Resources = append([]string(nil), identity.Resources...)
	identity.AuthorizationDetails = append([]string(nil), identity.AuthorizationDetails...)
	return identity
}

func decodeChange(body io.ReadCloser) (ChangeRequest, error) {
	defer body.Close()
	raw, err := io.ReadAll(io.LimitReader(body, maxRequestBytes+1))
	if err != nil || len(raw) > maxRequestBytes {
		return ChangeRequest{}, ErrInvalidChange
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var change ChangeRequest
	if err := decoder.Decode(&change); err != nil {
		return ChangeRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ChangeRequest{}, ErrInvalidChange
	}
	if err := validateChange(change); err != nil {
		return ChangeRequest{}, err
	}
	return change, nil
}

func decodeAttestation(value string) (production.AttestationResult, error) {
	if len(value) == 0 || len(value) > base64.RawURLEncoding.EncodedLen(maxRequestBytes) {
		return production.AttestationResult{}, production.ErrInvalidAttestationResult
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes {
		return production.AttestationResult{}, production.ErrInvalidAttestationResult
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var result production.AttestationResult
	if err := decoder.Decode(&result); err != nil {
		return production.AttestationResult{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return production.AttestationResult{}, production.ErrInvalidAttestationResult
	}
	return result, nil
}

func validateChange(change ChangeRequest) error {
	for _, value := range []string{change.ChangeID, change.Tenant, change.Setting} {
		if value == "" || value != strings.TrimSpace(value) || len(value) > 128 {
			return ErrInvalidChange
		}
		for _, r := range value {
			if !isIdentifierRune(r) {
				return ErrInvalidChange
			}
		}
	}
	return nil
}

func isIdentifierRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
}

func usesProtectedChangeSigningAuthorities(grant production.AuthorityPolicy, binding production.AuthorityPolicy) bool {
	return len(grant.ValidMethods) == 1 && grant.ValidMethods[0] == "EdDSA" &&
		len(binding.ValidMethods) == 1 && binding.ValidMethods[0] == "EdDSA"
}

func hasAttestedProfileConfiguration(profile production.Profile) bool {
	return authorityConfigured(profile.GrantAuthority) || authorityConfigured(profile.BindingAuthority) ||
		profile.IdentityPolicy.Enabled() || profile.Attestation != nil || profile.ReplayCache != nil || profile.Now != nil
}

func authorityConfigured(authority production.AuthorityPolicy) bool {
	return authority.ExpectedIssuer != "" || authority.ExpectedAudience != "" ||
		len(authority.ValidMethods) != 0 || authority.TrustSource != nil
}

func changeResource(change ChangeRequest) string {
	return fmt.Sprintf("config://%s/%s", change.Tenant, change.Setting)
}
