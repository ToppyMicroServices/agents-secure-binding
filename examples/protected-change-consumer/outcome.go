// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package protectedchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const OutcomePath = "/v1/changes/outcome"

// OutcomeStore reads the receipt of an exact change for its original Actor.
// A missing receipt is not evidence that an in-flight request cannot commit.
type OutcomeStore interface {
	Outcome(context.Context, ChangeRequest, production.AcceptedIdentity) (bool, error)
}

// OutcomeApplication performs a separately authorized, one-shot outcome lookup.
// Nonces and grant issuance for this endpoint belong to the verifier/operator;
// its change.read proof cannot be reused as a change.write proof.
type OutcomeApplication struct {
	Verifier Application
	Store    OutcomeStore
}

// ServeHTTP exposes historical receipt state only after fresh ASB acceptance.
func (a OutcomeApplication) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != OutcomePath {
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
	if a.Verifier.Nonces == nil || a.Store == nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	nonce, err := a.Verifier.Nonces.ExpectedNonce(r.Context(), change)
	if err == nil && strings.TrimSpace(nonce) == "" {
		err = ErrMissingNonce
	}
	if err != nil || strings.TrimSpace(nonce) == "" {
		if err != nil {
			a.Verifier.audit(r.Context(), fmt.Errorf("outcome nonce source: %w", err))
		}
		if err != nil && !errors.Is(err, ErrMissingNonce) {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
		}
		return
	}
	if len(r.Header.Get(IdentityGrantHeader)) > maxRequestBytes || len(r.Header.Get(SessionBindingHeader)) > maxRequestBytes {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	actionContext, err := CanonicalOutcomeContext(change)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	accepted, err := a.Verifier.verifyPolicy(r, actionContext, nonce, ExpectedOutcomePolicy(change, a.Verifier.ExpectedAgent))
	if err != nil {
		a.Verifier.audit(r.Context(), err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	found, err := a.Store.Outcome(r.Context(), change, accepted)
	if err != nil {
		a.Verifier.audit(r.Context(), fmt.Errorf("lookup outcome: %w", err))
		if errors.Is(err, ErrChangeConflict) {
			http.Error(w, "outcome unavailable", http.StatusNotFound)
		} else {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	state := "NOT_RECORDED"
	if found {
		state = "APPLIED"
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		State string `json:"state"`
	}{State: state}); err != nil {
		a.Verifier.audit(r.Context(), fmt.Errorf("write outcome: %w", err))
	}
}

// CanonicalOutcomeContext binds the lookup operation and full original change.
func CanonicalOutcomeContext(change ChangeRequest) ([]byte, error) {
	if err := validateChange(change); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalChange{
		Profile:  "asb.protected-change-outcome/v1",
		Method:   http.MethodPost,
		Resource: changeResource(change),
		ChangeID: change.ChangeID,
		Enabled:  change.Enabled,
	})
}

// ExpectedOutcomePolicy requires a grant that explicitly authorizes reading an
// outcome for this task and resource, rather than executing the original change.
func ExpectedOutcomePolicy(change ChangeRequest, agent string) identitypolicy.Policy {
	policy := ExpectedPolicy(change, agent)
	policy.Expected.IntentRef = "change:intent:outcome"
	policy.Expected.CapabilityRef = "change:capability:read"
	policy.Expected.Scopes = []string{"change.read"}
	policy.Expected.AuthorizationDetails = []string{"change:read-outcome"}
	return policy
}
