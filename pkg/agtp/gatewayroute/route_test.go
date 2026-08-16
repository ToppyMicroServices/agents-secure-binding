// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gatewayroute

import (
	"errors"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
)

func TestValidateAcceptsRouteAssertionWithAgentHolderProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	assertion := testAssertion(now)
	proof := testHolderProof(now)
	expected := testExpectedRoute()

	if err := Validate(assertion, &proof, expected, Options{Now: now, ReplayCache: newReplayCache()}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsPolicyBoundDiversion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name    string
		mutate  func(*Assertion, *HolderOfKeyProof, *ExpectedRoute)
		wantErr error
	}{
		{
			name: "wrong route",
			mutate: func(a *Assertion, _ *HolderOfKeyProof, _ *ExpectedRoute) {
				a.RouteID = "route-admin"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong tenant",
			mutate: func(a *Assertion, _ *HolderOfKeyProof, _ *ExpectedRoute) {
				a.Tenant = "tenant-b"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong policy",
			mutate: func(a *Assertion, _ *HolderOfKeyProof, _ *ExpectedRoute) {
				a.PolicyID = "policy-admin"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong task",
			mutate: func(a *Assertion, proof *HolderOfKeyProof, _ *ExpectedRoute) {
				a.TaskID = "task-b"
				proof.TaskID = "task-b"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong target agent",
			mutate: func(a *Assertion, proof *HolderOfKeyProof, _ *ExpectedRoute) {
				a.TargetAgent = "agent-b"
				proof.AgentID = "agent-b"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong holder nonce",
			mutate: func(_ *Assertion, proof *HolderOfKeyProof, _ *ExpectedRoute) {
				proof.Nonce = "route-nonce-b"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "wrong audit hash",
			mutate: func(a *Assertion, _ *HolderOfKeyProof, _ *ExpectedRoute) {
				a.AuditHash = "sha256:audit-b"
			},
			wantErr: ErrMismatch,
		},
		{
			name: "expired holder proof",
			mutate: func(_ *Assertion, proof *HolderOfKeyProof, _ *ExpectedRoute) {
				proof.ExpiresAt = now.Add(-time.Minute)
			},
			wantErr: ErrExpired,
		},
		{
			name: "missing holder proof hash",
			mutate: func(a *Assertion, _ *HolderOfKeyProof, _ *ExpectedRoute) {
				a.AgentHolderOfKeyProofSHA256 = ""
			},
			wantErr: ErrMissingObserved,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion := testAssertion(now)
			proof := testHolderProof(now)
			expected := testExpectedRoute()
			tt.mutate(&assertion, &proof, &expected)

			err := Validate(assertion, &proof, expected, Options{Now: now, ReplayCache: newReplayCache()})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsMissingRequiredAgentHolderProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	assertion := testAssertion(now)
	expected := testExpectedRoute()

	err := Validate(assertion, nil, expected, Options{Now: now, ReplayCache: newReplayCache()})
	if !errors.Is(err, ErrMissingObserved) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingObserved)
	}
}

func TestValidateRejectsRouteAssertionReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	assertion := testAssertion(now)
	proof := testHolderProof(now)
	expected := testExpectedRoute()
	replay := newReplayCache()
	opts := Options{Now: now, ReplayCache: replay}

	if err := Validate(assertion, &proof, expected, opts); err != nil {
		t.Fatalf("Validate() first error = %v", err)
	}
	err := Validate(assertion, &proof, expected, opts)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("Validate() replay error = %v, want %v", err, ErrReplayDetected)
	}
}

func testAssertion(now time.Time) Assertion {
	return Assertion{
		Type:                        AssertionType,
		Version:                     AssertionVersion,
		Issuer:                      "gateway-a",
		Audience:                    "client-a",
		ID:                          "route-assertion-1",
		IssuedAt:                    now,
		ExpiresAt:                   now.Add(time.Minute),
		Nonce:                       "route-nonce-a",
		GrantHash:                   "sha256:grant-a",
		GatewaySessionBindingSHA256: "sha256:gateway-session-a",
		RouteID:                     "route-payments",
		NextHop:                     "spiffe://mesh/ns/payments/sa/agent-a",
		Tenant:                      "tenant-a",
		Principal:                   "principal-a",
		AuthorityScope:              "orders:settle",
		PolicyID:                    "policy-payments-v1",
		TargetAgent:                 "agent-a",
		TargetWorkload:              "payments-workload-a",
		TargetAgentKeyThumbprint:    "sha256:agent-key-a",
		UpstreamAuthn:               "agent-hok",
		UpstreamPeer:                "spiffe://mesh/ns/payments/sa/agent-a",
		RequestContextSHA256:        "sha256:context-a",
		TaskID:                      "task-a",
		ContextID:                   "context-a",
		SessionID:                   "session-a",
		AuditHash:                   "sha256:audit-a",
		AgentHolderOfKeyProofSHA256: "sha256:hok-proof-a",
	}
}

func testHolderProof(now time.Time) HolderOfKeyProof {
	return HolderOfKeyProof{
		AgentID:       "agent-a",
		WorkloadID:    "payments-workload-a",
		KeyThumbprint: "sha256:agent-key-a",
		GrantHash:     "sha256:grant-a",
		RouteID:       "route-payments",
		TaskID:        "task-a",
		ContextID:     "context-a",
		Nonce:         "route-nonce-a",
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Minute),
	}
}

func testExpectedRoute() ExpectedRoute {
	return ExpectedRoute{
		Issuer:                       "gateway-a",
		Audience:                     "client-a",
		Tenant:                       "tenant-a",
		AuthorityScope:               "orders:settle",
		RouteID:                      "route-payments",
		PolicyID:                     "policy-payments-v1",
		TargetAgent:                  "agent-a",
		TargetWorkload:               "payments-workload-a",
		TargetAgentKeyThumbprint:     "sha256:agent-key-a",
		RequestContextSHA256:         "sha256:context-a",
		TaskID:                       "task-a",
		ContextID:                    "context-a",
		AuditHash:                    "sha256:audit-a",
		RequireAgentHolderOfKeyProof: true,
	}
}

type replayCache struct {
	seen map[string]struct{}
}

func newReplayCache() *replayCache {
	return &replayCache{seen: map[string]struct{}{}}
}

func (c *replayCache) MarkUsed(key string, _ time.Time) error {
	if _, ok := c.seen[key]; ok {
		return identitypolicy.ErrReplayDetected
	}
	c.seen[key] = struct{}{}
	return nil
}
