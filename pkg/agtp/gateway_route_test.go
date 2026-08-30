// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agtp

import (
	"crypto/ecdsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/gatewayroute"
	"github.com/golang-jwt/jwt/v5"
	"github.com/veraison/go-cose"
)

const (
	testGatewayRouteID      = "route-payments"
	testGatewayRouteAdminID = "route-admin"
	testGatewaySPIFFEPeer   = "spiffe://mesh/ns/payments/sa/agent-a"
	testGatewayTargetAgent  = "agent-a"
)

func TestVerifyGatewayRouteJWTAcceptsLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token := signTestJWT(t, "gateway-key", []byte("gateway-secret"), testGatewayRouteJWTClaims(now))

	assertion, err := VerifyGatewayRouteJWT(token, testGatewayRouteJWTOptions(now))
	if err != nil {
		t.Fatalf("VerifyGatewayRouteJWT() error = %v", err)
	}
	if assertion.RouteID != testGatewayRouteID || assertion.TargetAgent != testGatewayTargetAgent {
		t.Fatalf("assertion route/agent = %q/%q", assertion.RouteID, assertion.TargetAgent)
	}
}

func TestVerifyGatewayRouteJWTRedTeamRejectsAttacks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name    string
		claims  func() jwt.MapClaims
		opts    func() GatewayRouteJWTOptions
		wantErr error
	}{
		{
			name: "policy-bound route diversion",
			claims: func() jwt.MapClaims {
				claims := testGatewayRouteJWTClaims(now)
				claims[gatewayroute.FieldRouteID] = testGatewayRouteAdminID
				return claims
			},
			opts:    func() GatewayRouteJWTOptions { return testGatewayRouteJWTOptions(now) },
			wantErr: gatewayroute.ErrMismatch,
		},
		{
			name: "grant hash substitution",
			claims: func() jwt.MapClaims {
				claims := testGatewayRouteJWTClaims(now)
				claims[gatewayroute.FieldGrantHash] = "sha256:other-grant"
				return claims
			},
			opts:    func() GatewayRouteJWTOptions { return testGatewayRouteJWTOptions(now) },
			wantErr: gatewayroute.ErrMismatch,
		},
		{
			name: "gateway session substitution",
			claims: func() jwt.MapClaims {
				claims := testGatewayRouteJWTClaims(now)
				claims[gatewayroute.FieldGatewaySessionBindingSHA256] = "sha256:other-gateway-session"
				return claims
			},
			opts:    func() GatewayRouteJWTOptions { return testGatewayRouteJWTOptions(now) },
			wantErr: gatewayroute.ErrMismatch,
		},
		{
			name: "holder proof hash substitution",
			claims: func() jwt.MapClaims {
				claims := testGatewayRouteJWTClaims(now)
				claims[gatewayroute.FieldAgentHOKProofSHA256] = "sha256:other-hok-proof"
				return claims
			},
			opts:    func() GatewayRouteJWTOptions { return testGatewayRouteJWTOptions(now) },
			wantErr: gatewayroute.ErrMismatch,
		},
		{
			name:   "missing replay cache",
			claims: func() jwt.MapClaims { return testGatewayRouteJWTClaims(now) },
			opts: func() GatewayRouteJWTOptions {
				opts := testGatewayRouteJWTOptions(now)
				opts.Route.ReplayCache = nil
				return opts
			},
			wantErr: ErrMissingReplayCache,
		},
		{
			name:   "wrong gateway signing key",
			claims: func() jwt.MapClaims { return testGatewayRouteJWTClaims(now) },
			opts: func() GatewayRouteJWTOptions {
				opts := testGatewayRouteJWTOptions(now)
				opts.Assertion.KeyFunc = testKeyFunc(map[string][]byte{"gateway-key": []byte("gateway-secret")})
				return opts
			},
			wantErr: ErrMissingKeyID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID := "gateway-key"
			secret := []byte("gateway-secret")
			if tt.name == "wrong gateway signing key" {
				keyID = "tls-endpoint-key"
				secret = []byte("tls-secret")
			}
			token := signTestJWT(t, keyID, secret, tt.claims())
			_, err := VerifyGatewayRouteJWT(token, tt.opts())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyGatewayRouteJWT() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyGatewayRouteJWTRejectsMissingProtectedKeyIDAndReplay(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token := signGatewayRouteJWTWithoutKID(t, []byte("gateway-secret"), testGatewayRouteJWTClaims(now))
	if _, err := VerifyGatewayRouteJWT(token, testGatewayRouteJWTOptions(now)); !errors.Is(err, ErrMissingKeyID) {
		t.Fatalf("VerifyGatewayRouteJWT() missing kid error = %v, want %v", err, ErrMissingKeyID)
	}

	replayToken := signTestJWT(t, "gateway-key", []byte("gateway-secret"), testGatewayRouteJWTClaims(now))
	opts := testGatewayRouteJWTOptions(now)
	if _, err := VerifyGatewayRouteJWT(replayToken, opts); err != nil {
		t.Fatalf("VerifyGatewayRouteJWT() first error = %v", err)
	}
	if _, err := VerifyGatewayRouteJWT(replayToken, opts); !errors.Is(err, gatewayroute.ErrReplayDetected) {
		t.Fatalf("VerifyGatewayRouteJWT() replay error = %v, want %v", err, gatewayroute.ErrReplayDetected)
	}
}

func TestVerifyGatewayRouteJWTLiveRedTeamNetworkHarness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	replay := newAGTPReplayCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		routeID := strings.TrimPrefix(r.URL.Path, "/routes/")
		routeID, _, _ = strings.Cut(routeID, "/")
		opts := testGatewayRouteJWTOptions(now)
		opts.Route.ReplayCache = replay
		opts.Expected.RouteID = routeID
		proof := testGatewayHolderProof(now)
		proof.RouteID = routeID
		if routeID == testGatewayRouteAdminID {
			proof.Nonce = "route-nonce-admin"
		}
		opts.Proof = proof
		if _, err := VerifyGatewayRouteJWT(r.Header.Get("X-Gateway-Route-JWT"), opts); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	paymentClaims := testGatewayRouteJWTClaims(now)
	paymentToken := signTestJWT(t, "gateway-key", []byte("gateway-secret"), paymentClaims)
	liveRedTeamGatewayRouteRequest(t, server.URL+"/routes/route-payments/tasks/task-a", paymentToken, http.StatusNoContent)
	liveRedTeamGatewayRouteRequest(t, server.URL+"/routes/route-payments/tasks/task-a", paymentToken, http.StatusForbidden)

	wrongRouteClaims := testGatewayRouteJWTClaims(now)
	wrongRouteClaims["jti"] = "route-assertion-wrong-route"
	wrongRouteClaims[gatewayroute.FieldNonce] = "route-nonce-wrong-route"
	wrongRouteToken := signTestJWT(t, "gateway-key", []byte("gateway-secret"), wrongRouteClaims)
	liveRedTeamGatewayRouteRequest(t, server.URL+"/routes/"+testGatewayRouteAdminID+"/tasks/task-a", wrongRouteToken, http.StatusForbidden)

	adminClaims := testGatewayRouteJWTClaims(now)
	adminClaims["jti"] = "route-assertion-admin"
	adminClaims[gatewayroute.FieldNonce] = "route-nonce-admin"
	adminClaims[gatewayroute.FieldRouteID] = testGatewayRouteAdminID
	adminToken := signTestJWT(t, "gateway-key", []byte("gateway-secret"), adminClaims)
	liveRedTeamGatewayRouteRequest(t, server.URL+"/routes/"+testGatewayRouteAdminID+"/tasks/task-a", adminToken, http.StatusNoContent)
}

func TestVerifyGatewayRouteCWTAcceptsLocalPolicy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)
	token := signTestCWT(t, "gateway-key", keys.manager, testGatewayRouteCWTClaims(now))

	assertion, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
	if err != nil {
		t.Fatalf("VerifyGatewayRouteCWT() error = %v", err)
	}
	if assertion.RouteID != testGatewayRouteID || assertion.TargetAgent != testGatewayTargetAgent {
		t.Fatalf("assertion route/agent = %q/%q", assertion.RouteID, assertion.TargetAgent)
	}
}

func TestVerifyGatewayRouteCWTRedTeamRejectsAttacks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	keys := newTestCWTKeySet(t)

	t.Run("policy-bound route diversion", func(t *testing.T) {
		claims := testGatewayRouteCWTClaims(now)
		claims[gatewayroute.FieldRouteID] = testGatewayRouteAdminID
		token := signTestCWT(t, "gateway-key", keys.manager, claims)
		_, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
		if !errors.Is(err, gatewayroute.ErrMismatch) {
			t.Fatalf("VerifyGatewayRouteCWT() error = %v, want %v", err, gatewayroute.ErrMismatch)
		}
	})

	t.Run("grant hash substitution", func(t *testing.T) {
		claims := testGatewayRouteCWTClaims(now)
		claims[gatewayroute.FieldGrantHash] = "sha256:other-grant"
		token := signTestCWT(t, "gateway-key", keys.manager, claims)
		_, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
		if !errors.Is(err, gatewayroute.ErrMismatch) {
			t.Fatalf("VerifyGatewayRouteCWT() error = %v, want %v", err, gatewayroute.ErrMismatch)
		}
	})

	t.Run("gateway session substitution", func(t *testing.T) {
		claims := testGatewayRouteCWTClaims(now)
		claims[gatewayroute.FieldGatewaySessionBindingSHA256] = "sha256:other-gateway-session"
		token := signTestCWT(t, "gateway-key", keys.manager, claims)
		_, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
		if !errors.Is(err, gatewayroute.ErrMismatch) {
			t.Fatalf("VerifyGatewayRouteCWT() error = %v, want %v", err, gatewayroute.ErrMismatch)
		}
	})

	t.Run("holder proof hash substitution", func(t *testing.T) {
		claims := testGatewayRouteCWTClaims(now)
		claims[gatewayroute.FieldAgentHOKProofSHA256] = "sha256:other-hok-proof"
		token := signTestCWT(t, "gateway-key", keys.manager, claims)
		_, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
		if !errors.Is(err, gatewayroute.ErrMismatch) {
			t.Fatalf("VerifyGatewayRouteCWT() error = %v, want %v", err, gatewayroute.ErrMismatch)
		}
	})

	t.Run("unprotected COSE kid", func(t *testing.T) {
		token := signTestCWTWithKidPlacement(t, "gateway-key", keys.manager, testGatewayRouteCWTClaims(now), false)
		_, err := VerifyGatewayRouteCWT(token, testGatewayRouteCWTOptions(now, keys))
		if !errors.Is(err, ErrUnprotectedKeyID) {
			t.Fatalf("VerifyGatewayRouteCWT() error = %v, want %v", err, ErrUnprotectedKeyID)
		}
	})

	t.Run("replay", func(t *testing.T) {
		token := signTestCWT(t, "gateway-key", keys.manager, testGatewayRouteCWTClaims(now))
		opts := testGatewayRouteCWTOptions(now, keys)
		if _, err := VerifyGatewayRouteCWT(token, opts); err != nil {
			t.Fatalf("VerifyGatewayRouteCWT() first error = %v", err)
		}
		if _, err := VerifyGatewayRouteCWT(token, opts); !errors.Is(err, gatewayroute.ErrReplayDetected) {
			t.Fatalf("VerifyGatewayRouteCWT() replay error = %v, want %v", err, gatewayroute.ErrReplayDetected)
		}
	})
}

func testGatewayRouteJWTClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		gatewayroute.FieldType:      gatewayroute.AssertionType,
		gatewayroute.FieldVersion:   gatewayroute.AssertionVersion,
		"iss":                       "gateway-a",
		"aud":                       "client-a",
		"jti":                       "route-assertion-1",
		"iat":                       now.Unix(),
		"exp":                       now.Add(time.Minute).Unix(),
		gatewayroute.FieldNonce:     "route-nonce-a",
		gatewayroute.FieldGrantHash: "sha256:grant-a",
		gatewayroute.FieldGatewaySessionBindingSHA256: "sha256:gateway-session-a",
		gatewayroute.FieldRouteID:                     testGatewayRouteID,
		gatewayroute.FieldNextHop:                     testGatewaySPIFFEPeer,
		gatewayroute.FieldTenant:                      "tenant-a",
		gatewayroute.FieldPrincipal:                   "principal-a",
		gatewayroute.FieldAuthorityScope:              "orders:settle",
		gatewayroute.FieldPolicyID:                    "policy-payments-v1",
		gatewayroute.FieldTargetAgent:                 testGatewayTargetAgent,
		gatewayroute.FieldTargetWorkload:              "payments-workload-a",
		gatewayroute.FieldTargetAgentKeyThumbprint:    "sha256:agent-key-a",
		gatewayroute.FieldUpstreamAuthn:               "agent-hok",
		gatewayroute.FieldUpstreamPeer:                testGatewaySPIFFEPeer,
		gatewayroute.FieldRequestContextSHA256:        "sha256:context-a",
		gatewayroute.FieldTaskID:                      "task-a",
		gatewayroute.FieldContextID:                   "context-a",
		gatewayroute.FieldSessionID:                   "session-a",
		gatewayroute.FieldAuditHash:                   "sha256:audit-a",
		gatewayroute.FieldAgentHOKProofSHA256:         "sha256:hok-proof-a",
	}
}

func testGatewayRouteCWTClaims(now time.Time) map[any]any {
	return map[any]any{
		gatewayroute.FieldType:                        gatewayroute.AssertionType,
		gatewayroute.FieldVersion:                     gatewayroute.AssertionVersion,
		cose.CWTClaimIssuer:                           "gateway-a",
		cose.CWTClaimAudience:                         "client-a",
		cose.CWTClaimCWTID:                            []byte("route-assertion-1"),
		cose.CWTClaimIssuedAt:                         now.Unix(),
		cose.CWTClaimExpirationTime:                   now.Add(time.Minute).Unix(),
		gatewayroute.FieldNonce:                       "route-nonce-a",
		gatewayroute.FieldGrantHash:                   "sha256:grant-a",
		gatewayroute.FieldGatewaySessionBindingSHA256: "sha256:gateway-session-a",
		gatewayroute.FieldRouteID:                     testGatewayRouteID,
		gatewayroute.FieldNextHop:                     testGatewaySPIFFEPeer,
		gatewayroute.FieldTenant:                      "tenant-a",
		gatewayroute.FieldPrincipal:                   "principal-a",
		gatewayroute.FieldAuthorityScope:              "orders:settle",
		gatewayroute.FieldPolicyID:                    "policy-payments-v1",
		gatewayroute.FieldTargetAgent:                 testGatewayTargetAgent,
		gatewayroute.FieldTargetWorkload:              "payments-workload-a",
		gatewayroute.FieldTargetAgentKeyThumbprint:    "sha256:agent-key-a",
		gatewayroute.FieldUpstreamAuthn:               "agent-hok",
		gatewayroute.FieldUpstreamPeer:                testGatewaySPIFFEPeer,
		gatewayroute.FieldRequestContextSHA256:        "sha256:context-a",
		gatewayroute.FieldTaskID:                      "task-a",
		gatewayroute.FieldContextID:                   "context-a",
		gatewayroute.FieldSessionID:                   "session-a",
		gatewayroute.FieldAuditHash:                   "sha256:audit-a",
		gatewayroute.FieldAgentHOKProofSHA256:         "sha256:hok-proof-a",
	}
}

func testGatewayRouteJWTOptions(now time.Time) GatewayRouteJWTOptions {
	return GatewayRouteJWTOptions{
		Assertion: JWTVerifyOptions{
			ExpectedIssuer:   "gateway-a",
			ExpectedAudience: "client-a",
			ValidMethods:     []string{"HS256"},
			KeyFunc:          testKeyFunc(map[string][]byte{"gateway-key": []byte("gateway-secret")}),
			Now:              now,
		},
		Expected:                            testGatewayExpectedRoute(),
		Proof:                               testGatewayHolderProof(now),
		ExpectedGrantHash:                   "sha256:grant-a",
		ExpectedGatewaySessionBindingSHA256: "sha256:gateway-session-a",
		ExpectedAgentHolderOfKeyProofSHA256: "sha256:hok-proof-a",
		Route:                               gatewayroute.Options{Now: now, ReplayCache: newAGTPReplayCache()},
	}
}

func testGatewayRouteCWTOptions(now time.Time, keys testCWTKeySet) GatewayRouteCWTOptions {
	return GatewayRouteCWTOptions{
		Assertion: CWTVerifyOptions{
			ExpectedIssuer:   "gateway-a",
			ExpectedAudience: "client-a",
			ValidAlgorithms:  []cose.Algorithm{cose.AlgorithmES256},
			KeyFunc:          testCWTKeyFunc(map[string]*ecdsa.PrivateKey{"gateway-key": keys.manager}),
			Now:              now,
		},
		Expected:                            testGatewayExpectedRoute(),
		Proof:                               testGatewayHolderProof(now),
		ExpectedGrantHash:                   "sha256:grant-a",
		ExpectedGatewaySessionBindingSHA256: "sha256:gateway-session-a",
		ExpectedAgentHolderOfKeyProofSHA256: "sha256:hok-proof-a",
		Route:                               gatewayroute.Options{Now: now, ReplayCache: newAGTPReplayCache()},
	}
}

func testGatewayExpectedRoute() gatewayroute.ExpectedRoute {
	return gatewayroute.ExpectedRoute{
		Issuer:                       "gateway-a",
		Audience:                     "client-a",
		Tenant:                       "tenant-a",
		AuthorityScope:               "orders:settle",
		RouteID:                      testGatewayRouteID,
		PolicyID:                     "policy-payments-v1",
		TargetAgent:                  testGatewayTargetAgent,
		TargetWorkload:               "payments-workload-a",
		TargetAgentKeyThumbprint:     "sha256:agent-key-a",
		RequestContextSHA256:         "sha256:context-a",
		TaskID:                       "task-a",
		ContextID:                    "context-a",
		AuditHash:                    "sha256:audit-a",
		RequireAgentHolderOfKeyProof: true,
	}
}

func testGatewayHolderProof(now time.Time) *gatewayroute.HolderOfKeyProof {
	return &gatewayroute.HolderOfKeyProof{
		AgentID:       testGatewayTargetAgent,
		WorkloadID:    "payments-workload-a",
		KeyThumbprint: "sha256:agent-key-a",
		GrantHash:     "sha256:grant-a",
		RouteID:       testGatewayRouteID,
		TaskID:        "task-a",
		ContextID:     "context-a",
		Nonce:         "route-nonce-a",
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Minute),
	}
}

func signGatewayRouteJWTWithoutKID(t *testing.T, secret []byte, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return tokenString
}

func liveRedTeamGatewayRouteRequest(t *testing.T, url, token string, wantStatus int) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("X-Gateway-Route-JWT", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do(%s) error = %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("Do(%s) status = %d, want %d", url, resp.StatusCode, wantStatus)
	}
}
