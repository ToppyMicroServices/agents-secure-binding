// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/golang-jwt/jwt/v5"
)

type httpFixture struct {
	f           *fixture
	handler     http.Handler
	server      *httptest.Server
	client      *http.Client
	clientTLS   *tls.Config
	certificate tls.Certificate
}

func newHTTPFixture(t *testing.T, configure func(*fixture, *HTTPConfig)) *httpFixture {
	t.Helper()
	f := newFixture(t)
	config := HTTPConfig{Service: f.service}
	if configure != nil {
		configure(f, &config)
	}
	handler, err := NewHTTPHandler(config)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "least privilege test CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(3 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKeyPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	makeCertificate := func(serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private, Leaf: leaf}
	}
	serverCert := makeCertificate(2, x509.ExtKeyUsageServerAuth)
	clientCert := makeCertificate(3, x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{clientCert}}
	h := &httpFixture{f: f, handler: handler, server: server, clientTLS: clientTLS, certificate: clientCert}
	h.client = h.newClient(t)
	return h
}

func (h *httpFixture) newClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: h.clientTLS.Clone(), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func (h *httpFixture) post(t *testing.T, client *http.Client, path string, input any) (int, []byte, *tls.ConnectionState) {
	t.Helper()
	var raw []byte
	var err error
	if literal, ok := input.([]byte); ok {
		raw = literal
	} else {
		raw, err = json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.server.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body, response.TLS
}

func (h *httpFixture) challenge(t *testing.T, client *http.Client, mode string) HTTPChallenge {
	t.Helper()
	status, raw, state := h.post(t, client, "/challenge", HTTPChallengeRequest{Mode: mode, Operation: h.f.op})
	if status != http.StatusOK {
		t.Fatalf("challenge: %d %s", status, raw)
	}
	var challenge HTTPChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatal("test did not complete a real verified TLS1.3 handshake")
	}
	exported, err := state.ExportKeyingMaterial(HTTPExporterLabel, []byte(challenge.Binding.BindingContextSHA256), 32)
	if err != nil {
		t.Fatal(err)
	}
	exporter := sha256.Sum256(exported)
	spki := sha256.Sum256(h.certificate.Leaf.RawSubjectPublicKeyInfo)
	if challenge.Binding.TLSExporterSHA256 != "sha256:"+hex.EncodeToString(exporter[:]) || challenge.Binding.AcceptedEndpointSPKISHA256 != "sha256:"+hex.EncodeToString(spki[:]) {
		t.Fatal("challenge did not bind the actual TLS exporter and client SPKI")
	}
	return challenge
}

func (h *httpFixture) proof(t *testing.T, c HTTPChallenge, mutate func(jwt.MapClaims)) Proof {
	t.Helper()
	f := h.f
	n := f.nonce.Add(1)
	digest, err := ContextDigest(c.Mode, f.op)
	if err != nil {
		t.Fatal(err)
	}
	grantClaims := jwt.MapClaims{
		"iss": "authority", "sub": f.record.Mandate.ActorID, "aud": "executor", "jti": fmt.Sprintf("http-grant-%d", n),
		"iat": c.Binding.IssuedAt.Unix(), "exp": c.ExpiresAt.Unix(), clients.ClaimTokenType: clients.TokenTypeIdentityGrant, clients.ClaimProfileVersion: clients.ProfileVersion,
		"cnf": map[string]any{"kid": "actor-key"}, "agent": f.record.Mandate.ActorID, "task_id": f.record.Mandate.TaskID,
		"target_resource": f.op.Action.Resource, "target_operation": f.op.Action.Operation, "capability_ref": f.record.Mandate.PolicyRef, "scope": f.op.Action.Operation, "resource": f.op.Action.Resource,
		"authorization_details": []string{AuthorizationDetail(c.Mode, f.op, digest)},
	}
	if mutate != nil {
		mutate(grantClaims)
	}
	grant := sign(t, grantClaims, "authority-key", clients.IdentityGrantJWTTypeV2, f.authority)
	b := c.Binding
	claims := jwt.MapClaims{
		"iss": f.record.Mandate.ActorID, "aud": "executor", "jti": fmt.Sprintf("http-proof-%d", n), "iat": b.IssuedAt.Unix(), "exp": b.ExpiresAt.Unix(),
		clients.ClaimTokenType: clients.TokenTypeSessionBinding, clients.ClaimProfileVersion: clients.ProfileVersionV2, "grant_hash": clients.IdentityGrantHash(grant),
		"endpoint_role": b.EndpointRole, "interaction_type": b.InteractionType, "accepted_endpoint_spki_sha256": b.AcceptedEndpointSPKISHA256, "tls_exporter_sha256": b.TLSExporterSHA256,
		"binding_context_sha256": b.BindingContextSHA256, "verifier_nonce": b.VerifierNonce,
	}
	return Proof{GrantJWT: grant, SessionBindingJWT: sign(t, claims, "actor-key", clients.SessionBindingJWTTypeV2, f.actor)}
}

func (h *httpFixture) authorize(t *testing.T) lp.Capability {
	t.Helper()
	c := h.challenge(t, h.client, "authorize")
	status, raw, _ := h.post(t, h.client, "/authorize", HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Candidate: h.f.solution})
	if status != http.StatusOK {
		t.Fatalf("authorize: %d %s", status, raw)
	}
	var result HTTPResponse
	if err := json.Unmarshal(raw, &result); err != nil || result.Capability == nil {
		t.Fatalf("capability: %s %v", raw, err)
	}
	return *result.Capability
}

func TestHTTPMutualTLSAuthorizeExecuteAndFreshReconcile(t *testing.T) {
	h := newHTTPFixture(t, nil)
	capability := h.authorize(t)
	c := h.challenge(t, h.client, "execute")
	input := HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: capability}
	status, raw, _ := h.post(t, h.client, "/execute", input)
	var result HTTPResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || result.Execution == nil || result.Execution.State != lp.ExecutionSucceeded || h.f.calls.Load() != 1 {
		t.Fatalf("execute: %d %s calls=%d", status, raw, h.f.calls.Load())
	}
	status, raw, _ = h.post(t, h.client, "/execute", input)
	if status != http.StatusConflict || !bytes.Contains(raw, []byte(`"replay"`)) || h.f.calls.Load() != 1 {
		t.Fatalf("challenge replay accepted: %d %s", status, raw)
	}
	c = h.challenge(t, h.client, "reconcile")
	status, raw, _ = h.post(t, h.client, "/reconcile", HTTPReconcileRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil)})
	if status != http.StatusOK || h.f.calls.Load() != 1 {
		t.Fatalf("fresh reconciliation: %d %s", status, raw)
	}
}

func TestHTTPAcceptsEmptyOptimalPermissionSets(t *testing.T) {
	h := newHTTPFixture(t, func(f *fixture, _ *HTTPConfig) {
		f.record.Problem.Required = nil
		var err error
		f.solution, err = lp.Solve(context.Background(), f.record.Problem, 4)
		if err != nil {
			t.Fatal(err)
		}
		f.solution.Grants, f.solution.Effective = nil, nil
		f.record.Mandate.ProblemDigest = f.solution.ProblemDigest
		if err := f.policies.Put(f.record); err != nil {
			t.Fatal(err)
		}
		f.service.executors[f.op.Action.Operation] = func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
			f.calls.Add(1)
			return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("empty optimum")}, nil
		}
	})
	capability := h.authorize(t)
	if capability.Claims.Solution.Cost != 0 || len(capability.Claims.Solution.Grants) != 0 || len(capability.Claims.Solution.Effective) != 0 {
		t.Fatalf("wrong empty optimum: %+v", capability.Claims.Solution)
	}
	c := h.challenge(t, h.client, "execute")
	status, raw, _ := h.post(t, h.client, "/execute", HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: capability})
	if status != http.StatusOK || h.f.calls.Load() != 1 {
		t.Fatalf("empty optimum failed HTTP execution: %d %s", status, raw)
	}
}

func TestHTTPRejectsCrossConnectionAndCrossModeChallenge(t *testing.T) {
	h := newHTTPFixture(t, nil)
	c := h.challenge(t, h.client, "authorize")
	input := HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Candidate: h.f.solution}
	other := h.newClient(t)
	status, raw, _ := h.post(t, other, "/authorize", input)
	if status != http.StatusForbidden {
		t.Fatalf("cross-connection proof accepted: %d %s", status, raw)
	}
	status, raw, _ = h.post(t, h.client, "/authorize", input)
	if status != http.StatusOK {
		t.Fatalf("cross-connection rejection consumed original challenge: %d %s", status, raw)
	}
	var issued HTTPResponse
	if err := json.Unmarshal(raw, &issued); err != nil || issued.Capability == nil {
		t.Fatalf("authorize response: %s %v", raw, err)
	}
	c = h.challenge(t, h.client, "authorize")
	status, raw, _ = h.post(t, h.client, "/execute", HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: *issued.Capability})
	if status != http.StatusForbidden {
		t.Fatalf("cross-mode challenge accepted: %d %s", status, raw)
	}
}

func TestHTTPRejectsForgedActorAndConsumesFailedAttempt(t *testing.T) {
	h := newHTTPFixture(t, nil)
	c := h.challenge(t, h.client, "authorize")
	bad := h.proof(t, c, func(claims jwt.MapClaims) { claims["agent"] = "agent:attacker" })
	status, raw, _ := h.post(t, h.client, "/authorize", HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: bad, Candidate: h.f.solution})
	if status != http.StatusForbidden || bytes.Contains(raw, []byte("attacker")) {
		t.Fatalf("forged identity accepted or reflected: %d %s", status, raw)
	}
	status, raw, _ = h.post(t, h.client, "/authorize", HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Candidate: h.f.solution})
	if status != http.StatusConflict {
		t.Fatalf("failed proof challenge reused: %d %s", status, raw)
	}
	if h.f.calls.Load() != 0 {
		t.Fatal("forged identity dispatched")
	}
}

func TestHTTPUnknownIsExplicitAndReconciliationUsesTrustedAdapter(t *testing.T) {
	var queries atomic.Int32
	h := newHTTPFixture(t, func(f *fixture, _ *HTTPConfig) {
		f.service.executors[f.op.Action.Operation] = func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
			f.calls.Add(1)
			return lp.EffectResult{}, errors.New("private backend detail /sensitive/path")
		}
		f.service.reconcilers = map[string]Reconciler{f.op.Action.Operation: func(context.Context, lp.ExecutionRecord, lp.Request) (lp.EffectResult, error) {
			queries.Add(1)
			return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("authoritative query")}, nil
		}}
	})
	capability := h.authorize(t)
	c := h.challenge(t, h.client, "execute")
	status, raw, _ := h.post(t, h.client, "/execute", HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: capability})
	if status != http.StatusConflict || !bytes.Contains(raw, []byte(`"state":"UNKNOWN"`)) || bytes.Contains(raw, []byte("sensitive")) || bytes.Contains(raw, []byte("backend")) {
		t.Fatalf("uncertainty missing or private error exposed: %d %s", status, raw)
	}
	c = h.challenge(t, h.client, "reconcile")
	status, raw, _ = h.post(t, h.client, "/reconcile", HTTPReconcileRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil)})
	if status != http.StatusOK || queries.Load() != 1 || h.f.calls.Load() != 1 {
		t.Fatalf("authoritative recovery: %d %s queries=%d effects=%d", status, raw, queries.Load(), h.f.calls.Load())
	}
}

func TestHTTPRequiresActualClientCertificateAndRejectsProxyHeaders(t *testing.T) {
	h := newHTTPFixture(t, nil)
	r := httptest.NewRequest(http.MethodPost, "http://local/challenge", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Client-Cert", "forged certificate")
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("proxy headers substituted for TLS: %d", w.Code)
	}
	config := h.clientTLS.Clone()
	config.Certificates = nil
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, h.server.URL+"/challenge", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err == nil {
		defer response.Body.Close()
		t.Fatalf("TLS accepted no client certificate: %d", response.StatusCode)
	}
}

func TestHTTPStrictJSONBoundsAndUnknownFields(t *testing.T) {
	h := newHTTPFixture(t, nil)
	valid, err := json.Marshal(HTTPChallengeRequest{Mode: "authorize", Operation: h.f.op})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":         bytes.Replace(valid, []byte(`"mode":"authorize"`), []byte(`"mode":"authorize","mode":"execute"`), 1),
		"escaped duplicate": bytes.Replace(valid, []byte(`"mode":"authorize"`), []byte(`"mode":"authorize","\u006dode":"execute"`), 1),
		"case alias":        bytes.Replace(valid, []byte(`"mode":"authorize"`), []byte(`"mode":"authorize","Mode":"execute"`), 1),
		"peer transport":    append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"transport":{"binding":{}}}`)...),
		"actor label":       bytes.Replace(valid, []byte(`"operation_id":`), []byte(`"actor_id":"agent:forged","operation_id":`), 1),
		"trailing":          append(append([]byte(nil), valid...), []byte(` {}`)...),
		"oversized":         []byte(`{"padding":"` + strings.Repeat("x", maxHTTPBodyBytes) + `"}`),
		"deep":              []byte(`{"padding":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`),
		"null":              []byte(`null`),
		"null operation":    []byte(`{"mode":"authorize","operation":null}`),
		"scalar":            []byte(`true`),
	} {
		t.Run(name, func(t *testing.T) {
			status, body, _ := h.post(t, h.client, "/challenge", raw)
			if status != http.StatusBadRequest {
				t.Fatalf("invalid JSON accepted: %d %s", status, body)
			}
		})
	}
	if h.f.calls.Load() != 0 {
		t.Fatal("invalid schema dispatched")
	}
}

func TestHTTPChallengeCapacityExpiryAndCertificateExpiry(t *testing.T) {
	h := newHTTPFixture(t, func(_ *fixture, c *HTTPConfig) { c.MaxChallenges = 1; c.ChallengeTTL = time.Second })
	c := h.challenge(t, h.client, "authorize")
	status, raw, _ := h.post(t, h.client, "/challenge", HTTPChallengeRequest{Mode: "authorize", Operation: h.f.op})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("registry evicted active challenge: %d %s", status, raw)
	}
	h.f.now = h.f.now.Add(2 * time.Second)
	status, raw, _ = h.post(t, h.client, "/authorize", HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Candidate: h.f.solution})
	if status != http.StatusForbidden {
		t.Fatalf("expired challenge accepted: %d %s", status, raw)
	}
	h.challenge(t, h.client, "authorize")
	h.f.now = h.f.now.Add(2 * time.Hour)
	status, raw, _ = h.post(t, h.client, "/challenge", HTTPChallengeRequest{Mode: "authorize", Operation: h.f.op})
	if status != http.StatusForbidden {
		t.Fatalf("expired peer certificate accepted on live connection: %d %s", status, raw)
	}
}

func TestHTTPConfigurationBounds(t *testing.T) {
	if _, err := NewHTTPHandler(HTTPConfig{}); err == nil {
		t.Fatal("nil service accepted")
	}
	f := newFixture(t)
	for _, config := range []HTTPConfig{{Service: f.service, MaxChallenges: -1}, {Service: f.service, MaxChallenges: 10_001}, {Service: f.service, ChallengeTTL: time.Minute + time.Second}, {Service: f.service, ChallengeTTL: time.Millisecond}} {
		if _, err := NewHTTPHandler(config); err == nil {
			t.Fatal("unbounded configuration accepted")
		}
	}
}
