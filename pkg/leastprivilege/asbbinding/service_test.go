// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/golang-jwt/jwt/v5"
)

type fixture struct {
	now                      time.Time
	policies                 *Policies
	store                    *lp.DurableStore
	service                  *Service
	record                   PolicyRecord
	op                       Operation
	solution                 lp.Solution
	authority, actor, signer ed25519.PrivateKey
	nonce                    atomic.Uint64
	calls                    atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("durable authority supports Linux and macOS")
	}
	f := &fixture{now: time.Now().UTC().Truncate(time.Second), policies: NewPolicies()}
	var err error
	_, f.authority, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, f.actor, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, f.signer, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = lp.CreateDurableStore(filepath.Join(t.TempDir(), "state"), 100)
	if err != nil {
		t.Fatal(err)
	}
	f.op = Operation{ID: "operation-1", MandateID: "mandate-1", Action: lp.Action{Operation: "reports.read", Resource: "report:1", Arguments: []byte(`{"version":1}`)}}
	f.record.Problem = lp.Problem{
		Schema:      lp.ProblemSchemaV1,
		Permissions: []lp.Permission{{ID: "read", Cost: 1}, {ID: "write", Cost: 5}},
		Grants:      []lp.Grant{{ID: "reader", Permissions: []string{"read"}}, {ID: "writer", Permissions: []string{"read", "write"}}},
		Required:    []string{"read"}, Allowed: []string{"read", "write"},
	}
	problem, err := lp.DigestProblem(f.record.Problem)
	if err != nil {
		t.Fatal(err)
	}
	action, err := lp.DigestAction(f.op.Action)
	if err != nil {
		t.Fatal(err)
	}
	f.record.Mandate = lp.Mandate{
		ID: f.op.MandateID, PolicyRef: "policy:reports", ActorID: "agent:reader", TaskID: "task:reports",
		ActionDigest: action, ProblemDigest: problem, NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), MaxTTLSeconds: 300, AllowAutomatic: true,
	}
	if err := f.policies.Put(f.record); err != nil {
		t.Fatal(err)
	}
	f.solution, err = lp.Solve(context.Background(), f.record.Problem, 4)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = NewService(Config{
		Policies: f.policies, Store: f.store, Issuer: "authority", Audience: "executor",
		GrantKeys: map[string]ed25519.PublicKey{"authority-key": f.authority.Public().(ed25519.PublicKey)},
		ActorKeys: map[string]ed25519.PublicKey{"actor-key": f.actor.Public().(ed25519.PublicKey)}, SigningKey: f.signer,
		MaxEvaluations: 4, Clock: func() time.Time { return f.now },
		Executors: map[string]Executor{"reports.read": func(_ context.Context, id string, request lp.Request, solution lp.Solution) (lp.EffectResult, error) {
			f.calls.Add(1)
			if id != f.op.ID || request.ActorID != f.record.Mandate.ActorID || request.TaskID != f.record.Mandate.TaskID ||
				string(request.Action.Arguments) != `{"version":1}` || solution.Cost != 1 {
				return lp.EffectResult{}, lp.ErrBinding
			}
			return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("effect")}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func testDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func (f *fixture) proof(t *testing.T, mode string, op Operation, mutate func(jwt.MapClaims)) (Proof, Transport) {
	t.Helper()
	digest, err := ContextDigest(mode, op)
	if err != nil {
		t.Fatal(err)
	}
	n := sha256.Sum256([]byte(fmt.Sprint(f.nonce.Add(1))))
	transport := Transport{
		Binding: identitypolicy.BindingV2{
			EndpointRole: "client-tls-endpoint", InteractionType: "agent-to-tool",
			AcceptedEndpointSPKISHA256: testDigest("tls-endpoint"), TLSExporterSHA256: testDigest("tls-exporter"), BindingContextSHA256: digest,
			VerifierNonce: base64.RawURLEncoding.EncodeToString(n[:]), IssuedAt: f.now, ExpiresAt: f.now.Add(time.Minute),
		},
		EndpointCredentialExpiresAt: f.now.Add(time.Hour), ChallengeExpiresAt: f.now.Add(time.Minute),
	}
	grantClaims := jwt.MapClaims{
		"iss": "authority", "sub": f.record.Mandate.ActorID, "aud": "executor", "jti": fmt.Sprintf("grant-%d", f.nonce.Load()),
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), clients.ClaimTokenType: clients.TokenTypeIdentityGrant, clients.ClaimProfileVersion: clients.ProfileVersion,
		"cnf": map[string]any{"kid": "actor-key"}, "agent": f.record.Mandate.ActorID, "task_id": f.record.Mandate.TaskID,
		"target_resource": op.Action.Resource, "target_operation": op.Action.Operation, "capability_ref": f.record.Mandate.PolicyRef,
		"scope": op.Action.Operation, "resource": op.Action.Resource, "authorization_details": []string{AuthorizationDetail(mode, op, digest)},
	}
	if mutate != nil {
		mutate(grantClaims)
	}
	grant := sign(t, grantClaims, "authority-key", clients.IdentityGrantJWTTypeV2, f.authority)
	b := transport.Binding
	proofClaims := jwt.MapClaims{
		"iss": f.record.Mandate.ActorID, "aud": "executor", "jti": fmt.Sprintf("proof-%d", f.nonce.Load()),
		"iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), clients.ClaimTokenType: clients.TokenTypeSessionBinding, clients.ClaimProfileVersion: clients.ProfileVersionV2,
		"grant_hash": clients.IdentityGrantHash(grant), "endpoint_role": b.EndpointRole, "interaction_type": b.InteractionType,
		"accepted_endpoint_spki_sha256": b.AcceptedEndpointSPKISHA256, "tls_exporter_sha256": b.TLSExporterSHA256,
		"binding_context_sha256": b.BindingContextSHA256, "verifier_nonce": b.VerifierNonce,
	}
	return Proof{GrantJWT: grant, SessionBindingJWT: sign(t, proofClaims, "actor-key", clients.SessionBindingJWTTypeV2, f.actor)}, transport
}

func sign(t *testing.T, claims jwt.MapClaims, kid, typ string, key ed25519.PrivateKey) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"], token.Header["typ"] = kid, typ
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) capability(t *testing.T) lp.Capability {
	t.Helper()
	proof, transport := f.proof(t, "authorize", f.op, nil)
	cap, err := f.service.Authorize(context.Background(), f.op, proof, transport, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	return cap
}

func TestAuthenticateAuthorizeExecuteAndRecoverExactResult(t *testing.T) {
	f := newFixture(t)
	cap := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op, nil)
	result, err := f.service.Execute(context.Background(), f.op, proof, transport, cap)
	if err != nil || result.State != lp.ExecutionSucceeded || f.calls.Load() != 1 {
		t.Fatalf("execute=%+v err=%v calls=%d", result, err, f.calls.Load())
	}
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, cap); err == nil {
		t.Fatal("accepted ASB proof replay")
	}
	proof, transport = f.proof(t, "execute", f.op, nil)
	again, err := f.service.Execute(context.Background(), f.op, proof, transport, cap)
	if err != nil || again != result || f.calls.Load() != 1 {
		t.Fatalf("exact readback=%+v err=%v", again, err)
	}
	other := f.op
	other.ID = "operation-2"
	proof, transport = f.proof(t, "execute", other, nil)
	if _, err := f.service.Execute(context.Background(), other, proof, transport, cap); !errors.Is(err, lp.ErrReplay) {
		t.Fatalf("new operation with used mandate: %v", err)
	}
}

func TestRejectUntrustedIdentityAndContext(t *testing.T) {
	for name, mutate := range map[string]func(jwt.MapClaims){
		"actor":            func(c jwt.MapClaims) { c["agent"] = "agent:attacker" },
		"task":             func(c jwt.MapClaims) { c["task_id"] = "task:other" },
		"resource":         func(c jwt.MapClaims) { c["target_resource"] = "report:secret" },
		"scope":            func(c jwt.MapClaims) { c["scope"] = "reports.write" },
		"authority detail": func(c jwt.MapClaims) { c["authorization_details"] = []string{"anything"} },
		"audience":         func(c jwt.MapClaims) { c["aud"] = "other-executor" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			proof, transport := f.proof(t, "authorize", f.op, mutate)
			if _, err := f.service.Authorize(context.Background(), f.op, proof, transport, f.solution); err == nil {
				t.Fatal("accepted mismatched signed identity")
			}
			if f.calls.Load() != 0 {
				t.Fatal("dispatched rejected identity")
			}
		})
	}
	t.Run("different TLS exporter", func(t *testing.T) {
		f := newFixture(t)
		proof, transport := f.proof(t, "authorize", f.op, nil)
		transport.Binding.TLSExporterSHA256 = testDigest("another TLS session")
		if _, err := f.service.Authorize(context.Background(), f.op, proof, transport, f.solution); err == nil {
			t.Fatal("accepted cross-session proof")
		}
	})
	t.Run("signature", func(t *testing.T) {
		f := newFixture(t)
		proof, transport := f.proof(t, "authorize", f.op, nil)
		parts := strings.Split(proof.GrantJWT, ".")
		parts[2] = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		proof.GrantJWT = strings.Join(parts, ".")
		if _, err := f.service.Authorize(context.Background(), f.op, proof, transport, f.solution); err == nil {
			t.Fatal("accepted invalid signature")
		}
	})
	t.Run("authorize proof cannot execute", func(t *testing.T) {
		f := newFixture(t)
		cap := f.capability(t)
		proof, transport := f.proof(t, "authorize", f.op, nil)
		if _, err := f.service.Execute(context.Background(), f.op, proof, transport, cap); !errors.Is(err, ErrTransport) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestCurrentPolicyRejectsStaleCapabilities(t *testing.T) {
	for _, kind := range []string{"revoke", "human", "problem", "arguments", "nonoptimal"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			cap := f.capability(t)
			op := f.op
			switch kind {
			case "revoke":
				if err := f.policies.Revoke(op.MandateID); err != nil {
					t.Fatal(err)
				}
			case "human":
				f.record.Mandate.AllowAutomatic = false
				if err := f.policies.Put(f.record); err != nil {
					t.Fatal(err)
				}
			case "problem":
				f.record.Problem.Permissions[0].Cost++
				d, err := lp.DigestProblem(f.record.Problem)
				if err != nil {
					t.Fatal(err)
				}
				f.record.Mandate.ProblemDigest = d
				if err := f.policies.Put(f.record); err != nil {
					t.Fatal(err)
				}
			case "arguments":
				op.Action.Arguments = []byte(`{"version":2}`)
			case "nonoptimal":
				proof, transport := f.proof(t, "authorize", op, nil)
				candidate := f.solution
				candidate.Grants, candidate.Effective, candidate.Cost = []string{"writer"}, []string{"read", "write"}, 6
				if _, err := f.service.Authorize(context.Background(), op, proof, transport, candidate); !errors.Is(err, lp.ErrNotOptimal) {
					t.Fatalf("error=%v", err)
				}
				return
			}
			proof, transport := f.proof(t, "execute", op, nil)
			if _, err := f.service.Execute(context.Background(), op, proof, transport, cap); err == nil {
				t.Fatal("accepted stale authority")
			}
			if f.calls.Load() != 0 {
				t.Fatal("dispatched stale authority")
			}
		})
	}
}

func TestPolicyUpdateWaitsForDispatchAndBlocksLaterOperations(t *testing.T) {
	f := newFixture(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	f.service.executors["reports.read"] = func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
		close(entered)
		<-release
		return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("done")}, nil
	}
	cap := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op, nil)
	go func() {
		_, err := f.service.Execute(context.Background(), f.op, proof, transport, cap)
		finished <- err
	}()
	<-entered
	revoked := make(chan error, 1)
	go func() { revoked <- f.policies.Revoke(f.op.MandateID) }()
	select {
	case err := <-revoked:
		t.Fatalf("revocation returned during guarded dispatch: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	proof, transport = f.proof(t, "execute", f.op, nil)
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, cap); !errors.Is(err, ErrPolicy) {
		t.Fatalf("post-revocation=%v", err)
	}
	if err := f.policies.Put(f.record); !errors.Is(err, ErrPolicy) {
		t.Fatalf("revived revoked mandate: %v", err)
	}
}

func TestUncertainEffectNeedsAuthoritativeReconciliation(t *testing.T) {
	f := newFixture(t)
	f.service.executors["reports.read"] = func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
		f.calls.Add(1)
		return lp.EffectResult{}, errors.New("response lost")
	}
	cap := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op, nil)
	result, err := f.service.Execute(context.Background(), f.op, proof, transport, cap)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || result.State != lp.ExecutionUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	proof, transport = f.proof(t, "execute", f.op, nil)
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, cap); !errors.Is(err, lp.ErrOutcomeUnknown) || f.calls.Load() != 1 {
		t.Fatalf("blind retry=%v calls=%d", err, f.calls.Load())
	}
	proof, transport = f.proof(t, "reconcile", f.op, nil)
	if _, err := f.service.Reconcile(context.Background(), f.op, proof, transport); !errors.Is(err, lp.ErrOutcomeUnknown) {
		t.Fatalf("unconfigured query=%v", err)
	}
	queries := 0
	f.service.reconcilers["reports.read"] = func(_ context.Context, r lp.ExecutionRecord, request lp.Request) (lp.EffectResult, error) {
		queries++
		if r.OperationID != result.OperationID || r.RequestDigest != result.RequestDigest || request.ActorID != f.record.Mandate.ActorID {
			return lp.EffectResult{}, lp.ErrBinding
		}
		if queries == 1 {
			return lp.EffectResult{}, errors.New("authoritative service unavailable")
		}
		return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("authoritative readback")}, nil
	}
	proof, transport = f.proof(t, "execute", f.op, nil)
	if _, err := f.service.Reconcile(context.Background(), f.op, proof, transport); err == nil || queries != 0 {
		t.Fatalf("execution proof used for reconciliation=%v queries=%d", err, queries)
	}
	proof, transport = f.proof(t, "reconcile", f.op, nil)
	if _, err := f.service.Reconcile(context.Background(), f.op, proof, transport); !errors.Is(err, lp.ErrOutcomeUnknown) {
		t.Fatalf("missing authoritative evidence=%v", err)
	}
	proof, transport = f.proof(t, "reconcile", f.op, nil)
	if recovered, err := f.service.Reconcile(context.Background(), f.op, proof, transport); err != nil || recovered.State != lp.ExecutionSucceeded {
		t.Fatalf("authenticated reconciliation=%+v err=%v", recovered, err)
	}
	if _, err := f.service.Reconcile(context.Background(), f.op, proof, transport); err == nil || queries != 2 {
		t.Fatalf("replayed reconciliation proof=%v queries=%d", err, queries)
	}
	proof, transport = f.proof(t, "execute", f.op, nil)
	result, err = f.service.Execute(context.Background(), f.op, proof, transport, cap)
	if err != nil || result.State != lp.ExecutionSucceeded || f.calls.Load() != 1 {
		t.Fatalf("reconciled=%+v error=%v calls=%d", result, err, f.calls.Load())
	}
}

func TestPolicySnapshotAndExpiryCannotBeExtended(t *testing.T) {
	f := newFixture(t)
	f.record.Problem.Permissions[0].Cost = 100
	_ = f.capability(t) // installed policy owns its original model
	f.record.Mandate.ExpiresAt = f.record.Mandate.ExpiresAt.Add(time.Hour)
	f.record.Problem.Permissions[0].Cost = 1
	if err := f.policies.Put(f.record); !errors.Is(err, ErrPolicy) {
		t.Fatalf("extended mandate=%v", err)
	}
}

func TestReconciliationClockAdvancePreservesUnknown(t *testing.T) {
	f := newFixture(t)
	f.service.executors["reports.read"] = func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error) {
		f.calls.Add(1)
		return lp.EffectResult{}, errors.New("response lost")
	}
	capability := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op, nil)
	initial, err := f.service.Execute(context.Background(), f.op, proof, transport, capability)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || initial.State != lp.ExecutionUnknown {
		t.Fatalf("initial execution=%+v err=%v", initial, err)
	}
	proof, transport = f.proof(t, "reconcile", f.op, nil)
	f.service.reconcilers["reports.read"] = func(context.Context, lp.ExecutionRecord, lp.Request) (lp.EffectResult, error) {
		// The configured authority clock can advance independently of a
		// context timer's monotonic deadline (for example a clock correction).
		f.now = transport.ChallengeExpiresAt.Add(time.Second)
		return lp.EffectResult{State: lp.ExecutionSucceeded, EvidenceDigest: testDigest("authoritative readback")}, nil
	}
	result, err := f.service.Reconcile(context.Background(), f.op, proof, transport)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || !errors.Is(err, lp.ErrExpired) || result.State != lp.ExecutionUnknown {
		t.Fatalf("expired reconciliation=%+v err=%v", result, err)
	}
	stored, err := f.store.Lookup(context.Background(), initial.OperationID, initial.RequestDigest)
	if err != nil || stored.State != lp.ExecutionUnknown || f.calls.Load() != 1 {
		t.Fatalf("stored=%+v err=%v dispatches=%d", stored, err, f.calls.Load())
	}
}
