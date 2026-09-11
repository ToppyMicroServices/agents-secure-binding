// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
	"github.com/golang-jwt/jwt/v5"
)

type asbFixture struct {
	service          *asbbinding.Service
	policies         *asbbinding.Policies
	record           asbbinding.PolicyRecord
	op               asbbinding.Operation
	solution         lp.Solution
	authority, actor ed25519.PrivateKey
	nonce            atomic.Uint64
	getCalls         atomic.Int32
	now              time.Time
}

func newASBFixture(t *testing.T, uncertain bool) *asbFixture {
	t.Helper()
	e, solution, request, _ := fakeExecutor(t)
	f := &asbFixture{policies: asbbinding.NewPolicies(), solution: solution, now: time.Now().UTC().Truncate(time.Second)}
	_, authority, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.authority = authority
	_, actor, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.actor = actor
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := lp.CreateDurableStore(filepath.Join(t.TempDir(), "journal"), 100)
	if err != nil {
		t.Fatal(err)
	}
	f.op = asbbinding.Operation{ID: "s3-operation", MandateID: "s3-mandate", Action: request.Action}
	problem, err := lp.DigestProblem(e.profile.Problem())
	if err != nil {
		t.Fatal(err)
	}
	action, err := lp.DigestAction(request.Action)
	if err != nil {
		t.Fatal(err)
	}
	f.record = asbbinding.PolicyRecord{Problem: e.profile.Problem(), Mandate: lp.Mandate{ID: f.op.MandateID, PolicyRef: e.profile.Digest(), ActorID: request.ActorID, TaskID: request.TaskID, ActionDigest: action, ProblemDigest: problem, NotBefore: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Hour), MaxTTLSeconds: 60, AllowAutomatic: true}}
	if err := f.policies.Put(f.record); err != nil {
		t.Fatal(err)
	}
	e.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		f.getCalls.Add(1)
		if uncertain {
			return nil, errors.New("response lost after dispatch")
		}
		return goodResponse(), nil
	})
	f.service, err = asbbinding.NewService(asbbinding.Config{Policies: f.policies, Store: store, Issuer: "authority", Audience: "s3-executor", GrantKeys: map[string]ed25519.PublicKey{"authority-key": authority.Public().(ed25519.PublicKey)}, ActorKeys: map[string]ed25519.PublicKey{"actor-key": actor.Public().(ed25519.PublicKey)}, SigningKey: signer, MaxEvaluations: 4, Executors: map[string]asbbinding.Executor{Operation: e.Execute}, Clock: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func testHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func (f *asbFixture) proof(t *testing.T, mode string, op asbbinding.Operation) (asbbinding.Proof, asbbinding.Transport) {
	t.Helper()
	digest, err := asbbinding.ContextDigest(mode, op)
	if err != nil {
		t.Fatal(err)
	}
	nonce := f.nonce.Add(1)
	hash := sha256.Sum256([]byte(fmt.Sprint(nonce)))
	transport := asbbinding.Transport{Binding: identitypolicy.BindingV2{EndpointRole: "client-tls-endpoint", InteractionType: "agent-to-tool", AcceptedEndpointSPKISHA256: testHash("endpoint"), TLSExporterSHA256: testHash("exporter"), BindingContextSHA256: digest, VerifierNonce: base64.RawURLEncoding.EncodeToString(hash[:]), IssuedAt: f.now, ExpiresAt: f.now.Add(time.Minute)}, EndpointCredentialExpiresAt: f.now.Add(time.Hour), ChallengeExpiresAt: f.now.Add(time.Minute)}
	grantClaims := jwt.MapClaims{"iss": "authority", "sub": f.record.Mandate.ActorID, "aud": "s3-executor", "jti": fmt.Sprintf("grant-%d", nonce), "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), clients.ClaimTokenType: clients.TokenTypeIdentityGrant, clients.ClaimProfileVersion: clients.ProfileVersion, "cnf": map[string]any{"kid": "actor-key"}, "agent": f.record.Mandate.ActorID, "task_id": f.record.Mandate.TaskID, "target_resource": op.Action.Resource, "target_operation": op.Action.Operation, "capability_ref": f.record.Mandate.PolicyRef, "scope": op.Action.Operation, "resource": op.Action.Resource, "authorization_details": []string{asbbinding.AuthorizationDetail(mode, op, digest)}}
	sign := func(claims jwt.MapClaims, kid, typ string, key ed25519.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
		token.Header["kid"], token.Header["typ"] = kid, typ
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	grant := sign(grantClaims, "authority-key", clients.IdentityGrantJWTTypeV2, f.authority)
	b := transport.Binding
	proofClaims := jwt.MapClaims{"iss": f.record.Mandate.ActorID, "aud": "s3-executor", "jti": fmt.Sprintf("proof-%d", nonce), "iat": f.now.Unix(), "exp": f.now.Add(time.Minute).Unix(), clients.ClaimTokenType: clients.TokenTypeSessionBinding, clients.ClaimProfileVersion: clients.ProfileVersionV2, "grant_hash": clients.IdentityGrantHash(grant), "endpoint_role": b.EndpointRole, "interaction_type": b.InteractionType, "accepted_endpoint_spki_sha256": b.AcceptedEndpointSPKISHA256, "tls_exporter_sha256": b.TLSExporterSHA256, "binding_context_sha256": b.BindingContextSHA256, "verifier_nonce": b.VerifierNonce}
	return asbbinding.Proof{GrantJWT: grant, SessionBindingJWT: sign(proofClaims, "actor-key", clients.SessionBindingJWTTypeV2, f.actor)}, transport
}

func (f *asbFixture) capability(t *testing.T) lp.Capability {
	t.Helper()
	proof, transport := f.proof(t, "authorize", f.op)
	capability, err := f.service.Authorize(context.Background(), f.op, proof, transport, f.solution)
	if err != nil {
		t.Fatal(err)
	}
	return capability
}

func TestASBServiceRunsActualRestrictedAWSExecutorOnce(t *testing.T) {
	f := newASBFixture(t, false)
	capability := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op)
	result, err := f.service.Execute(context.Background(), f.op, proof, transport, capability)
	if err != nil || result.State != lp.ExecutionSucceeded || f.getCalls.Load() != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, capability); err == nil {
		t.Fatal("accepted ASB proof replay")
	}
	proof, transport = f.proof(t, "execute", f.op)
	again, err := f.service.Execute(context.Background(), f.op, proof, transport, capability)
	if err != nil || again.EvidenceDigest != result.EvidenceDigest || f.getCalls.Load() != 1 {
		t.Fatal("completed retry redispatched GET", err)
	}
	if err := f.policies.Revoke(f.op.MandateID); err != nil {
		t.Fatal(err)
	}
	proof, transport = f.proof(t, "execute", f.op)
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, capability); err == nil || f.getCalls.Load() != 1 {
		t.Fatal("revoked policy admitted request")
	}
}

func TestASBServiceRejectsChangedAWSActionAndPolicy(t *testing.T) {
	for _, change := range []string{"resource", "arguments", "model", "human"} {
		t.Run(change, func(t *testing.T) {
			f := newASBFixture(t, false)
			capability := f.capability(t)
			op := f.op
			switch change {
			case "resource":
				op.Action.Resource = extraARN
			case "arguments":
				op.Action.Arguments = []byte(strings.ReplaceAll(string(op.Action.Arguments), `"range_end":3`, `"range_end":2`))
			case "model":
				f.record.Problem.Permissions[0].Cost++
				digest, err := lp.DigestProblem(f.record.Problem)
				if err != nil {
					t.Fatal(err)
				}
				f.record.Mandate.ProblemDigest = digest
				if err := f.policies.Put(f.record); err != nil {
					t.Fatal(err)
				}
			case "human":
				f.record.Mandate.AllowAutomatic = false
				if err := f.policies.Put(f.record); err != nil {
					t.Fatal(err)
				}
			}
			proof, transport := f.proof(t, "execute", op)
			if _, err := f.service.Execute(context.Background(), op, proof, transport, capability); err == nil || f.getCalls.Load() != 0 {
				t.Fatal("changed action/current policy dispatched AWS")
			}
		})
	}
}

func TestASBServiceKeepsUncertainGetUnknownWithoutRetry(t *testing.T) {
	f := newASBFixture(t, true)
	capability := f.capability(t)
	proof, transport := f.proof(t, "execute", f.op)
	result, err := f.service.Execute(context.Background(), f.op, proof, transport, capability)
	if !errors.Is(err, lp.ErrOutcomeUnknown) || result.State != lp.ExecutionUnknown {
		t.Fatalf("%+v %v", result, err)
	}
	proof, transport = f.proof(t, "execute", f.op)
	if _, err := f.service.Execute(context.Background(), f.op, proof, transport, capability); !errors.Is(err, lp.ErrOutcomeUnknown) || f.getCalls.Load() != 1 {
		t.Fatal("uncertain GET redispatched", err)
	}
}
