// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package asbbinding authenticates least-privilege operations with ASB v2
// proofs, current operator policy and durable single-use execution.
package asbbinding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const ProtocolID = "urn:asb:least-privilege:execution:v1"

var (
	ErrPolicy    = errors.New("least privilege ASB: policy unavailable or invalid")
	ErrTransport = errors.New("least privilege ASB: invalid trusted transport binding")
)

// PolicyRecord is installed by the operator. The requesting agent never
// supplies the problem, mandate or verification keys to the service.
type PolicyRecord struct {
	Problem lp.Problem `json:"problem"`
	Mandate lp.Mandate `json:"mandate"`
}

type policyEntry struct {
	record  PolicyRecord
	revoked bool
}

// Policies serializes operator updates with admissions within one authority
// process. All handlers of that authority must share this instance. It is not
// a distributed policy store. Restart requires loading current trusted policy.
type Policies struct {
	mu      sync.RWMutex
	entries map[string]policyEntry
}

func NewPolicies() *Policies { return &Policies{entries: make(map[string]policyEntry)} }

// Put snapshots policy. An existing mandate cannot be revived after revocation
// or have its expiry extended. A new authority grant needs a new mandate ID.
func (p *Policies) Put(record PolicyRecord) error {
	if p == nil {
		return ErrPolicy
	}
	digest, err := lp.DigestProblem(record.Problem)
	if err != nil {
		return err
	}
	if _, err := lp.DigestMandate(record.Mandate); err != nil {
		return err
	}
	if digest != record.Mandate.ProblemDigest {
		return lp.ErrBinding
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	var owned PolicyRecord
	if err := json.Unmarshal(raw, &owned); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil {
		p.entries = make(map[string]policyEntry)
	}
	old, exists := p.entries[record.Mandate.ID]
	if exists && (old.revoked || record.Mandate.ExpiresAt.After(old.record.Mandate.ExpiresAt)) {
		return ErrPolicy
	}
	if !exists && len(p.entries) >= 4096 {
		return lp.ErrCapacity
	}
	p.entries[record.Mandate.ID] = policyEntry{record: owned}
	return nil
}

// Revoke waits for admissions already holding the guard, then prevents every
// later admission. It cannot undo an effect that has already been dispatched.
func (p *Policies) Revoke(id string) error {
	if p == nil {
		return ErrPolicy
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[id]
	if !ok {
		return ErrPolicy
	}
	e.revoked = true
	p.entries[id] = e
	return nil
}

// Operation has no caller-selected actor or task label. Those values are
// derived from the authenticated ASB result and matched to operator policy.
type Operation struct {
	ID        string    `json:"operation_id"`
	MandateID string    `json:"mandate_id"`
	Action    lp.Action `json:"action"`
}

type Proof struct {
	GrantJWT          string `json:"grant_jwt"`
	SessionBindingJWT string `json:"session_binding_jwt"`
}

// Transport is verifier-local evidence from the accepted TLS connection and
// server challenge registry. Never deserialize it from a peer request/header.
// This profile is software-only and rejects attestation binders.
type Transport struct {
	Binding                     identitypolicy.BindingV2
	EndpointCredentialExpiresAt time.Time
	ChallengeExpiresAt          time.Time
}

// Executor must enforce the supplied verified permission set itself. Register
// operation-specific adapters; never register an arbitrary command dispatcher.
type Executor func(context.Context, string, lp.Request, lp.Solution) (lp.EffectResult, error)

// Reconciler queries authoritative downstream state. It must never dispatch or
// retry the operation. Missing or ambiguous evidence must remain UNKNOWN.
type Reconciler func(context.Context, lp.ExecutionRecord, lp.Request) (lp.EffectResult, error)

type Config struct {
	Policies       *Policies
	Store          *lp.DurableStore
	Issuer         string
	Audience       string
	GrantKeys      map[string]ed25519.PublicKey
	ActorKeys      map[string]ed25519.PublicKey
	SigningKey     ed25519.PrivateKey
	Executors      map[string]Executor
	Reconcilers    map[string]Reconciler
	MaxEvaluations uint64
	Clock          func() time.Time
}

type Service struct {
	policies             *Policies
	store                *lp.DurableStore
	issuer, audience     string
	grantKeys, actorKeys []clients.LocalKey
	key                  ed25519.PrivateKey
	executors            map[string]Executor
	reconcilers          map[string]Reconciler
	budget               uint64
	clock                func() time.Time
}

func NewService(c Config) (*Service, error) {
	if c.Policies == nil || c.Store == nil || !identifier(c.Issuer) || !identifier(c.Audience) || c.MaxEvaluations == 0 ||
		len(c.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(c.SigningKey[:ed25519.SeedSize]), c.SigningKey) {
		return nil, ErrPolicy
	}
	grant, err := snapshotKeys(c.GrantKeys)
	if err != nil {
		return nil, err
	}
	actor, err := snapshotKeys(c.ActorKeys)
	if err != nil {
		return nil, err
	}
	for id, key := range c.ActorKeys {
		if _, ok := c.GrantKeys[id]; ok {
			return nil, ErrPolicy
		}
		for _, authority := range c.GrantKeys {
			if bytes.Equal(key, authority) {
				return nil, ErrPolicy
			}
		}
	}
	executors := make(map[string]Executor, len(c.Executors))
	for op, execute := range c.Executors {
		if !identifier(op) || execute == nil {
			return nil, ErrPolicy
		}
		executors[op] = execute
	}
	if len(executors) == 0 {
		return nil, ErrPolicy
	}
	reconcilers := make(map[string]Reconciler, len(c.Reconcilers))
	for op, reconcile := range c.Reconcilers {
		if executors[op] == nil || reconcile == nil {
			return nil, ErrPolicy
		}
		reconcilers[op] = reconcile
	}
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{
		policies: c.Policies, store: c.Store, issuer: c.Issuer, audience: c.Audience,
		grantKeys: grant, actorKeys: actor, key: append(ed25519.PrivateKey(nil), c.SigningKey...),
		executors: executors, reconcilers: reconcilers, budget: c.MaxEvaluations, clock: clock,
	}, nil
}

// Authorize requires an ASB proof for the authorize operation, then independently
// verifies the candidate. Execute requires a separate fresh ASB proof.
func (s *Service) Authorize(ctx context.Context, op Operation, proof Proof, transport Transport, candidate lp.Solution) (lp.Capability, error) {
	var result lp.Capability
	err := s.withPolicy(ctx, op, func(record PolicyRecord, owned Operation) error {
		request, err := s.authenticate(ctx, "authorize", owned, proof, transport, record)
		if err != nil {
			return err
		}
		authorizer, err := lp.NewAuthorizer(lp.AuthorizerConfig{Problem: record.Problem, Mandate: record.Mandate, SigningKey: s.key, MaxEvaluations: s.budget, Clock: s.clock})
		if err != nil {
			return err
		}
		verificationContext, cancel := context.WithDeadline(ctx, request.ExpiresAt)
		defer cancel()
		result, err = authorizer.Authorize(verificationContext, request.Request, candidate)
		if err == nil && !s.clock().Before(request.ExpiresAt) {
			result = lp.Capability{}
			return lp.ErrExpired
		}
		return err
	})
	return result, err
}

// Execute holds the policy read guard through durable admission and dispatch.
// Operator changes take the write guard: once an update returns, no operation
// using the previous policy can begin dispatch in this authority process.
func (s *Service) Execute(ctx context.Context, op Operation, proof Proof, transport Transport, capability lp.Capability) (lp.ExecutionRecord, error) {
	var result lp.ExecutionRecord
	// Bound before serialization, then snapshot all mutable capability slices.
	if !boundedCapability(capability) {
		return result, lp.ErrInvalidCapability
	}
	raw, err := json.Marshal(capability)
	if err != nil || len(raw) > 1<<20 {
		return result, lp.ErrInvalidCapability
	}
	var cap lp.Capability
	if err := json.Unmarshal(raw, &cap); err != nil {
		return result, err
	}
	err = s.withPolicy(ctx, op, func(record PolicyRecord, owned Operation) error {
		request, err := s.authenticate(ctx, "execute", owned, proof, transport, record)
		if err != nil {
			return err
		}
		executor := s.executors[request.Action.Operation]
		deadline := request.ExpiresAt
		if cap.Claims.ExpiresAt.Before(deadline) {
			deadline = cap.Claims.ExpiresAt
		}
		executionContext, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		result, err = s.store.Run(executionContext, owned.ID, cap, s.key.Public().(ed25519.PublicKey), record.Mandate, request.Request, s.clock(),
			func(ctx context.Context, id string, exact lp.Request) (lp.EffectResult, error) {
				// The ASB proof may expire while waiting for durable admission.
				if !s.clock().Before(request.ExpiresAt) || !s.clock().Before(transport.Binding.ExpiresAt) || !s.clock().Before(transport.ChallengeExpiresAt) || !s.clock().Before(transport.EndpointCredentialExpiresAt) {
					return lp.EffectResult{}, lp.ErrExpired
				}
				return executor(ctx, id, exact, cap.Claims.Solution)
			})
		return err
	})
	return result, err
}

// Reconcile authenticates a fresh, separately authorized query and consults only
// an operator-registered adapter. No caller-supplied outcome is accepted. The
// original current mandate must still be valid and unchanged; expired, revoked
// or replaced mandates require a separate trusted operator recovery procedure.
func (s *Service) Reconcile(ctx context.Context, op Operation, proof Proof, transport Transport) (lp.ExecutionRecord, error) {
	var result lp.ExecutionRecord
	err := s.withPolicy(ctx, op, func(record PolicyRecord, owned Operation) error {
		request, err := s.authenticate(ctx, "reconcile", owned, proof, transport, record)
		if err != nil {
			return err
		}
		queryContext, cancel := context.WithDeadline(ctx, request.ExpiresAt)
		defer cancel()
		digest, err := lp.DigestExecution(owned.ID, record.Mandate, request.Request)
		if err != nil {
			return err
		}
		result, err = s.store.Lookup(queryContext, owned.ID, digest)
		if err != nil || result.Terminal() {
			return err
		}
		query := s.reconcilers[owned.Action.Operation]
		if query == nil || result.State == lp.ExecutionAccepted {
			return lp.ErrOutcomeUnknown
		}
		evidence, err := query(queryContext, result, request.Request)
		if err != nil || queryContext.Err() != nil || (evidence.State != lp.ExecutionSucceeded && evidence.State != lp.ExecutionFailed) {
			return errors.Join(lp.ErrOutcomeUnknown, err, queryContext.Err())
		}
		if !s.clock().Before(request.ExpiresAt) {
			return errors.Join(lp.ErrOutcomeUnknown, lp.ErrExpired)
		}
		completed, err := s.store.Complete(queryContext, owned.ID, digest, evidence.State, evidence.EvidenceDigest)
		if err != nil {
			return errors.Join(lp.ErrOutcomeUnknown, err)
		}
		result = completed
		return nil
	})
	return result, err
}

func (s *Service) withPolicy(ctx context.Context, op Operation, fn func(PolicyRecord, Operation) error) error {
	if s == nil || ctx == nil {
		return ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !identifier(op.ID) || !identifier(op.MandateID) {
		return lp.ErrBinding
	}
	if _, err := lp.DigestAction(op.Action); err != nil {
		return err
	}
	op.Action.Arguments = append([]byte(nil), op.Action.Arguments...)
	s.policies.mu.RLock()
	defer s.policies.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	entry, ok := s.policies.entries[op.MandateID]
	if !ok || entry.revoked {
		return ErrPolicy
	}
	if s.executors[op.Action.Operation] == nil {
		return lp.ErrBinding
	}
	digest, _ := lp.DigestAction(op.Action)
	if digest != entry.record.Mandate.ActionDigest {
		return lp.ErrBinding
	}
	return fn(entry.record, op)
}

type authenticatedRequest struct {
	lp.Request
	ExpiresAt time.Time
}

func (s *Service) authenticate(ctx context.Context, mode string, op Operation, proof Proof, transport Transport, record PolicyRecord) (authenticatedRequest, error) {
	if err := ctx.Err(); err != nil {
		return authenticatedRequest{}, err
	}
	if len(proof.GrantJWT) > 64<<10 || len(proof.SessionBindingJWT) > 64<<10 {
		return authenticatedRequest{}, lp.ErrBinding
	}
	digest, err := ContextDigest(mode, op)
	if err != nil {
		return authenticatedRequest{}, err
	}
	binding := transport.Binding
	if binding.BindingContextSHA256 != digest || binding.AttestationBinderSHA256 != "" ||
		binding.EndpointRole != "client-tls-endpoint" || binding.InteractionType != "agent-to-tool" {
		return authenticatedRequest{}, ErrTransport
	}
	now := s.clock()
	if now.Before(record.Mandate.NotBefore) || !now.Before(record.Mandate.ExpiresAt) {
		return authenticatedRequest{}, lp.ErrExpired
	}
	options := clients.SessionIdentityJWTOptionsV2{
		Grant:          clients.JWTVerifyOptions{ExpectedIssuer: s.issuer, ExpectedAudience: s.audience, ValidMethods: []string{"EdDSA"}, LocalKeys: s.grantKeys},
		SessionBinding: clients.JWTVerifyOptions{ExpectedIssuer: record.Mandate.ActorID, ExpectedAudience: s.audience, ValidMethods: []string{"EdDSA"}, LocalKeys: s.actorKeys},
		Policy: identitypolicy.PolicyV2{
			Mode: identitypolicy.ModeRequired, SetMode: identitypolicy.SetModeExact,
			Require:        identitypolicy.RequirementsV2{D4: true, D5: true, D6: true, D7: true},
			Expected:       identitypolicy.Values{Agent: record.Mandate.ActorID, TaskID: record.Mandate.TaskID},
			ExpectedTarget: identitypolicy.TargetV2{Resource: op.Action.Resource, Operation: op.Action.Operation},
			ExpectedAuthorization: identitypolicy.AuthorizationV2{
				CapabilityRef: record.Mandate.PolicyRef,
				Scopes:        []string{op.Action.Operation}, Resources: []string{op.Action.Resource}, AuthorizationDetails: []string{AuthorizationDetail(mode, op, digest)},
			},
		},
		ExpectedBinding: binding,
		AcceptedProfile: identitypolicy.ProfileSelectionV2{ProfileType: clients.TokenTypeSessionBinding, ProfileVersion: clients.ProfileVersionV2, BindingProfile: "draft06-v2", ProtocolID: ProtocolID},
		Freshness: identitypolicy.FreshnessInputsV2{
			EndpointCredentialExpiresAt: transport.EndpointCredentialExpiresAt,
			EvidenceChallengeExpiresAt:  transport.ChallengeExpiresAt, LocalPolicyExpiresAt: record.Mandate.ExpiresAt,
		},
		ReplayCache: durableReplay{s.store, s.clock, ctx}, Clock: s.clock, Now: now,
	}
	verified, err := clients.VerifySessionIdentityJWTV2(proof.GrantJWT, proof.SessionBindingJWT, options)
	if err != nil {
		return authenticatedRequest{}, fmt.Errorf("least privilege ASB authentication: %w", err)
	}
	accepted := verified.Accepted
	if accepted.ReplayCommit.State != identitypolicy.ReplayCommitStateCommittedV2 || !s.clock().Before(accepted.Expiry) {
		return authenticatedRequest{}, lp.ErrExpired
	}
	if !record.Mandate.AllowAutomatic {
		return authenticatedRequest{}, lp.ErrHumanRequired
	}
	return authenticatedRequest{Request: lp.Request{ActorID: accepted.AcceptedActor.ID, TaskID: accepted.AcceptedInteraction.TaskID, Action: op.Action}, ExpiresAt: accepted.Expiry}, nil
}

// ContextDigest domain-separates authorization and execution and binds their
// exact operation, mandate and action. It is also the verifier's TLS context.
func ContextDigest(mode string, op Operation) (string, error) {
	if (mode != "authorize" && mode != "execute" && mode != "reconcile") || !identifier(op.ID) || !identifier(op.MandateID) {
		return "", lp.ErrBinding
	}
	action, err := lp.DigestAction(op.Action)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct{ Mode, OperationID, MandateID, ActionDigest string }{mode, op.ID, op.MandateID, action})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte(ProtocolID+"\x00"), raw...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// AuthorizationDetail is the exact D7 detail that the ASB grant must authorize.
func AuthorizationDetail(mode string, op Operation, digest string) string {
	return ProtocolID + ":" + mode + ":" + op.MandateID + ":" + digest
}

func snapshotKeys(keys map[string]ed25519.PublicKey) ([]clients.LocalKey, error) {
	if len(keys) == 0 || len(keys) > 256 {
		return nil, ErrPolicy
	}
	result := make([]clients.LocalKey, 0, len(keys))
	for id, key := range keys {
		if !identifier(id) || len(key) != ed25519.PublicKeySize {
			return nil, ErrPolicy
		}
		result = append(result, clients.LocalKey{KeyID: id, Key: append(ed25519.PublicKey(nil), key...)})
	}
	return result, nil
}

func boundedCapability(cap lp.Capability) bool {
	c := cap.Claims
	if len(cap.Signature) != ed25519.SignatureSize || len(c.Schema) > 128 || len(c.ID) != 64 ||
		len(c.MandateID) > 256 || len(c.MandateDigest) != 71 || len(c.PolicyRef) > 2048 ||
		len(c.ActorID) > 256 || len(c.TaskID) > 256 || len(c.ActionDigest) != 71 ||
		len(c.Solution.Schema) > 128 || len(c.Solution.ProblemDigest) != 71 ||
		len(c.Solution.Grants) > lp.MaxGrants || len(c.Solution.Effective) > lp.MaxPermissions {
		return false
	}
	for _, ids := range [][]string{c.Solution.Grants, c.Solution.Effective} {
		for _, id := range ids {
			if len(id) > lp.MaxIDBytes {
				return false
			}
		}
	}
	return true
}

type durableReplay struct {
	store *lp.DurableStore
	clock func() time.Time
	ctx   context.Context
}

func (r durableReplay) MarkUsed(key string, expiry time.Time) error {
	err := r.store.Use(r.ctx, "asb.least-privilege.session/"+key, expiry, r.clock())
	if errors.Is(err, lp.ErrReplay) {
		return identitypolicy.ErrReplayDetected
	}
	return err
}

func identifier(s string) bool {
	if s == "" || len(s) > 256 || strings.TrimSpace(s) != s || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
