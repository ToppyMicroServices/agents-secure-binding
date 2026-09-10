// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const CapabilitySchemaV1 = "asb.least-privilege.capability/v1"

var (
	ErrInvalidMandate    = errors.New("least privilege: invalid trusted mandate")
	ErrHumanRequired     = errors.New("least privilege: human approval required")
	ErrBinding           = errors.New("least privilege: action or authority binding mismatch")
	ErrExpired           = errors.New("least privilege: outside authorization lifetime")
	ErrInvalidCapability = errors.New("least privilege: invalid capability")
	ErrReplay            = errors.New("least privilege: mandate already consumed")
	ErrCapacity          = errors.New("least privilege: use store capacity reached")
)

// Action identifies the exact effect. Arguments are opaque bytes: changing even
// JSON whitespace changes the digest. The executor must dispatch these same
// bytes, operation and resource after checking the capability.
type Action struct {
	Operation string `json:"operation"`
	Resource  string `json:"resource"`
	Arguments []byte `json:"arguments"`
}

// Request must be constructed from authenticated actor/task context. This
// package does not authenticate the actor or establish an ASB session.
type Request struct {
	ActorID string `json:"actor_id"`
	TaskID  string `json:"task_id"`
	Action  Action `json:"action"`
}

// Mandate is trusted policy, supplied by an operator or authenticated policy
// authority, never by the requesting model. It permits at most one execution.
// A new execution needs a new ID. AllowAutomatic defaults to false.
type Mandate struct {
	ID             string    `json:"id"`
	PolicyRef      string    `json:"policy_ref"`
	ActorID        string    `json:"actor_id"`
	TaskID         string    `json:"task_id"`
	ActionDigest   string    `json:"action_digest"`
	ProblemDigest  string    `json:"problem_digest"`
	NotBefore      time.Time `json:"not_before"`
	ExpiresAt      time.Time `json:"expires_at"`
	MaxTTLSeconds  uint32    `json:"max_ttl_seconds"`
	AllowAutomatic bool      `json:"allow_automatic"`
}

// CapabilityClaims carry the candidate that was independently checked before
// issuance. The signature attests to a trusted authorizer's decision; it is not
// a portable mathematical proof of optimality. Verify can recheck the candidate.
type CapabilityClaims struct {
	Schema        string    `json:"schema"`
	ID            string    `json:"id"`
	MandateID     string    `json:"mandate_id"`
	MandateDigest string    `json:"mandate_digest"`
	PolicyRef     string    `json:"policy_ref"`
	ActorID       string    `json:"actor_id"`
	TaskID        string    `json:"task_id"`
	ActionDigest  string    `json:"action_digest"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Solution      Solution  `json:"solution"`
}

type Capability struct {
	Claims    CapabilityClaims `json:"claims"`
	Signature []byte           `json:"signature"`
}

type AuthorizerConfig struct {
	Problem        Problem
	Mandate        Mandate
	SigningKey     ed25519.PrivateKey
	MaxEvaluations uint64
	Clock          func() time.Time
}

// Authorizer is an immutable snapshot of trusted inputs. Executors must still
// compare each capability with the CURRENT mandate to enforce policy changes.
type Authorizer struct {
	problem Problem
	mandate Mandate
	key     ed25519.PrivateKey
	budget  uint64
	clock   func() time.Time
}

func NewAuthorizer(c AuthorizerConfig) (*Authorizer, error) {
	digest, err := DigestProblem(c.Problem)
	if err != nil {
		return nil, err
	}
	if err := validateMandate(c.Mandate); err != nil {
		return nil, err
	}
	if digest != c.Mandate.ProblemDigest {
		return nil, ErrBinding
	}
	if len(c.SigningKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(ed25519.NewKeyFromSeed(c.SigningKey[:ed25519.SeedSize]), c.SigningKey) {
		return nil, fmt.Errorf("%w: invalid signing key", ErrInvalidMandate)
	}
	if c.MaxEvaluations == 0 {
		return nil, ErrLimit
	}
	// Own all slices. Caller mutations cannot change an approved search space.
	raw, err := json.Marshal(c.Problem)
	if err != nil {
		return nil, err
	}
	var snapshot Problem
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Authorizer{
		problem: snapshot, mandate: c.Mandate,
		key:    append(ed25519.PrivateKey(nil), c.SigningKey...),
		budget: c.MaxEvaluations, clock: clock,
	}, nil
}

// Authorize accepts a solver or model candidate only after independent exact
// verification. No capability is returned on a partial search or failed check.
func (a *Authorizer) Authorize(ctx context.Context, request Request, candidate Solution) (Capability, error) {
	if a == nil || a.clock == nil || ctx == nil {
		return Capability{}, ErrInvalidMandate
	}
	if err := ctx.Err(); err != nil {
		return Capability{}, err
	}
	if len(candidate.Grants) > MaxGrants || len(candidate.Effective) > MaxPermissions {
		return Capability{}, ErrInvalidSolution
	}
	// Snapshot before callbacks: verification and signing must see the same
	// candidate even if the caller reuses its proposal buffers meanwhile.
	candidate.Grants = append([]string(nil), candidate.Grants...)
	candidate.Effective = append([]string(nil), candidate.Effective...)
	if err := checkRequest(a.mandate, request, a.clock()); err != nil {
		return Capability{}, err
	}
	if err := Verify(ctx, a.problem, candidate, a.budget); err != nil {
		return Capability{}, err
	}
	// Verification may be slow. Do not use the pre-verification timestamp.
	now := a.clock().UTC()
	if err := checkRequest(a.mandate, request, now); err != nil {
		return Capability{}, err
	}
	if err := ctx.Err(); err != nil {
		return Capability{}, err
	}
	md, err := DigestMandate(a.mandate)
	if err != nil {
		return Capability{}, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Capability{}, err
	}
	expires := now.Add(time.Duration(a.mandate.MaxTTLSeconds) * time.Second)
	if expires.After(a.mandate.ExpiresAt) {
		expires = a.mandate.ExpiresAt.UTC()
	}
	claims := CapabilityClaims{
		Schema: CapabilitySchemaV1, ID: hex.EncodeToString(id),
		MandateID: a.mandate.ID, MandateDigest: md, PolicyRef: a.mandate.PolicyRef,
		ActorID: request.ActorID, TaskID: request.TaskID, ActionDigest: a.mandate.ActionDigest,
		IssuedAt: now, ExpiresAt: expires, Solution: candidate,
	}
	message, err := capabilityMessage(claims)
	if err != nil {
		return Capability{}, err
	}
	signature := ed25519.Sign(a.key, message)
	if err := ctx.Err(); err != nil {
		return Capability{}, err
	}
	return Capability{Claims: claims, Signature: signature}, nil
}

// CheckCapability verifies an authority signature, the current trusted mandate,
// and the exact authenticated request. It does NOT consume execution authority.
// Use ConsumeCapability at the execution boundary to enforce single use.
func CheckCapability(cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || len(cap.Signature) != ed25519.SignatureSize {
		return ErrInvalidCapability
	}
	message, err := capabilityMessage(cap.Claims)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, message, cap.Signature) {
		return ErrInvalidCapability
	}
	if err := validateMandate(current); err != nil {
		return err
	}
	if err := checkRequest(current, request, now); err != nil {
		return err
	}
	md, err := DigestMandate(current)
	if err != nil {
		return err
	}
	c := cap.Claims
	if c.MandateID != current.ID || c.MandateDigest != md || c.PolicyRef != current.PolicyRef ||
		c.ActorID != request.ActorID || c.TaskID != request.TaskID || c.ActionDigest != current.ActionDigest ||
		c.Solution.ProblemDigest != current.ProblemDigest {
		return ErrBinding
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) ||
		c.IssuedAt.Before(current.NotBefore) || c.IssuedAt.After(now) || !now.Before(c.ExpiresAt) ||
		c.ExpiresAt.After(current.ExpiresAt) ||
		c.ExpiresAt.Sub(c.IssuedAt) > time.Duration(current.MaxTTLSeconds)*time.Second {
		return ErrExpired
	}
	return nil
}

// UseStore atomically consumes a mandate ID until its expiry. Implementations
// must not evict unexpired records or allow parallel callers to both succeed.
// Persistent storage and atomic coupling to effects belong to the deployment.
type UseStore interface {
	Use(ctx context.Context, key string, expiresAt, now time.Time) error
}

// ConsumeCapability provides at-most-once admission across ALL capabilities for
// the same mandate, including re-issued ones. A crash after consumption can lose
// the operation; this is not an exactly-once external-effect transaction.
func ConsumeCapability(ctx context.Context, cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time, uses UseStore) error {
	if ctx == nil || uses == nil {
		return ErrInvalidCapability
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := CheckCapability(cap, key, current, request, now); err != nil {
		return err
	}
	// Mandate IDs are globally unique within a UseStore, also across key rotation.
	return uses.Use(ctx, "asb.least-privilege/"+current.ID, current.ExpiresAt, now)
}

func DigestAction(action Action) (string, error) {
	if !boundedText(action.Operation, 256) || !boundedText(action.Resource, 2048) || len(action.Arguments) > 64<<10 {
		return "", ErrBinding
	}
	if action.Arguments == nil {
		action.Arguments = []byte{}
	}
	return digestValue("asb.least-privilege.action/v1", action)
}

func DigestMandate(m Mandate) (string, error) {
	if err := validateMandate(m); err != nil {
		return "", err
	}
	m.NotBefore, m.ExpiresAt = m.NotBefore.UTC(), m.ExpiresAt.UTC()
	return digestValue("asb.least-privilege.mandate/v1", m)
}

// DigestCapability is an evidence reference, never a substitute for verification.
func DigestCapability(c Capability) (string, error) {
	if _, err := capabilityMessage(c.Claims); err != nil {
		return "", err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return "", ErrInvalidCapability
	}
	return digestValue("asb.least-privilege.evidence/v1", c)
}

func validateMandate(m Mandate) error {
	if !boundedText(m.ID, 256) || !boundedText(m.PolicyRef, 2048) || !boundedText(m.ActorID, 256) ||
		!boundedText(m.TaskID, 256) || !canonicalDigest(m.ActionDigest) || !canonicalDigest(m.ProblemDigest) ||
		m.NotBefore.IsZero() || m.ExpiresAt.IsZero() || !m.ExpiresAt.After(m.NotBefore) ||
		m.MaxTTLSeconds == 0 || m.MaxTTLSeconds > 3600 {
		return ErrInvalidMandate
	}
	return nil
}

func checkRequest(m Mandate, r Request, now time.Time) error {
	if now.IsZero() || now.Before(m.NotBefore) || !now.Before(m.ExpiresAt) {
		return ErrExpired
	}
	digest, err := DigestAction(r.Action)
	if err != nil {
		return err
	}
	if r.ActorID != m.ActorID || r.TaskID != m.TaskID || digest != m.ActionDigest {
		return ErrBinding
	}
	if !m.AllowAutomatic {
		return ErrHumanRequired
	}
	return nil
}

func capabilityMessage(c CapabilityClaims) ([]byte, error) {
	if c.Schema != CapabilitySchemaV1 || len(c.ID) != 64 || !canonicalDigest("sha256:"+c.ID) ||
		!boundedText(c.MandateID, 256) || !boundedText(c.PolicyRef, 2048) ||
		!boundedText(c.ActorID, 256) || !boundedText(c.TaskID, 256) ||
		!canonicalDigest(c.MandateDigest) || !canonicalDigest(c.ActionDigest) ||
		c.Solution.Schema != SolutionSchemaV1 || !canonicalDigest(c.Solution.ProblemDigest) ||
		len(c.Solution.Grants) > MaxGrants || len(c.Solution.Effective) > MaxPermissions {
		return nil, ErrInvalidCapability
	}
	for _, set := range [][]string{c.Solution.Grants, c.Solution.Effective} {
		for _, id := range set {
			if !boundedText(id, 256) {
				return nil, ErrInvalidCapability
			}
		}
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append([]byte(CapabilitySchemaV1+"\x00"), raw...), nil
}

func digestValue(domain string, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain+"\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}

func boundedText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
