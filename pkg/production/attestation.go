// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidAttestationResult = errors.New("production: invalid attestation result")
	ErrUnknownAttestationKey    = errors.New("production: unknown attestation verifier key")
	ErrDisabledAttestationKey   = errors.New("production: disabled attestation verifier key")
	ErrAttestationSignature     = errors.New("production: invalid attestation result signature")
	ErrAttestationPolicy        = errors.New("production: attestation policy mismatch")
	ErrAttestationBinding       = errors.New("production: attestation binding mismatch")
	ErrAttestationExpired       = errors.New("production: expired attestation result")
	ErrAttestationFuture        = errors.New("production: attestation result issued in the future")
	ErrAttestationStale         = errors.New("production: stale attestation result")
)

const AttestationResultVersion = "asb-attestation-result/v1"

// AttestationResult is a signed appraisal result bound to one accepted TLS and
// application context. Signature contains an Ed25519 signature over
// SigningBytes.
type AttestationResult struct {
	Version                 string    `json:"version"`
	ResultID                string    `json:"result_id"`
	VerifierKeyID           string    `json:"verifier_key_id"`
	PolicyID                string    `json:"policy_id"`
	Measurement             string    `json:"measurement"`
	AttestationBinderSHA256 string    `json:"attestation_binder_sha256"`
	IssuedAt                time.Time `json:"issued_at"`
	ExpiresAt               time.Time `json:"expires_at"`
	Signature               []byte    `json:"signature"`
}

type attestationSigningPayload struct {
	Version                 string `json:"version"`
	ResultID                string `json:"result_id"`
	VerifierKeyID           string `json:"verifier_key_id"`
	PolicyID                string `json:"policy_id"`
	Measurement             string `json:"measurement"`
	AttestationBinderSHA256 string `json:"attestation_binder_sha256"`
	IssuedAt                string `json:"issued_at"`
	ExpiresAt               string `json:"expires_at"`
}

// SigningBytes returns the canonical bytes covered by the attestation-result
// signature.
func (r AttestationResult) SigningBytes() ([]byte, error) {
	if err := r.validateShape(); err != nil {
		return nil, err
	}
	payload := attestationSigningPayload{
		Version:                 r.Version,
		ResultID:                r.ResultID,
		VerifierKeyID:           r.VerifierKeyID,
		PolicyID:                r.PolicyID,
		Measurement:             r.Measurement,
		AttestationBinderSHA256: r.AttestationBinderSHA256,
		IssuedAt:                r.IssuedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:               r.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	return json.Marshal(payload)
}

// SignedAttestationPolicy verifies a signed result under a local verifier-key
// namespace and exact appraisal policy.
type SignedAttestationPolicy struct {
	TrustedKeys         map[string]ed25519.PublicKey
	DisabledKeyIDs      []string
	PolicyID            string
	AllowedMeasurements []string
	MaxAge              time.Duration
	ClockSkew           time.Duration
}

// Verify authenticates and appraises one result.
func (p SignedAttestationPolicy) Verify(_ context.Context, result AttestationResult, expectedBinder string, now time.Time) error {
	if p.ClockSkew < 0 || p.MaxAge <= 0 || len(p.TrustedKeys) == 0 || len(p.AllowedMeasurements) == 0 {
		return ErrAttestationPolicy
	}
	payload, err := result.SigningBytes()
	if err != nil {
		return err
	}
	if expectedBinder == "" || result.AttestationBinderSHA256 != expectedBinder {
		return ErrAttestationBinding
	}
	if p.PolicyID == "" || result.PolicyID != p.PolicyID {
		return ErrAttestationPolicy
	}
	if !contains(p.AllowedMeasurements, result.Measurement) {
		return ErrAttestationPolicy
	}
	if contains(p.DisabledKeyIDs, result.VerifierKeyID) {
		return ErrDisabledAttestationKey
	}
	key, ok := p.TrustedKeys[result.VerifierKeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return ErrUnknownAttestationKey
	}
	if !ed25519.Verify(key, payload, result.Signature) {
		return ErrAttestationSignature
	}
	if now.IsZero() {
		now = time.Now()
	}
	if result.IssuedAt.After(now.Add(p.ClockSkew)) {
		return ErrAttestationFuture
	}
	if now.After(result.ExpiresAt.Add(p.ClockSkew)) {
		return ErrAttestationExpired
	}
	if now.Sub(result.IssuedAt) > p.MaxAge+p.ClockSkew {
		return ErrAttestationStale
	}
	return nil
}

func (r AttestationResult) validateShape() error {
	if r.Version != AttestationResultVersion ||
		strings.TrimSpace(r.ResultID) == "" ||
		strings.TrimSpace(r.VerifierKeyID) == "" ||
		strings.TrimSpace(r.PolicyID) == "" ||
		strings.TrimSpace(r.Measurement) == "" ||
		strings.TrimSpace(r.AttestationBinderSHA256) == "" ||
		r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.IssuedAt) {
		return ErrInvalidAttestationResult
	}
	for _, value := range []string{
		r.ResultID, r.VerifierKeyID, r.PolicyID, r.Measurement, r.AttestationBinderSHA256,
	} {
		if len(value) > 1024 || strings.TrimSpace(value) != value {
			return fmt.Errorf("%w: non-canonical field", ErrInvalidAttestationResult)
		}
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
