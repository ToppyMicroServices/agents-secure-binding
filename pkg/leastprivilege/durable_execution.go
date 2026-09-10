// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package leastprivilege

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

// EffectResult is supplied by a trusted, operation-specific adapter. FAILED
// means the adapter established that the requested effect did not occur. A
// timeout, interrupted connection or uncertain response is UNKNOWN instead.
type EffectResult struct {
	State          ExecutionState
	EvidenceDigest string
}

// Effect receives the exact reserved operation ID and an owned copy of the
// authorized request. It should propagate the ID as the downstream idempotency
// key when supported. Never register a general shell or arbitrary-call adapter.
type Effect func(context.Context, string, Request) (EffectResult, error)

// Run reserves and dispatches at most once across all processes using this
// store. An exact completed retry returns the recorded result without dispatch.
// RUNNING and UNKNOWN readback returns ErrOutcomeUnknown and never dispatches.
// Hold the trusted policy guard across this call to prevent policy replacement
// between validation and dispatch. The storage layer does not authenticate peers.
func (s *DurableStore) Run(ctx context.Context, operationID string, cap Capability, key ed25519.PublicKey, current Mandate, request Request, now time.Time, effect Effect) (ExecutionRecord, error) {
	if ctx == nil || effect == nil {
		return ExecutionRecord{}, ErrBinding
	}
	wallStart := time.Now()
	request.Action.Arguments = append([]byte(nil), request.Action.Arguments...)
	r, _, err := s.Prepare(ctx, operationID, cap, key, current, request, now)
	if err != nil {
		return ExecutionRecord{}, err
	}
	if r.Terminal() {
		return r, nil
	}
	if r.State != ExecutionAccepted {
		return r, ErrOutcomeUnknown
	}
	if err := CheckCapability(cap, key, current, request, now.Add(time.Since(wallStart))); err != nil {
		return r, err
	}
	r, started, err := s.Start(ctx, r.OperationID, r.RequestDigest)
	if err != nil {
		return ExecutionRecord{}, err
	}
	if !started {
		if r.Terminal() {
			return r, nil
		}
		return r, ErrOutcomeUnknown
	}
	// Durable commit may block past expiry. Recheck before calling the adapter.
	if err := CheckCapability(cap, key, current, request, now.Add(time.Since(wallStart))); err != nil {
		return s.recordNoEffect(ctx, r, err)
	}
	if err := ctx.Err(); err != nil {
		return s.recordNoEffect(ctx, r, err)
	}
	result, effectErr := effect(ctx, operationID, request)
	if effectErr != nil || ctx.Err() != nil || (result.State != ExecutionSucceeded && result.State != ExecutionFailed) || !canonicalDigest(result.EvidenceDigest) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		unknown, commitErr := s.Complete(cleanup, r.OperationID, r.RequestDigest, ExecutionUnknown, "")
		if commitErr != nil {
			return r, errors.Join(ErrOutcomeUnknown, effectErr, ctx.Err(), commitErr)
		}
		return unknown, errors.Join(ErrOutcomeUnknown, effectErr, ctx.Err())
	}
	complete, err := s.Complete(ctx, r.OperationID, r.RequestDigest, result.State, result.EvidenceDigest)
	if err != nil {
		return r, errors.Join(ErrOutcomeUnknown, err)
	}
	return complete, nil
}

func (s *DurableStore) recordNoEffect(ctx context.Context, r ExecutionRecord, cause error) (ExecutionRecord, error) {
	// A failure observed before invocation is an authoritative local no-effect
	// decision. It is distinct from an adapter timeout after invocation.
	evidence, err := digestValue("asb.least-privilege.not-dispatched/v1", struct{ OperationID, RequestDigest, Reason string }{r.OperationID, r.RequestDigest, cause.Error()})
	if err != nil {
		return r, errors.Join(cause, err)
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	complete, err := s.Complete(cleanup, r.OperationID, r.RequestDigest, ExecutionFailed, evidence)
	if err != nil {
		return r, errors.Join(cause, ErrOutcomeUnknown, err)
	}
	return complete, cause
}
