// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"context"
	"errors"
)

var ErrNilEvidenceSourceFunc = errors.New("attestation: nil evidence source function")

// EvidenceRequest contains the session-bound values that an evidence source
// must place in, or otherwise bind to, newly collected evidence.
type EvidenceRequest struct {
	ReportData [64]byte
	Nonce      [32]byte
}

// EvidenceResult is the opaque statement returned by an evidence source.
// Platform-specific parsing and collection remain outside the ASB core.
type EvidenceResult struct {
	MediaType string
	Evidence  []byte
}

// EvidenceSource collects evidence for one ASB authentication attempt.
type EvidenceSource interface {
	GetEvidence(context.Context, EvidenceRequest) (EvidenceResult, error)
}

// EvidenceSourceFunc adapts a function to EvidenceSource. It is useful at an
// application composition boundary without adding a platform dependency to
// the ASB core.
type EvidenceSourceFunc func(context.Context, EvidenceRequest) (EvidenceResult, error)

func (f EvidenceSourceFunc) GetEvidence(ctx context.Context, request EvidenceRequest) (EvidenceResult, error) {
	if f == nil {
		return EvidenceResult{}, ErrNilEvidenceSourceFunc
	}
	return f(ctx, request)
}
