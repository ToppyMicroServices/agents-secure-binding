// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package evidencesource adapts the legacy Cocos attestation-service client to
// the platform-neutral ASB evidence-source boundary.
package evidencesource

import (
	"context"
	"errors"
	"fmt"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	platformattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
)

var (
	ErrMissingEvidenceClient = errors.New("attestation evidence source requires a client")
	ErrInvalidPlatform       = errors.New("attestation evidence source requires a confidential-computing platform")
)

// Client is the smallest legacy Cocos client surface needed by the adapter.
// Keeping this interface local avoids coupling the integration module to the
// concrete gRPC client implementation.
type Client interface {
	GetAttestation(context.Context, [64]byte, [32]byte, platformattestation.PlatformType) ([]byte, error)
}

// EvidenceSource adapts the legacy attestation-service client to ASB's
// platform-neutral evidence source. The platform is fixed by local composition
// and is never selected from peer-provided evidence.
type EvidenceSource struct {
	client   Client
	platform platformattestation.PlatformType
}

func NewEvidenceSource(client Client, platform platformattestation.PlatformType) (*EvidenceSource, error) {
	if client == nil {
		return nil, ErrMissingEvidenceClient
	}
	switch platform {
	case platformattestation.SNP, platformattestation.TDX:
		// Supported by Client.GetAttestation.
	default:
		return nil, ErrInvalidPlatform
	}
	return &EvidenceSource{client: client, platform: platform}, nil
}

func (s *EvidenceSource) GetEvidence(ctx context.Context, request eaattestation.EvidenceRequest) (eaattestation.EvidenceResult, error) {
	if s == nil || s.client == nil {
		return eaattestation.EvidenceResult{}, ErrMissingEvidenceClient
	}
	evidence, err := s.client.GetAttestation(ctx, request.ReportData, request.Nonce, s.platform)
	if err != nil {
		return eaattestation.EvidenceResult{}, fmt.Errorf("fetch platform evidence: %w", err)
	}
	return eaattestation.EvidenceResult{
		MediaType: "application/eat+cwt",
		Evidence:  evidence,
	}, nil
}

var _ eaattestation.EvidenceSource = (*EvidenceSource)(nil)
