// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/hex"
	"fmt"

	attestationpb "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/proto/attestation/v1"
)

func (s *service) FetchRawEvidence(ctx context.Context, req *attestationpb.AttestationRequest) (*attestationpb.RawEvidenceResponse, error) {
	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Received raw evidence request with platform type: %v (%d)",
		req.PlatformType, req.PlatformType))

	var binaryReport []byte
	var err error

	// Get binary attestation report based on platform type
	switch req.PlatformType {
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP, attestationpb.PlatformType_PLATFORM_TYPE_TDX:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		binaryReport, err = s.provider.TeeAttestation(reportData[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_VTPM:
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.VTpmAttestation(nonce[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.Attestation(reportData[:], nonce[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED:
		// Generate sample attestation for testing in non-TEE environments
		// This uses the underlying provider (EmptyProvider or CC Attestation Agent)
		s.logger.Warn("fetching sample attestation for PLATFORM_TYPE_UNSPECIFIED")
		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Fetching sample/unspecified attestation: reportData_len=%d",
			len(req.ReportData)))

		// Ask the configured provider for sample evidence. EmptyProvider rejects
		// TEE collection; a configured CC agent may supply a sample.
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		binaryReport, err = s.provider.TeeAttestation(reportData[:])
		if err != nil {
			return nil, fmt.Errorf("failed to fetch sample attestation: %w", err)
		}

		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Sample attestation fetched: binaryReport_len=%d",
			len(binaryReport)))
	default:
		return nil, fmt.Errorf("unsupported platform type")
	}

	if err != nil {
		return nil, err
	}
	if err := requireCollectedEvidence(binaryReport); err != nil {
		return nil, err
	}

	// Debug logging: show evidence details
	previewLen := len(binaryReport)
	if previewLen > 200 {
		previewLen = 200
	}
	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Returning raw evidence: total_len=%d, preview_hex=%s",
		len(binaryReport), hex.EncodeToString(binaryReport[:previewLen])))
	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Evidence as string preview: %s", string(binaryReport[:previewLen])))

	return &attestationpb.RawEvidenceResponse{Evidence: binaryReport}, nil
}
