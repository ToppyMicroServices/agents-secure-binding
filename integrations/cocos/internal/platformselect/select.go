// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package platformselect resolves the direct hardware platform selected by
// trusted local Cocos configuration. It deliberately ignores vTPM and cloud
// metadata so those legacy signals cannot redirect the direct SNP/TDX adapter.
package platformselect

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
)

var (
	ErrUnsupportedPlatform = errors.New("Cocos direct attestation platform must be snp, tdx, auto, or none")
	ErrAmbiguousPlatform   = errors.New("both direct SNP and TDX devices were detected; select one explicitly")
)

// Resolve returns a direct platform from trusted local configuration. An
// explicit selection is not a hardware qualification check; evidence
// collection still fails closed if the selected device is unavailable.
func Resolve(configured string) (attestation.PlatformType, error) {
	return resolve(configured, attestation.SevSnpGuestDeviceExists, attestation.TDXGuestDeviceExists)
}

func resolve(configured string, snpExists, tdxExists func() bool) (attestation.PlatformType, error) {
	switch strings.ToLower(strings.TrimSpace(configured)) {
	case "snp":
		return attestation.SNP, nil
	case "tdx":
		return attestation.TDX, nil
	case "none", "no-cc":
		return attestation.NoCC, nil
	case "", "auto":
		snp := snpExists != nil && snpExists()
		tdx := tdxExists != nil && tdxExists()
		switch {
		case snp && tdx:
			return attestation.NoCC, ErrAmbiguousPlatform
		case snp:
			return attestation.SNP, nil
		case tdx:
			return attestation.TDX, nil
		default:
			return attestation.NoCC, nil
		}
	default:
		return attestation.NoCC, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, configured)
	}
}
