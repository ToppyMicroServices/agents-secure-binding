// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed

package manager

import (
	"context"
	/*
		attestationPolicy "github.com/ToppyMicroServices/agents-secure-binding/v2/scripts/attestation_policy/sev-snp"
	*/)

func (ms *managerService) FetchAttestationPolicy(_ context.Context, _ string) ([]byte, error) {
	// return attestationPolicy.AttestationPolicy, nil
	return nil, nil
}
