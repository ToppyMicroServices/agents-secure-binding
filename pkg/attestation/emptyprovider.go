// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"

	asb "github.com/ToppyMicroServices/agents-secure-binding/v2"
)

var _ Provider = (*EmptyProvider)(nil)

var errEmptyProvider = errors.New("EmptyProvider should not be used - configure USE_CC_ATTESTATION_AGENT=true to use the CC Attestation Agent's sample attester")

type EmptyProvider struct{}

func (e *EmptyProvider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return e.TeeAttestation(teeNonce)
}

func (e *EmptyProvider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	// EmptyProvider should not be used for attestation
	// The CC Attestation Agent's sample attester should be used instead
	return nil, errEmptyProvider
}

func (e *EmptyProvider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	if len(asb.EmbeddedAttestation) == 0 {
		return nil, errors.New("embedded sample attestation is empty")
	}
	// Preserve the legacy sample fixture; it is not fresh hardware evidence.
	return asb.EmbeddedAttestation, nil
}

func (e *EmptyProvider) AzureAttestationToken(nonce []byte) ([]byte, error) {
	return nil, errEmptyProvider
}
