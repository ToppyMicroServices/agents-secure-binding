// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"testing"

	asb "github.com/ToppyMicroServices/agents-secure-binding/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmptyProviderRejectsUnsupportedEvidenceCollection(t *testing.T) {
	p := &EmptyProvider{}
	methods := []struct {
		name    string
		collect func([]byte) ([]byte, error)
	}{
		{
			name: "Attestation",
			collect: func(nonce []byte) ([]byte, error) {
				return p.Attestation(nonce, nonce)
			},
		},
		{name: "TeeAttestation", collect: p.TeeAttestation},
		{name: "AzureAttestationToken", collect: p.AzureAttestationToken},
	}
	nonces := []struct {
		name  string
		value []byte
	}{
		{name: "nil", value: nil},
		{name: "empty", value: []byte{}},
		{name: "nonempty", value: []byte("nonce")},
	}
	for _, method := range methods {
		t.Run(method.name, func(t *testing.T) {
			for _, nonce := range nonces {
				t.Run(nonce.name, func(t *testing.T) {
					evidence, err := method.collect(nonce.value)
					require.Error(t, err)
					assert.Contains(t, err.Error(), "EmptyProvider should not be used")
					assert.Nil(t, evidence, "an unavailable provider must not return embedded or other evidence")
				})
			}
		})
	}
}

func TestEmptyProviderVTpmAttestationRequiresNonemptySample(t *testing.T) {
	// These tests run serially because they temporarily replace the package's
	// embedded sample. Collection success does not verify hardware evidence.
	saved := asb.EmbeddedAttestation
	t.Cleanup(func() { asb.EmbeddedAttestation = saved })
	require.NotEmpty(t, saved)
	fixtures := []struct {
		name    string
		value   []byte
		wantErr bool
	}{
		{name: "embedded sample", value: saved},
		{name: "nil sample", value: nil, wantErr: true},
		{name: "empty sample", value: []byte{}, wantErr: true},
	}
	nonces := []struct {
		name  string
		value []byte
	}{
		{name: "nil", value: nil},
		{name: "empty", value: []byte{}},
		{name: "nonempty", value: make([]byte, 32)},
	}
	p := &EmptyProvider{}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			asb.EmbeddedAttestation = fixture.value
			for _, nonce := range nonces {
				t.Run(nonce.name, func(t *testing.T) {
					evidence, err := p.VTpmAttestation(nonce.value)
					if fixture.wantErr {
						require.Error(t, err)
						assert.Nil(t, evidence)
						return
					}
					require.NoError(t, err)
					assert.Equal(t, saved, evidence)
				})
			}
		})
	}
}

func TestEmptyProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*EmptyProvider)(nil)
}
