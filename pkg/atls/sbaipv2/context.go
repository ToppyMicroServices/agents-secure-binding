// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package sbaipv2 implements the byte constructions defined by
// draft-okutomi-session-bound-agent-identity-06 Section 17.2.
//
// It intentionally does not select endpoint roles, interaction types, TLS
// exporter labels, or application canonicalization rules. Those inputs must
// come from an authenticated binding profile and verifier-local state.
package sbaipv2

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	ContextDomain            = "SBAIP-CONTEXT-v2"
	AttestationBindingDomain = "SBAIP-ATTESTATION-BINDING-v1"
	ExporterLength           = 32
	MinVerifierNonceLength   = 16
)

var (
	ErrMissingInput       = errors.New("sbaipv2: missing input")
	ErrInputTooLong       = errors.New("sbaipv2: input too long")
	ErrVerifierNonceShort = errors.New("sbaipv2: verifier nonce must contain at least 128 bits")
	ErrExporterLength     = errors.New("sbaipv2: TLS exporter must be 32 bytes")
)

// ContextInputs contains authenticated inputs and verifier-local values for
// the fixed sbaip_context_v2 construction. AttemptID is optional, but its
// field is always encoded, including when its value is empty.
type ContextInputs struct {
	EndpointRole    string
	InteractionType string
	ProtocolID      string
	Audience        string
	GrantHash       [sha256.Size]byte
	TaskContext     []byte
	TargetContext   []byte
	VerifierNonce   []byte
	AttemptID       []byte
}

// DerivedHashes contains the four SHA-256 values derived by Section 17.2.
type DerivedHashes struct {
	AcceptedEndpointSPKISHA256 [sha256.Size]byte
	TLSExporterSHA256          [sha256.Size]byte
	BindingContextSHA256       [sha256.Size]byte
	AttestationBinderSHA256    [sha256.Size]byte
}

// EncodeContext encodes the exact sbaip_context_v2 field sequence.
func EncodeContext(inputs ContextInputs) ([]byte, error) {
	for _, input := range []struct {
		name  string
		value string
	}{
		{"endpoint_role", inputs.EndpointRole},
		{"interaction_type", inputs.InteractionType},
		{"protocol_id", inputs.ProtocolID},
		{"aud", inputs.Audience},
	} {
		if input.value == "" {
			return nil, fmt.Errorf("%w: %s", ErrMissingInput, input.name)
		}
	}
	for _, input := range []struct {
		name  string
		value []byte
	}{
		{"task_context", inputs.TaskContext},
		{"target_context", inputs.TargetContext},
	} {
		if len(input.value) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrMissingInput, input.name)
		}
	}
	if len(inputs.VerifierNonce) < MinVerifierNonceLength {
		return nil, ErrVerifierNonceShort
	}

	context := make([]byte, 0, len(ContextDomain)+1+256)
	context = append(context, ContextDomain...)
	context = append(context, 0)

	var err error
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{"endpoint_role", []byte(inputs.EndpointRole)},
		{"interaction_type", []byte(inputs.InteractionType)},
		{"protocol_id", []byte(inputs.ProtocolID)},
		{"aud", []byte(inputs.Audience)},
		{"grant_hash", inputs.GrantHash[:]},
		{"task_context", inputs.TaskContext},
		{"target_context", inputs.TargetContext},
		{"verifier_nonce", inputs.VerifierNonce},
		{"attempt_id", inputs.AttemptID},
	} {
		context, err = appendField(context, field.name, field.value)
		if err != nil {
			return nil, err
		}
	}
	return context, nil
}

// AttestationBindingInput encodes the Section 17.2 attestation binder input.
func AttestationBindingInput(leafSPKI, ekm []byte) ([]byte, error) {
	if len(leafSPKI) == 0 {
		return nil, fmt.Errorf("%w: leaf_spki", ErrMissingInput)
	}
	if len(ekm) != ExporterLength {
		return nil, ErrExporterLength
	}

	input := make([]byte, 0, len(AttestationBindingDomain)+1+len(leafSPKI)+len(ekm)+32)
	input = append(input, AttestationBindingDomain...)
	input = append(input, 0)

	var err error
	input, err = appendField(input, "leaf_spki", leafSPKI)
	if err != nil {
		return nil, err
	}
	return appendField(input, "ekm", ekm)
}

// DeriveHashes computes the Section 17.2 endpoint, exporter, context, and
// attestation-binder hashes. Context must be produced by EncodeContext and EKM
// must be the 32-byte result of the profile-selected TLS exporter.
func DeriveHashes(context, leafSPKI, ekm []byte) (DerivedHashes, error) {
	if len(context) == 0 {
		return DerivedHashes{}, fmt.Errorf("%w: context", ErrMissingInput)
	}
	attestationInput, err := AttestationBindingInput(leafSPKI, ekm)
	if err != nil {
		return DerivedHashes{}, err
	}
	return DerivedHashes{
		AcceptedEndpointSPKISHA256: sha256.Sum256(leafSPKI),
		TLSExporterSHA256:          sha256.Sum256(ekm),
		BindingContextSHA256:       sha256.Sum256(context),
		AttestationBinderSHA256:    sha256.Sum256(attestationInput),
	}, nil
}

func appendField(dst []byte, name string, value []byte) ([]byte, error) {
	if len(name) > math.MaxUint16 || uint64(len(value)) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: %s", ErrInputTooLong, name)
	}
	var lengths [4]byte
	binary.BigEndian.PutUint16(lengths[:2], uint16(len(name)))
	dst = append(dst, lengths[:2]...)
	dst = append(dst, name...)
	binary.BigEndian.PutUint32(lengths[:], uint32(len(value)))
	dst = append(dst, lengths[:]...)
	dst = append(dst, value...)
	return dst, nil
}
