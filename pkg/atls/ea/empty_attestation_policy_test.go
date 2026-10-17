// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"bytes"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
)

type emptyStatementVerifier struct {
	calls int
}

func (v *emptyStatementVerifier) VerifyEvidence([]byte, eaattestation.EvidenceBinding) error {
	v.calls++
	return nil
}

func (v *emptyStatementVerifier) VerifyAttestationResults([]byte, eaattestation.EvidenceBinding) error {
	v.calls++
	return nil
}

func TestEmptyAuthenticatorRespectsAttestationPolicy(t *testing.T) {
	server, client := tlsPair(t, selfSignedCert(t))
	t.Cleanup(func() {
		_ = server.SetDeadline(time.Now())
		_ = client.SetDeadline(time.Now())
		_ = server.Close()
		_ = client.Close()
	})
	serverState, clientState := server.ConnectionState(), client.ConnectionState()
	request := &AuthenticatorRequest{
		Type:    HandshakeTypeClientCertificateRequest,
		Context: []byte("empty-authenticator-policy"),
		Extensions: []Extension{
			{Type: SignatureAlgorithmsExtensionType, Data: []byte{0x00, 0x02, 0x04, 0x03}},
			CMWAttestationOfferExtension(),
		},
	}
	auth, err := CreateAuthenticator(&serverState, RoleServer, request, tls.Certificate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	message, rest, err := UnmarshalHandshakeMessage(auth)
	if err != nil || message.Type != HandshakeTypeFinished || len(rest) != 0 {
		t.Fatalf("expected a valid Finished-only authenticator, got type %d, error %v", message.Type, err)
	}

	for _, tc := range []struct {
		name            string
		requireEvidence bool
		requireResults  bool
		tamperFinished  bool
		wantErr         error
	}{
		{name: "optional attestation"},
		{name: "required evidence", requireEvidence: true, wantErr: eaattestation.ErrMissingAttestation},
		{name: "required results", requireResults: true, wantErr: eaattestation.ErrMissingAttestation},
		{name: "both required", requireEvidence: true, requireResults: true, wantErr: eaattestation.ErrMissingAttestation},
		{name: "invalid Finished remains rejected", requireEvidence: true, tamperFinished: true, wantErr: ErrFinishedMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &emptyStatementVerifier{}
			policy := eaattestation.VerificationPolicy{}
			if tc.requireEvidence {
				policy.EvidenceVerifier = verifier
			}
			if tc.requireResults {
				policy.ResultsVerifier = verifier
			}
			input := bytes.Clone(auth)
			if tc.tamperFinished {
				input[len(input)-1] ^= 0x01
			}
			result, err := NewSession().ValidateAuthenticatorWithAttestation(&clientState, RoleServer, request, input, nil, policy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateAuthenticatorWithAttestation() error = %v, want %v; result = %#v", err, tc.wantErr, result)
			}
			if tc.wantErr != nil {
				if result != nil {
					t.Fatalf("required or invalid authenticator returned a usable result: %#v", result)
				}
			} else if result == nil || !result.Empty || result.Attestation != nil || len(result.Chain) != 0 {
				t.Fatalf("optional attestation did not preserve empty authenticator semantics: %#v", result)
			}
			if verifier.calls != 0 {
				t.Fatal("a statement verifier was called without a statement")
			}
		})
	}
}
