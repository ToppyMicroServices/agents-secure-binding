// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"
)

func boundVerificationPayload(t *testing.T) (*tls.ConnectionState, *x509.Certificate, []byte, Payload) {
	t.Helper()
	cert, leaf := makeCert(t)
	server, client := tls13Client(t, cert)
	t.Cleanup(func() {
		// net.Pipe has no peer reading TLS close_notify after these tests.
		_ = server.SetDeadline(time.Now())
		_ = client.SetDeadline(time.Now())
		_ = server.Close()
		_ = client.Close()
	})
	state := client.ConnectionState()
	requestContext := []byte("required-attestation-test")
	_, aik, binding, err := ComputeBinding(&state, ExporterLabelAttestation, requestContext, leaf)
	if err != nil {
		t.Fatal(err)
	}
	return &state, leaf, requestContext, Payload{
		Version: 1,
		Binder: AttestationBinder{
			ExporterLabel: ExporterLabelAttestation,
			AIKPubHash:    aik,
			Binding:       binding,
		},
	}
}

func TestVerifyPayloadRequiresVerifierForEachStatement(t *testing.T) {
	state, leaf, requestContext, base := boundVerificationPayload(t)
	for _, tc := range []struct {
		name     string
		evidence []byte
		results  []byte
		policy   VerificationPolicy
		wantErr  error
	}{
		{
			name:     "nonempty evidence without verifier",
			evidence: []byte("not valid attestation evidence"),
			wantErr:  ErrEvidenceVerificationMissing,
		},
		{
			name:    "nonempty results without verifier",
			results: []byte("not valid attestation results"),
			wantErr: ErrResultsVerificationMissing,
		},
		{
			name:     "results verifier does not cover evidence",
			evidence: []byte("unverified evidence"),
			results:  []byte("results"),
			policy:   VerificationPolicy{ResultsVerifier: &stubResultsVerifier{}},
			wantErr:  ErrEvidenceVerificationMissing,
		},
		{
			name:     "evidence verifier does not cover results",
			evidence: []byte("evidence"),
			results:  []byte("unverified results"),
			policy:   VerificationPolicy{EvidenceVerifier: &stubEvidenceVerifier{}},
			wantErr:  ErrResultsVerificationMissing,
		},
		{
			name:    "configured verifier cannot replace missing statements",
			policy:  VerificationPolicy{EvidenceVerifier: &stubEvidenceVerifier{}},
			wantErr: ErrMissingStatement,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			payload.Evidence, payload.AttestationResults = tc.evidence, tc.results
			verified, err := VerifyPayload(state, ExporterLabelAttestation, requestContext, leaf, &payload, tc.policy)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyPayload() error = %v, want %v", err, tc.wantErr)
			}
			if verified != nil {
				t.Fatalf("failed verification returned a usable payload: %#v", verified)
			}
		})
	}
}

func TestVerifyPayloadPropagatesVerifierRejection(t *testing.T) {
	state, leaf, requestContext, base := boundVerificationPayload(t)
	rejected := errors.New("test appraiser rejected statement")
	for _, tc := range []struct {
		name                 string
		evidence             []byte
		results              []byte
		evidenceErr          error
		resultsErr           error
		wantEvidenceVerified bool
		wantResultsVerified  bool
	}{
		{
			name:        "rejected evidence stops verification",
			evidence:    []byte("nonempty rejected evidence"),
			results:     []byte("results"),
			evidenceErr: fmt.Errorf("evidence appraisal: %w", rejected),
		},
		{
			name:       "rejected results alone",
			results:    []byte("nonempty rejected results"),
			resultsErr: fmt.Errorf("results appraisal: %w", rejected),
		},
		{
			name:       "accepted evidence does not override rejected results",
			evidence:   []byte("evidence"),
			results:    []byte("nonempty rejected results"),
			resultsErr: fmt.Errorf("results appraisal: %w", rejected),
		},
		{
			name:                 "accepted evidence positive control",
			evidence:             []byte("evidence"),
			wantEvidenceVerified: true,
		},
		{
			name:                "accepted results positive control",
			results:             []byte("results"),
			wantResultsVerified: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := base
			payload.Evidence, payload.AttestationResults = tc.evidence, tc.results
			evidenceVerifier := &stubEvidenceVerifier{err: tc.evidenceErr}
			resultsVerifier := &stubResultsVerifier{err: tc.resultsErr}
			policy := VerificationPolicy{EvidenceVerifier: evidenceVerifier, ResultsVerifier: resultsVerifier}
			verified, err := VerifyPayload(state, ExporterLabelAttestation, requestContext, leaf, &payload, policy)
			if tc.evidenceErr != nil || tc.resultsErr != nil {
				if !errors.Is(err, rejected) {
					t.Fatalf("VerifyPayload() error = %v, want verifier rejection", err)
				}
				if verified != nil {
					t.Fatalf("rejection exposed a partially verified payload: %#v", verified)
				}
			} else {
				if err != nil {
					t.Fatalf("positive control failed: %v", err)
				}
				if verified == nil || !verified.BindingVerified ||
					verified.EvidenceVerified != tc.wantEvidenceVerified || verified.ResultsVerified != tc.wantResultsVerified {
					t.Fatalf("unexpected positive control result: %#v", verified)
				}
			}
			if evidenceVerifier.called != (len(tc.evidence) > 0) {
				t.Fatalf("evidence verifier called = %v", evidenceVerifier.called)
			}
			if resultsVerifier.called != (len(tc.results) > 0 && tc.evidenceErr == nil) {
				t.Fatalf("results verifier called = %v", resultsVerifier.called)
			}
			if evidenceVerifier.called && !bytes.Equal(evidenceVerifier.gotBinding.Binding, base.Binder.Binding) {
				t.Fatal("evidence verifier did not receive the TLS binding")
			}
			if resultsVerifier.called && !bytes.Equal(resultsVerifier.gotBinding.Binding, base.Binder.Binding) {
				t.Fatal("results verifier did not receive the TLS binding")
			}
		})
	}
}
