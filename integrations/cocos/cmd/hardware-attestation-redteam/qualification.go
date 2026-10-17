// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	asb "github.com/ToppyMicroServices/agents-secure-binding/v2"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/veraison/go-cose"
	"google.golang.org/protobuf/proto"
)

// Results deliberately contain no raw evidence, claims, tokens or error text.
type verificationCheck struct {
	Name           string `json:"name"`
	Expected       string `json:"expected"`
	Observed       string `json:"observed"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type rejectionCase struct {
	name     string
	evidence []byte
	want     error
}

type signedRejection struct {
	name, claim string
	raw         []byte
	want        error
}

func verifyQualificationCases(
	verifier eaattestation.EvidenceVerifier,
	platform string,
	rawEvidence, tokenA, tokenB []byte,
	bindingA, bindingB eaattestation.EvidenceBinding,
	key *ecdsa.PrivateKey,
	issuer string,
) ([]verificationCheck, error) {
	var results []verificationCheck
	// Both fresh controls must pass the same verifier before any rejection can
	// count as a successful qualification. An unavailable appraiser cannot pass.
	for _, control := range []struct {
		name     string
		evidence []byte
		binding  eaattestation.EvidenceBinding
	}{
		{"fresh_session_a", tokenA, bindingA},
		{"fresh_session_b", tokenB, bindingB},
	} {
		if err := verifier.VerifyEvidence(control.evidence, control.binding); err != nil {
			return nil, fmt.Errorf("%s control failed: %w", control.name, err)
		}
		results = append(results, verificationCheck{control.name, "accept", "accept", sha256Hex(control.evidence)})
	}
	if err := verifier.VerifyEvidence(tokenA, bindingB); err == nil {
		return nil, fmt.Errorf("stale_session_a: evidence was accepted for session B")
	}
	results = append(results, verificationCheck{"stale_session_a", "reject", "reject", sha256Hex(tokenA)})
	cases, err := qualificationRejections(platform, rawEvidence, tokenA, bindingA, key, issuer)
	if err != nil {
		return nil, err
	}
	for _, test := range cases {
		err := verifier.VerifyEvidence(test.evidence, bindingA)
		if err == nil {
			return nil, fmt.Errorf("%s: invalid evidence was accepted", test.name)
		}
		if test.want != nil && !errors.Is(err, test.want) {
			return nil, fmt.Errorf("%s: rejection did not reach the expected verification check", test.name)
		}
		results = append(results, verificationCheck{test.name, "reject", "reject", sha256Hex(test.evidence)})
	}
	return results, nil
}

func qualificationClaims(raw, nonce []byte, platform string) *eat.EATClaims {
	return &eat.EATClaims{
		Nonce:        append([]byte(nil), nonce...),
		RawReport:    append([]byte(nil), raw...),
		PlatformType: platform,
		IntUse:       eat.IntUseGenericFresh,
	}
}

func qualificationRejections(platform string, rawEvidence, token []byte, expected eaattestation.EvidenceBinding, key *ecdsa.PrivateKey, issuer string) ([]rejectionCase, error) {
	var tamperedEnvelope cose.Sign1Message
	if err := tamperedEnvelope.UnmarshalCBOR(token); err != nil {
		return nil, fmt.Errorf("decode control EAT for signature mutation: %w", err)
	}
	if len(tamperedEnvelope.Signature) == 0 {
		return nil, fmt.Errorf("control EAT has no signature")
	}
	tamperedEnvelope.Signature[0] ^= 0xff
	tamperedToken, err := tamperedEnvelope.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("encode mutated EAT: %w", err)
	}
	tamperedRaw, err := tamperReportSignature(platform, rawEvidence)
	if err != nil {
		return nil, err
	}
	verificationError := platformmodule.ErrSNPVerification
	malformedError := platformmodule.ErrInvalidSNPEvidence
	if platform == platformTDX {
		verificationError = platformmodule.ErrTDXVerification
		malformedError = platformmodule.ErrTDXVerification
	}
	cases := []rejectionCase{
		{"malformed_eat", []byte("nonempty malformed EAT"), eat.ErrSignedCBORRequired},
		{"tampered_eat_signature", tamperedToken, cose.ErrVerification},
	}
	signedCases := []signedRejection{
		{"tampered_report_signature", strings.ToUpper(platform), tamperedRaw, verificationError},
		{"malformed_report", strings.ToUpper(platform), []byte("nonempty malformed report"), malformedError},
	}
	noCC := append(append([]byte(nil), expected.ReportData[:]...), expected.Nonce[:]...)
	ccSample, err := json.Marshal(map[string]string{
		"svn": "1", "report_data": base64.StdEncoding.EncodeToString(expected.ReportData[:]),
	})
	if err != nil {
		return nil, err
	}
	for _, sample := range []signedRejection{
		{"nocc_sample", "NoCC", noCC, malformedError},
		{"cc_json_sample", "sample", ccSample, malformedError},
		{"embedded_vtpm_sample", "vTPM", asb.EmbeddedAttestation, verificationError},
	} {
		if len(sample.raw) == 0 {
			return nil, fmt.Errorf("%s: sample fixture is empty", sample.name)
		}
		signedCases = append(signedCases,
			signedRejection{sample.name, sample.claim, sample.raw, platformmodule.ErrUnsupportedPlatform},
			signedRejection{"relabeled_" + sample.name, strings.ToUpper(platform), sample.raw, sample.want},
		)
	}
	for _, test := range signedCases {
		token, err := eat.EncodeToCBOR(qualificationClaims(test.raw, expected.Nonce[:], test.claim), key, issuer)
		if err != nil {
			return nil, fmt.Errorf("sign %s fixture: %w", test.name, err)
		}
		cases = append(cases, rejectionCase{test.name, token, test.want})
	}
	return cases, nil
}

func tamperReportSignature(platform string, evidence []byte) ([]byte, error) {
	switch platform {
	case platformSNP:
		var report sevsnppb.Attestation
		if err := proto.Unmarshal(evidence, &report); err != nil {
			return nil, fmt.Errorf("decode SNP report for signature mutation: %w", err)
		}
		if len(report.GetReport().GetSignature()) == 0 {
			return nil, fmt.Errorf("SNP report has no signature")
		}
		report.Report.Signature[0] ^= 0xff
		return proto.Marshal(&report)
	case platformTDX:
		parsed, err := tdxabi.QuoteToProto(evidence)
		if err != nil {
			return nil, fmt.Errorf("decode TDX report for signature mutation: %w", err)
		}
		quote, ok := parsed.(*tdxpb.QuoteV4)
		if !ok || len(quote.GetSignedData().GetSignature()) == 0 {
			return nil, fmt.Errorf("TDX report has no supported signature")
		}
		quote.SignedData.Signature[0] ^= 0xff
		return tdxabi.QuoteToAbiBytes(quote)
	default:
		return nil, fmt.Errorf("unsupported signature mutation platform %q", platform)
	}
}
