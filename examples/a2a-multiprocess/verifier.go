// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	sevsnp "github.com/google/go-sev-guest/proto/sevsnp"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
	tdxverify "github.com/google/go-tdx-guest/verify"
	"google.golang.org/protobuf/proto"
)

func runVerifier(ctx context.Context, opts options, out outputWriter) error {
	dir := roleDirectory(opts.stateDir, "verifier")
	resultKey, err := loadPrivateKey(filepath.Join(dir, signingKeyFile))
	if err != nil {
		return fmt.Errorf("load verifier signing key: %w", err)
	}
	simulationKey, err := loadPublicKey(filepath.Join(dir, simPublicFile))
	if err != nil {
		return fmt.Errorf("load simulation attester key: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /attest", func(w http.ResponseWriter, r *http.Request) {
		if err := requirePeer(r, demoAgentIssuer); err != nil {
			writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", err.Error())
			return
		}
		var request appraisalRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		binder, err := base64.RawURLEncoding.DecodeString(request.Binder)
		if err != nil || len(binder) == 0 {
			writeProblem(w, http.StatusBadRequest, "binder", "Invalid attestation binder", "binder must be non-empty base64url")
			return
		}
		claims, err := appraiseEvidence(r.Context(), request.Evidence, binder, opts.expectedMeasurementHex, simulationKey)
		if err != nil {
			writeProblem(w, http.StatusForbidden, "attestation-rejected", "Attestation rejected", err.Error())
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		id, err := randomID("attestation-")
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "Attestation result failed", "identifier generation failed")
			return
		}
		claims.RegisteredClaims = jwt.RegisteredClaims{
			Issuer: demoVerifierIssuer, Subject: demoAgentIssuer,
			Audience: jwt.ClaimStrings{demoAudience}, ID: id,
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		}
		token, err := signJWT(demoVerifierKeyID, resultKey, claims)
		if err != nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "Attestation result failed", "signing failed")
			return
		}
		writeJSON(w, http.StatusOK, "application/json", appraisalResponse{AttestationResult: token})
	})
	return serveTLS(ctx, opts, "verifier", tls.RequireAndVerifyClientCert, mux, out)
}

func appraiseEvidence(ctx context.Context, evidence evidenceResponse, binder []byte, expectedMeasurementHex string, simulationKey any) (attestationResultClaims, error) {
	reportData := sha512.Sum512(binder)
	evidenceBytes := []byte(evidence.Evidence)
	evidenceHash := sha256String(evidenceBytes)
	binderHash := sha256String(binder)

	switch evidence.Platform {
	case platformSimulated:
		if evidence.Format != "application/asb-simulated-evidence+jwt" {
			return attestationResultClaims{}, fmt.Errorf("unexpected simulated evidence format")
		}
		claims := &simulatedEvidenceClaims{}
		_, err := jwt.ParseWithClaims(evidence.Evidence, claims, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodES256 || token.Header["kid"] != demoAttesterKeyID {
				return nil, fmt.Errorf("unexpected simulated evidence signer")
			}
			return simulationKey, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}), jwt.WithIssuer(demoAttesterIssuer), jwt.WithAudience(demoVerifierIssuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
		if err != nil {
			return attestationResultClaims{}, fmt.Errorf("verify simulated evidence: %w", err)
		}
		expectedReportHash := sha256String(reportData[:])
		if claims.ProfileType != "sbaip.simulated-evidence" || claims.Platform != platformSimulated || claims.Subject != demoAgentIssuer || claims.ID == "" ||
			claims.ReportDataSHA256 != expectedReportHash || claims.Measurement != demoMeasurement {
			return attestationResultClaims{}, fmt.Errorf("simulated evidence claims mismatch")
		}
		return attestationResultClaims{
			ProfileType: "sbaip.attestation-result", Platform: platformSimulated, Simulation: true,
			BinderSHA256: binderHash, EvidenceSHA256: evidenceHash,
			MeasurementSHA256: sha256String([]byte(demoMeasurement)),
		}, nil
	case platformSNP, platformTDX:
		expectedFormat := "application/asb-" + strings.ToLower(evidence.Platform) + "-evidence"
		if evidence.Format != expectedFormat {
			return attestationResultClaims{}, fmt.Errorf("unexpected hardware evidence format")
		}
		measurement, err := decodeExpectedMeasurement(expectedMeasurementHex)
		if err != nil {
			return attestationResultClaims{}, err
		}
		raw, err := base64.RawURLEncoding.DecodeString(evidence.Evidence)
		if err != nil {
			return attestationResultClaims{}, fmt.Errorf("decode hardware evidence: %w", err)
		}
		if evidence.Platform == platformSNP {
			var attestation sevsnp.Attestation
			if err := proto.Unmarshal(raw, &attestation); err != nil {
				return attestationResultClaims{}, fmt.Errorf("decode SNP attestation: %w", err)
			}
			verifyOptions := sevverify.DefaultOptions()
			verifyOptions.CheckRevocations = true
			verifyOptions.DisableCertFetching = false
			verifyOptions.Now = time.Now().UTC()
			if err := sevverify.SnpAttestationContext(ctx, &attestation, verifyOptions); err != nil {
				return attestationResultClaims{}, fmt.Errorf("verify SNP certificate chain and revocation: %w", err)
			}
			if err := sevvalidate.SnpAttestation(&attestation, &sevvalidate.Options{ReportData: reportData[:], Measurement: measurement}); err != nil {
				return attestationResultClaims{}, fmt.Errorf("validate SNP report data and measurement: %w", err)
			}
		} else {
			quote, err := tdxabi.QuoteToProto(raw)
			if err != nil {
				return attestationResultClaims{}, fmt.Errorf("decode TDX quote: %w", err)
			}
			verifyOptions := tdxverify.DefaultOptions()
			verifyOptions.CheckRevocations = true
			verifyOptions.GetCollateral = true
			verifyOptions.Now = time.Now().UTC()
			if err := tdxverify.TdxQuote(quote, verifyOptions); err != nil {
				return attestationResultClaims{}, fmt.Errorf("verify TDX certificate chain and revocation: %w", err)
			}
			validation := &tdxvalidate.Options{TdQuoteBodyOptions: tdxvalidate.TdQuoteBodyOptions{ReportData: reportData[:], MrTd: measurement}}
			if err := tdxvalidate.TdxQuote(quote, validation); err != nil {
				return attestationResultClaims{}, fmt.Errorf("validate TDX report data and measurement: %w", err)
			}
		}
		return attestationResultClaims{
			ProfileType: "sbaip.attestation-result", Platform: evidence.Platform, Simulation: false,
			BinderSHA256: binderHash, EvidenceSHA256: sha256String(raw), MeasurementSHA256: sha256String(measurement),
		}, nil
	default:
		return attestationResultClaims{}, fmt.Errorf("unsupported evidence platform %q", evidence.Platform)
	}
}

func decodeExpectedMeasurement(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("expected hardware measurement is required")
	}
	measurement, err := hex.DecodeString(value)
	if err != nil || len(measurement) != 48 {
		return nil, fmt.Errorf("expected hardware measurement must be exactly 48 bytes of hex")
	}
	if bytes.Equal(measurement, make([]byte, 48)) {
		return nil, fmt.Errorf("all-zero hardware measurement is not accepted")
	}
	return measurement, nil
}
