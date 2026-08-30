// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/tdx"
	"github.com/golang-jwt/jwt/v5"
	sevclient "github.com/google/go-sev-guest/client"
	"google.golang.org/protobuf/proto"
)

func runAttester(ctx context.Context, opts options, out outputWriter) error {
	mode := strings.ToLower(opts.attestationMode)
	if mode != modeSimulation && mode != modeHardware {
		return fmt.Errorf("unsupported attestation mode %q", opts.attestationMode)
	}
	var simulationKeyPath string
	if mode == modeSimulation {
		simulationKeyPath = filepath.Join(roleDirectory(opts.stateDir, "attester"), signingKeyFile)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok", "mode": mode})
	})
	mux.HandleFunc("POST /evidence", func(w http.ResponseWriter, r *http.Request) {
		if err := requirePeer(r, demoAgentIssuer); err != nil {
			writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", err.Error())
			return
		}
		var request evidenceRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		reportData, err := base64.RawURLEncoding.DecodeString(request.ReportData)
		if err != nil || len(reportData) != 64 {
			writeProblem(w, http.StatusBadRequest, "report-data", "Invalid report data", "report data must be 64-byte base64url")
			return
		}
		response, err := collectEvidence(mode, opts.attestationPlatform, simulationKeyPath, reportData)
		if err != nil {
			writeProblem(w, http.StatusServiceUnavailable, "attestation-unavailable", "Attestation unavailable", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, "application/json", response)
	})
	return serveTLS(ctx, opts, "attester", tls.RequireAndVerifyClientCert, mux, out)
}

func collectEvidence(mode, requestedPlatform, simulationKeyPath string, reportData []byte) (evidenceResponse, error) {
	if mode == modeSimulation {
		key, err := loadPrivateKey(simulationKeyPath)
		if err != nil {
			return evidenceResponse{}, err
		}
		now := time.Now().UTC().Truncate(time.Second)
		id, err := randomID("evidence-")
		if err != nil {
			return evidenceResponse{}, err
		}
		sum := sha256.Sum256(reportData)
		token, err := signJWT(demoAttesterKeyID, key, simulatedEvidenceClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: demoAttesterIssuer, Subject: demoAgentIssuer,
				Audience: jwt.ClaimStrings{demoVerifierIssuer}, ID: id,
				IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			},
			ProfileType: "sbaip.simulated-evidence", Platform: platformSimulated,
			ReportDataSHA256: fmt.Sprintf("sha256:%x", sum[:]), Measurement: demoMeasurement,
		})
		if err != nil {
			return evidenceResponse{}, fmt.Errorf("sign simulated evidence: %w", err)
		}
		return evidenceResponse{Format: "application/asb-simulated-evidence+jwt", Platform: platformSimulated, Evidence: token}, nil
	}

	platform, err := resolveHardwarePlatform(requestedPlatform)
	if err != nil {
		return evidenceResponse{}, err
	}
	var evidence []byte
	switch platform {
	case platformSNP:
		provider, providerErr := sevclient.GetLeveledQuoteProvider()
		if providerErr != nil {
			return evidenceResponse{}, fmt.Errorf("open SNP guest device: %w", providerErr)
		}
		var userData [64]byte
		copy(userData[:], reportData)
		quote, quoteErr := sevclient.GetQuoteProtoAtLevel(provider, userData, 0)
		if quoteErr != nil {
			return evidenceResponse{}, fmt.Errorf("collect SNP evidence: %w", quoteErr)
		}
		evidence, err = proto.Marshal(quote)
		if err != nil {
			return evidenceResponse{}, fmt.Errorf("encode SNP evidence: %w", err)
		}
	case platformTDX:
		evidence, err = tdx.NewProvider().TeeAttestation(reportData)
		if err != nil {
			return evidenceResponse{}, fmt.Errorf("collect TDX evidence: %w", err)
		}
	default:
		return evidenceResponse{}, fmt.Errorf("unsupported hardware platform %q", platform)
	}
	return evidenceResponse{
		Format:   "application/asb-" + strings.ToLower(platform) + "-evidence",
		Platform: platform,
		Evidence: base64.RawURLEncoding.EncodeToString(evidence),
	}, nil
}

func resolveHardwarePlatform(requested string) (string, error) {
	switch strings.ToLower(requested) {
	case "snp":
		return platformSNP, nil
	case "tdx":
		return platformTDX, nil
	case "", platformAuto:
		switch attestation.CCPlatform() {
		case attestation.SNP, attestation.SNPvTPM:
			return platformSNP, nil
		case attestation.TDX:
			return platformTDX, nil
		default:
			return "", fmt.Errorf("no supported SNP or TDX guest device detected")
		}
	default:
		return "", fmt.Errorf("unsupported hardware platform %q", requested)
	}
}
