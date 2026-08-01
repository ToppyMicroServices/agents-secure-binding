// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

type agentBServer struct {
	managerKey          any
	agentKey            any
	verifierKey         any
	replay              identitypolicy.ReplayCache
	allowSimulation     bool
	expectedMeasurement string
	publicURL           string
}

func runAgentB(ctx context.Context, opts options, out outputWriter) error {
	if opts.bindingProfile == bindingProfileDraft06V2 {
		return runAgentBV2(ctx, opts, out)
	}
	if opts.bindingProfile != bindingProfileV1 {
		return fmt.Errorf("unsupported binding profile %q", opts.bindingProfile)
	}
	if opts.replayURL == "" {
		return fmt.Errorf("replay URL is required")
	}
	dir := roleDirectory(opts.stateDir, "agent-b")
	managerKey, err := loadPublicKey(filepath.Join(dir, managerPublicFile))
	if err != nil {
		return err
	}
	agentKey, err := loadPublicKey(filepath.Join(dir, agentPublicFile))
	if err != nil {
		return err
	}
	verifierKey, err := loadPublicKey(filepath.Join(dir, verifierPublicFile))
	if err != nil {
		return err
	}
	replayTLS, err := loadClientTLS(opts.stateDir, "agent-b", opts.replayURL)
	if err != nil {
		return err
	}
	server := &agentBServer{
		managerKey: managerKey, agentKey: agentKey, verifierKey: verifierKey,
		replay:          identitypolicy.NewSetNXReplayCache(ctx, &httpSetNXStore{client: newHTTPClient(replayTLS), url: opts.replayURL}),
		allowSimulation: opts.allowSimulation, expectedMeasurement: opts.expectedMeasurementHex,
		publicURL: opts.publicURL,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/agent-card.json", server.handleAgentCard)
	mux.HandleFunc("POST /message:send", server.handleMessage)
	return serveTLS(ctx, opts, "agent-b", tls.VerifyClientCertIfGiven, mux, out)
}

func (s *agentBServer) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("A2A-Version") != a2aVersion {
		writeProblem(w, http.StatusBadRequest, "a2a-version", "Unsupported A2A version", "A2A-Version must be 1.0")
		return
	}
	baseURL := s.publicURL
	if baseURL == "" {
		baseURL = "https://" + r.Host
	}
	writeJSON(w, http.StatusOK, a2aMediaType, map[string]any{
		"name": "ASB multiprocess Agent B", "description": "A2A receiver requiring session-bound identity and attestation",
		"version":             "1.0.0",
		"supportedInterfaces": []map[string]any{{"url": baseURL, "protocolBinding": "HTTP+JSON", "protocolVersion": a2aVersion}},
		"capabilities": map[string]any{"extensions": []map[string]any{
			{"uri": securityBindingExtension, "required": true},
			{"uri": attestationResultExtension, "required": true},
		}},
		"securitySchemes":      map[string]any{"mutualTLS": map[string]any{"mtlsSecurityScheme": map[string]any{"description": "Demo CA-issued client certificate"}}},
		"securityRequirements": []map[string]any{{"schemes": map[string]any{"mutualTLS": map[string]any{"list": []string{}}}}},
		"skills":               []map[string]any{{"id": demoCapability, "name": "Summarize a referenced document", "description": "Summarizes one receiver-authorized document reference", "tags": []string{"demo"}}},
		"defaultInputModes":    []string{"text/plain"}, "defaultOutputModes": []string{"text/plain"},
	})
}

func (s *agentBServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if err := requirePeer(r, demoAgentIssuer); err != nil {
		writeProblem(w, http.StatusForbidden, "mutual-tls-required", "Mutual TLS required", err.Error())
		return
	}
	if r.Header.Get("A2A-Version") != a2aVersion {
		writeProblem(w, http.StatusBadRequest, "a2a-version", "Unsupported A2A version", "A2A-Version must be 1.0")
		return
	}
	if r.Header.Get("A2A-Extensions") != securityBindingExtension+","+attestationResultExtension {
		writeProblem(w, http.StatusBadRequest, "a2a-extensions", "Unsupported A2A extensions", "A2A-Extensions must select the two required security extensions")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != a2aMediaType {
		writeProblem(w, http.StatusUnsupportedMediaType, "media-type", "Unsupported media type", "Content-Type must be application/a2a+json")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(raw) > maxBodySize {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "request body is unavailable or too large")
		return
	}
	var request a2aSendMessageRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "request is outside the supported A2A Send Message subset")
		return
	}
	if request.Message.MessageID == "" || request.Message.TaskID != demoTaskID || request.Message.ContextID != demoContextID ||
		request.Message.Role != "ROLE_USER" || !hasExactExtensions(request.Message.Extensions) {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "message identifiers, role, or extensions do not match policy")
		return
	}
	operation, resource, err := taskOperationAndResource(request.Message)
	if err != nil || operation != demoOperation || resource != demoResource {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "operation or resource does not match policy")
		return
	}
	var sbo securityBindingObject
	if err := json.Unmarshal(request.Message.Metadata[securityBindingExtension], &sbo); err != nil {
		writeProblem(w, http.StatusForbidden, "security-binding", "Security binding rejected", "Security Binding Object is missing or malformed")
		return
	}
	var attestationToken string
	if err := json.Unmarshal(request.Message.Metadata[attestationResultExtension], &attestationToken); err != nil || attestationToken == "" {
		writeProblem(w, http.StatusForbidden, "attestation-result", "Attestation result rejected", "attestation result is missing or malformed")
		return
	}
	contextValue, err := canonicalRequestContext(request)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "session-binding", "Session binding rejected", "canonical request context failed")
		return
	}
	expected, binder, err := deriveAcceptedBinding(r.TLS, contextValue, r.TLS.PeerCertificates[0])
	if err != nil {
		writeProblem(w, http.StatusForbidden, "session-binding", "Session binding rejected", "accepted TLS session cannot be bound")
		return
	}
	attestationClaims, err := parseAttestationResult(attestationToken, s.verifierKey)
	if err != nil || attestationClaims.BinderSHA256 != sha256String(binder) {
		writeProblem(w, http.StatusForbidden, "attestation-result", "Attestation result rejected", "signature or session binder mismatch")
		return
	}
	if attestationClaims.Simulation {
		if !s.allowSimulation || attestationClaims.Platform != platformSimulated || attestationClaims.MeasurementSHA256 != sha256String([]byte(demoMeasurement)) {
			writeProblem(w, http.StatusForbidden, "simulation-not-allowed", "Simulation attestation rejected", "receiver policy does not permit this simulation result")
			return
		}
	} else {
		measurement, measurementErr := decodeExpectedMeasurement(s.expectedMeasurement)
		if measurementErr != nil || attestationClaims.MeasurementSHA256 != sha256String(measurement) ||
			(attestationClaims.Platform != platformSNP && attestationClaims.Platform != platformTDX) {
			writeProblem(w, http.StatusForbidden, "measurement-mismatch", "Hardware measurement rejected", "result does not match receiver measurement policy")
			return
		}
	}
	expected.Nonce = sbo.Nonce
	if err := validateSBO(sbo, expected, attestationClaims.BinderSHA256); err != nil {
		writeProblem(w, http.StatusForbidden, "security-binding", "Security binding rejected", err.Error())
		return
	}
	result, err := clients.VerifySessionIdentityJWT(sbo.Grant, sbo.Binding, clients.SessionIdentityJWTOptions{
		Grant: clients.JWTVerifyOptions{
			ExpectedIssuer: demoManagerIssuer, ExpectedAudience: demoAudience,
			ValidMethods: []string{jwt.SigningMethodES256.Alg()}, LocalKeys: []clients.LocalKey{{KeyID: demoManagerKeyID, Key: s.managerKey}},
		},
		SessionBinding: clients.JWTVerifyOptions{
			ExpectedIssuer: demoAgentIssuer, ExpectedAudience: demoAudience,
			ValidMethods: []string{jwt.SigningMethodES256.Alg()}, LocalKeys: []clients.LocalKey{{KeyID: demoAgentKeyID, Key: s.agentKey}},
		},
		Policy: receiverPolicy(), ExpectedBinding: expected, ReplayCache: s.replay, Now: time.Now().UTC(),
	})
	if err != nil {
		writeProblem(w, http.StatusForbidden, classifyVerificationError(err), "Identity binding rejected", "grant, session, replay, or local policy validation failed")
		return
	}
	if result.Assertion.Values.TaskID != request.Message.TaskID || result.Assertion.Values.CapabilityRef != demoCapability {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "verified grant does not authorize this message")
		return
	}
	writeJSON(w, http.StatusOK, a2aMediaType, a2aTaskResponse{Task: a2aTask{
		ID: request.Message.TaskID, ContextID: request.Message.ContextID,
		Status:    a2aTaskStatus{State: "TASK_STATE_COMPLETED", Timestamp: time.Now().UTC().Format(time.RFC3339)},
		Artifacts: []a2aArtifact{{ArtifactID: "artifact-summary-1", Name: "Demonstration result", Parts: []a2aPart{{Text: "The authorized Agent B completed the bound demonstration task.", MediaType: "text/plain"}}}},
	}})
}

func validateSBO(sbo securityBindingObject, expected identitypolicy.Binding, binderHash string) error {
	if sbo.Type != "sbaip.security-binding" || sbo.Version != 1 || sbo.Audience != demoAudience || sbo.ID == "" ||
		sbo.Mode != "identity-grant+jws-session-binding" || sbo.GrantFormat != jwtFormat || sbo.BindingFormat != jwtFormat ||
		sbo.Grant == "" || sbo.Binding == "" || sbo.Nonce == "" {
		return fmt.Errorf("Security Binding Object contract mismatch")
	}
	if sbo.ExpiresAt <= time.Now().UTC().Unix() || sbo.IssuedAt > time.Now().UTC().Add(30*time.Second).Unix() {
		return fmt.Errorf("Security Binding Object is expired or not yet valid")
	}
	if sbo.GrantSHA256 != sha256String([]byte(sbo.Grant)) || sbo.BindingSHA256 != sha256String([]byte(sbo.Binding)) ||
		sbo.RequestContextSHA256 != expected.RequestContextSHA256 || sbo.TLSExporterSHA256 != expected.TLSExporterSHA256 ||
		expected.AttestationBinderSHA256 != binderHash {
		return fmt.Errorf("Security Binding Object hash mismatch")
	}
	return nil
}
