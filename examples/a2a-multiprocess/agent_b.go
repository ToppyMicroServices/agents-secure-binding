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
	"github.com/thinksyncs/agents-secure-binding/pkg/llmruntime"
)

type agentBServer struct {
	managerKey          any
	agentKey            any
	verifierKey         any
	replay              identitypolicy.ReplayCache
	allowSimulation     bool
	expectedMeasurement string
	publicURL           string
	generator           llmruntime.Generator
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
	var generator llmruntime.Generator
	if effectiveWorkflow(opts.workflow) == workflowLLMConversation {
		if err := validateAgentBConversationOptions(opts); err != nil {
			return err
		}
		configuredGenerator, generationErr := newConversationGenerator(opts.agentBLLMURL, opts.agentBLLMModel, opts.agentBAPIKeyEnv, opts.allowInsecureLLMLoopback)
		if generationErr != nil {
			return fmt.Errorf("configure Agent B LLM: %w", generationErr)
		}
		generator = configuredGenerator
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
		publicURL: opts.publicURL, generator: generator,
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
		writeA2AProtocolError(w, http.StatusBadRequest, "VERSION_NOT_SUPPORTED", "A2A-Version must be 1.0")
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
		writeASBA2AError(w, http.StatusForbidden, "mutual-tls-required", "Mutual TLS is required")
		return
	}
	if r.Header.Get("A2A-Version") != a2aVersion {
		writeA2AProtocolError(w, http.StatusBadRequest, "VERSION_NOT_SUPPORTED", "A2A-Version must be 1.0")
		return
	}
	if r.Header.Get("A2A-Extensions") != securityBindingExtension+","+attestationResultExtension {
		writeA2AProtocolError(w, http.StatusBadRequest, "EXTENSION_SUPPORT_REQUIRED", "The required ASB extensions were not selected")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != a2aMediaType {
		writeASBA2AError(w, http.StatusUnsupportedMediaType, "media-type", "Content-Type must be application/a2a+json")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(raw) > maxBodySize {
		writeASBA2AError(w, http.StatusBadRequest, "invalid-request", "The request body is unavailable or too large")
		return
	}
	var request a2aSendMessageRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeASBA2AError(w, http.StatusBadRequest, "invalid-request", "The request is outside the supported Send Message subset")
		return
	}
	if request.Message.TaskID != "" {
		writeA2AProtocolError(w, http.StatusNotFound, "TASK_NOT_FOUND", "The specified task ID does not exist or is not accessible")
		return
	}
	if request.Message.MessageID == "" || request.Message.ContextID != demoContextID ||
		request.Message.Role != "ROLE_USER" || !hasExactExtensions(request.Message.Extensions) {
		writeASBA2AError(w, http.StatusForbidden, "message-policy", "Message identifiers, role, or extensions do not match policy")
		return
	}
	operation, resource, err := taskOperationAndResource(request.Message)
	if err != nil || operation == "" || resource == "" {
		writeASBA2AError(w, http.StatusForbidden, "message-policy", "Operation or resource is missing or malformed")
		return
	}
	var sbo securityBindingObject
	if err := json.Unmarshal(request.Message.Metadata[securityBindingExtension], &sbo); err != nil {
		writeASBA2AError(w, http.StatusForbidden, "security-binding", "The Security Binding Object is missing or malformed")
		return
	}
	var attestationToken string
	if err := json.Unmarshal(request.Message.Metadata[attestationResultExtension], &attestationToken); err != nil || attestationToken == "" {
		writeASBA2AError(w, http.StatusForbidden, "attestation-result", "The attestation result is missing or malformed")
		return
	}
	contextValue, err := canonicalRequestContext(request)
	if err != nil {
		writeASBA2AError(w, http.StatusForbidden, "session-binding", "The canonical request context is invalid")
		return
	}
	expected, binder, err := deriveAcceptedBinding(r.TLS, contextValue, r.TLS.PeerCertificates[0])
	if err != nil {
		writeASBA2AError(w, http.StatusForbidden, "session-binding", "The accepted TLS session cannot be bound")
		return
	}
	attestationClaims, err := parseAttestationResult(attestationToken, s.verifierKey)
	if err != nil || attestationClaims.BinderSHA256 != sha256String(binder) {
		writeASBA2AError(w, http.StatusForbidden, "attestation-result", "The attestation result does not match the accepted session")
		return
	}
	if attestationClaims.Simulation {
		if !s.allowSimulation || attestationClaims.Platform != platformSimulated || attestationClaims.MeasurementSHA256 != sha256String([]byte(demoMeasurement)) {
			writeASBA2AError(w, http.StatusForbidden, "simulation-not-allowed", "Receiver policy does not permit this simulation result")
			return
		}
	} else {
		measurement, measurementErr := decodeExpectedMeasurement(s.expectedMeasurement)
		if measurementErr != nil || attestationClaims.MeasurementSHA256 != sha256String(measurement) ||
			(attestationClaims.Platform != platformSNP && attestationClaims.Platform != platformTDX) {
			writeASBA2AError(w, http.StatusForbidden, "measurement-mismatch", "The result does not match receiver measurement policy")
			return
		}
	}
	expected.Nonce = sbo.Nonce
	if err := validateSBO(sbo, expected, attestationClaims.BinderSHA256); err != nil {
		writeASBA2AError(w, http.StatusForbidden, "security-binding", "The Security Binding Object does not match the accepted interaction")
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
		writeASBA2AError(w, http.StatusForbidden, classifyVerificationError(err), "Grant, session, replay, or local policy validation failed")
		return
	}
	if result.Assertion.Values.TaskID != demoTaskID || result.Assertion.Values.CapabilityRef != demoCapability ||
		operation != demoOperation || resource != demoResource {
		writeASBA2AError(w, http.StatusForbidden, "message-policy", "The verified grant does not authorize this message")
		return
	}
	artifactText := "The authorized Agent B completed the bound demonstration task."
	if s.generator != nil {
		if len(request.Message.Parts) != 1 || request.Message.Parts[0].MediaType != "text/plain" || !validConversationText(request.Message.Parts[0].Text) {
			writeASBA2AError(w, http.StatusBadRequest, "invalid-llm-input", "The verified request does not contain valid LLM input")
			return
		}
		generated, generationErr := s.generator.Generate(r.Context(), llmruntime.Request{
			System: agentBSystemPrompt,
			Input:  request.Message.Parts[0].Text,
		})
		if generationErr != nil {
			writeASBA2AError(w, http.StatusServiceUnavailable, "llm-unavailable", "Agent B could not produce a model response")
			return
		}
		artifactText = generated.Text
	}
	taskID, err := randomID("task-")
	if err != nil {
		writeASBA2AError(w, http.StatusInternalServerError, "internal", "Task identifier generation failed")
		return
	}
	writeJSON(w, http.StatusOK, a2aMediaType, a2aTaskResponse{Task: a2aTask{
		ID: taskID, ContextID: request.Message.ContextID,
		Status:    a2aTaskStatus{State: "TASK_STATE_COMPLETED", Timestamp: time.Now().UTC().Format(time.RFC3339)},
		Artifacts: []a2aArtifact{{ArtifactID: "artifact-summary-1", Name: "Demonstration result", Parts: []a2aPart{{Text: artifactText, MediaType: "text/plain"}}}},
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
