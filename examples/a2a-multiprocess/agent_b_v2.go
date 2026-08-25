// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
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
	"github.com/thinksyncs/agents-secure-binding/pkg/operationjournal"
)

type agentBServerV2 struct {
	managerKey          any
	agentKey            any
	verifierKey         any
	operationClient     *httpOperationJournalClientV2
	challenges          *challengeStoreV2
	allowSimulation     bool
	expectedMeasurement string
	publicURL           string
	clock               func() time.Time
	generator           llmruntime.Generator
}

type preparedConversationInputV2 struct {
	text                 string
	textSHA256           string
	bindingContextSHA256 string
}

func runAgentBV2(ctx context.Context, opts options, out outputWriter) error {
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
	resultSealer, err := loadResultSealerV2(filepath.Join(dir, resultSealingKeyFileV2))
	if err != nil {
		return err
	}
	replayTLS, err := loadClientTLS(opts.stateDir, "agent-b", opts.replayURL)
	if err != nil {
		return err
	}
	server := &agentBServerV2{
		managerKey: managerKey, agentKey: agentKey, verifierKey: verifierKey,
		operationClient: &httpOperationJournalClientV2{client: newHTTPClient(replayTLS), url: opts.replayURL, sealer: resultSealer},
		challenges:      newChallengeStoreV2(), allowSimulation: opts.allowSimulation,
		expectedMeasurement: opts.expectedMeasurementHex, publicURL: opts.publicURL,
		clock: func() time.Time { return time.Now().UTC() }, generator: generator,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, "application/json", map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/agent-card.json", server.handleAgentCard)
	mux.HandleFunc("POST "+v2ChallengePath, server.handleChallenge)
	mux.HandleFunc("POST /message:send", server.handleMessage)
	return serveTLS(ctx, opts, "agent-b", tls.RequireAndVerifyClientCert, mux, out)
}

func (s *agentBServerV2) handleAgentCard(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("A2A-Version") != a2aVersion {
		writeProblem(w, http.StatusBadRequest, "a2a-version", "Unsupported A2A version", "A2A-Version must be 1.0")
		return
	}
	baseURL := s.publicURL
	if baseURL == "" {
		baseURL = "https://" + r.Host
	}
	writeJSON(w, http.StatusOK, a2aMediaType, map[string]any{
		"name": "ASB multiprocess Agent B", "description": "A2A receiver using the separate experimental draft-06 binding profile",
		"version":             "2.0.0-experimental",
		"supportedInterfaces": []map[string]any{{"url": baseURL, "protocolBinding": "HTTP+JSON", "protocolVersion": a2aVersion}},
		"capabilities": map[string]any{"extensions": []map[string]any{
			{"uri": securityBindingExtensionV2, "required": true},
			{"uri": attestationResultExtensionV2, "required": true},
		}},
		"securitySchemes":      map[string]any{"mutualTLS": map[string]any{"mtlsSecurityScheme": map[string]any{"description": "Demo CA-issued client certificate"}}},
		"securityRequirements": []map[string]any{{"schemes": map[string]any{"mutualTLS": map[string]any{"list": []string{}}}}},
		"skills":               []map[string]any{{"id": demoCapability, "name": "Summarize a referenced document", "description": "Summarizes one receiver-authorized document reference", "tags": []string{"demo"}}},
		"defaultInputModes":    []string{"text/plain"}, "defaultOutputModes": []string{"text/plain"},
	})
}

func (s *agentBServerV2) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if err := requirePeer(r, demoAgentIssuer); err != nil {
		writeProblem(w, http.StatusForbidden, "mutual-tls-required", "Mutual TLS required", err.Error())
		return
	}
	if err := rejectTransportIndirectionV2(r); err != nil {
		writeProblem(w, http.StatusForbidden, "direct-tls-required", "Direct TLS endpoint required", err.Error())
		return
	}
	if r.Header.Get("A2A-Version") != a2aVersion || r.Header.Get("Content-Type") != "application/json" {
		writeProblem(w, http.StatusBadRequest, "challenge-request", "Challenge request rejected", "A2A version or media type mismatch")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(raw) > maxBodySize {
		writeProblem(w, http.StatusBadRequest, "challenge-request", "Challenge request rejected", "challenge request is unavailable or too large")
		return
	}
	if _, err := decodeChallengeRequestV2(raw); err != nil {
		writeProblem(w, http.StatusBadRequest, "challenge-request", "Challenge request rejected", err.Error())
		return
	}
	challenge, err := s.challenges.issue(r.TLS, s.now())
	if err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "challenge-unavailable", "Challenge unavailable", "challenge state could not be issued")
		return
	}
	writeJSON(w, http.StatusOK, "application/json", challenge)
}

func (s *agentBServerV2) handleMessage(w http.ResponseWriter, r *http.Request) {
	if err := requirePeer(r, demoAgentIssuer); err != nil {
		writeProblem(w, http.StatusForbidden, "mutual-tls-required", "Mutual TLS required", err.Error())
		return
	}
	if err := rejectTransportIndirectionV2(r); err != nil {
		writeProblem(w, http.StatusForbidden, "direct-tls-required", "Direct TLS endpoint required", err.Error())
		return
	}
	if r.Header.Get("A2A-Version") != a2aVersion {
		writeProblem(w, http.StatusBadRequest, "a2a-version", "Unsupported A2A version", "A2A-Version must be 1.0")
		return
	}
	if r.Header.Get("A2A-Extensions") != securityBindingExtensionV2+","+attestationResultExtensionV2 {
		writeProblem(w, http.StatusBadRequest, "a2a-extensions", "Unsupported A2A extensions", "A2A-Extensions must select the exact draft-06 profile")
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != a2aMediaType || len(parameters) != 0 {
		writeProblem(w, http.StatusUnsupportedMediaType, "media-type", "Unsupported media type", "Content-Type must be exactly application/a2a+json")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil || len(raw) > maxBodySize {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "request body is unavailable or too large")
		return
	}
	request, err := decodeStrictA2ARequestV2(raw)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "invalid-request", "Invalid request", "request is outside the strict draft-06 A2A subset")
		return
	}
	if request.Message.TaskID != demoTaskID || request.Message.ContextID != demoThreadID || request.Message.Role != "ROLE_USER" {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "task, thread, or role does not match verifier policy")
		return
	}
	contexts, err := canonicalRequestContextsV2(request)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "exact target resource or operation does not match verifier policy")
		return
	}
	operationReservation, err := applicationOperationV2(request, contexts)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "message-policy", "Message policy rejected", "stable operation identity could not be derived")
		return
	}
	operationSession := newOperationSessionV2(r.Context(), s.operationClient, operationReservation)
	sbo, err := decodeSBOV2(request.Message.Metadata[securityBindingExtensionV2])
	if err != nil {
		writeProblem(w, http.StatusForbidden, "security-binding", "Security binding rejected", "Security Binding Object is missing or malformed")
		return
	}
	var attestationToken string
	if err := json.Unmarshal(request.Message.Metadata[attestationResultExtensionV2], &attestationToken); err != nil || attestationToken == "" {
		writeProblem(w, http.StatusForbidden, "attestation-result", "Attestation result rejected", "attestation result is missing or malformed")
		return
	}
	channel, err := channelTagV2At(r.TLS, s.now())
	if err != nil {
		writeProblem(w, http.StatusForbidden, "session-binding", "Session binding rejected", "accepted TLS session is unavailable")
		return
	}
	peerSPKI, err := currentPeerSPKIHashV2At(r.TLS, s.now())
	if err != nil {
		writeProblem(w, http.StatusForbidden, "challenge-rejected", "Challenge rejected", "challenge is not valid for this TLS endpoint attempt")
		return
	}
	challengeRecord, err := s.challenges.begin(sbo.VerifierNonce, sbo.AttemptID, channel, peerSPKI, s.now())
	if err != nil {
		writeProblem(w, http.StatusForbidden, "challenge-rejected", "Challenge rejected", "challenge is not valid for this TLS endpoint attempt")
		return
	}
	challengeConsumed := false
	defer func() {
		if !challengeConsumed {
			s.challenges.release(sbo.VerifierNonce)
		}
	}()

	grantVerifyOptions := clients.JWTVerifyOptions{
		ExpectedIssuer: demoManagerIssuer, ExpectedAudience: demoAudience,
		ValidMethods: []string{jwt.SigningMethodES256.Alg()}, LocalKeys: []clients.LocalKey{{KeyID: demoManagerKeyID, Key: s.managerKey}},
		Now: s.now(),
	}
	if _, err := clients.VerifyIdentityGrantJWTV2(sbo.Grant, grantVerifyOptions); err != nil {
		writeProblem(w, http.StatusForbidden, "profile-rejected", "Identity grant rejected", "authority grant verification failed")
		return
	}
	expected, _, err := deriveAcceptedBindingV2At(r.TLS, contexts, sbo.Grant, sbo.VerifierNonce, sbo.AttemptID, r.TLS.PeerCertificates[0], s.now())
	if err != nil || validateSBOV2(sbo, expected, challengeRecord.expiresAt, s.now()) != nil {
		writeProblem(w, http.StatusForbidden, "binding-context", "Binding context rejected", "request, target, grant, or accepted TLS binding does not match")
		return
	}
	var preparedConversation preparedConversationInputV2
	if s.generator != nil {
		preparedConversation, err = prepareConversationInputV2(request, expected)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid-llm-input", "Invalid LLM input", "the bound request does not contain valid model input")
			return
		}
	}
	now := s.now()
	endpointCredentialExpiresAt, err := acceptedPeerCredentialExpiryV2(r.TLS, now)
	if err != nil {
		writeProblem(w, http.StatusForbidden, "client-identity", "Client identity rejected", "accepted peer credential lifetime is unavailable")
		return
	}
	verification, err := clients.VerifySessionIdentityJWTV2(sbo.Grant, sbo.Binding, clients.SessionIdentityJWTOptionsV2{
		Grant: grantVerifyOptions,
		SessionBinding: clients.JWTVerifyOptions{
			ExpectedIssuer: demoAgentIssuer, ExpectedAudience: demoAudience,
			ValidMethods: []string{jwt.SigningMethodES256.Alg()}, LocalKeys: []clients.LocalKey{{KeyID: demoAgentKeyID, Key: s.agentKey}},
		},
		Policy: receiverPolicyV2(), ExpectedBinding: expected, ReplayCache: operationSession, Now: now,
		AcceptedProfile: identitypolicy.ProfileSelectionV2{
			ProfileType: clients.TokenTypeSessionBinding, ProfileVersion: clients.ProfileVersionV2,
			BindingProfile: bindingProfileDraft06V2, ProtocolID: v2ProtocolID,
		},
		Freshness: identitypolicy.FreshnessInputsV2{
			EndpointCredentialExpiresAt: endpointCredentialExpiresAt,
			EvidenceChallengeExpiresAt:  challengeRecord.expiresAt,
			LocalPolicyExpiresAt:        now.Add(challengeLifetimeV2),
		},
		Clock: s.now,
		AttestationVerifier: func(grant identitypolicy.VerifiedGrantV2, statement identitypolicy.VerifiedSessionBindingStatementV2, accepted identitypolicy.BindingV2) (identitypolicy.VerifiedAttestationResultV2, error) {
			attestationClaims, err := parseAttestationResultV2(attestationToken, s.verifierKey, now)
			if err != nil || attestationClaims.BinderSHA256 != accepted.AttestationBinderSHA256 {
				return identitypolicy.VerifiedAttestationResultV2{}, fmt.Errorf("attestation signature, profile, audience, or binder mismatch")
			}
			if err := s.validateAttestationPolicyV2(attestationClaims); err != nil {
				return identitypolicy.VerifiedAttestationResultV2{}, err
			}
			if statement.Binding.AttestationBinderSHA256 != attestationClaims.BinderSHA256 || accepted.AttestationBinderSHA256 != attestationClaims.BinderSHA256 {
				return identitypolicy.VerifiedAttestationResultV2{}, fmt.Errorf("attestation binder mismatch")
			}
			if attestationClaims.ExpiresAt == nil || !attestationClaims.ExpiresAt.Time.After(now) {
				return identitypolicy.VerifiedAttestationResultV2{}, fmt.Errorf("attestation result is not currently valid")
			}
			if statement.Binding.IssuedAt.Unix() != sbo.IssuedAt || statement.Binding.ExpiresAt.Unix() != sbo.ExpiresAt {
				return identitypolicy.VerifiedAttestationResultV2{}, fmt.Errorf("wrapper and proof lifetimes differ")
			}
			if err := validateChallengeBoundExpiryV2(statement.Binding.ExpiresAt.Unix(), challengeRecord.expiresAt); err != nil {
				return identitypolicy.VerifiedAttestationResultV2{}, err
			}
			if contexts.Resource != demoResource || contexts.Operation != demoOperation {
				return identitypolicy.VerifiedAttestationResultV2{}, fmt.Errorf("request does not select the exact local target")
			}
			return identitypolicy.VerifiedAttestationResultV2{
				ProfileType:       attestationClaims.ProfileType,
				ProfileVersion:    attestationClaims.ProfileVersion,
				ResultID:          attestationClaims.ID,
				Issuer:            attestationClaims.Issuer,
				Subject:           attestationClaims.Subject,
				SignerKeyID:       demoVerifierKeyID,
				Audience:          attestationClaims.Audience[0],
				AppraisalPolicyID: attestationClaims.AppraisalPolicyID,
				BinderSHA256:      attestationClaims.BinderSHA256,
				IssuedAt:          attestationClaims.IssuedAt.Time,
				ExpiresAt:         attestationClaims.ExpiresAt.Time,
			}, nil
		},
	})
	if err != nil {
		writeProblem(w, http.StatusForbidden, classifyVerificationErrorV2(err), "Identity binding rejected", "grant, proof, attestation, replay, or D3-D7 validation failed")
		return
	}
	if err := s.challenges.consume(sbo.VerifierNonce); err != nil {
		writeProblem(w, http.StatusServiceUnavailable, "challenge-state", "Challenge state unavailable", "accepted replay decision could not consume the challenge")
		return
	}
	challengeConsumed = true
	operationResult, err := operationSession.executeOnce(r.Context(), verification.Accepted.Expiry, s.now, func(ctx context.Context) (operationResultV2, error) {
		var artifactText string
		if s.generator == nil {
			artifactText = "The authorized Agent B completed the draft-06 bound demonstration task."
		} else {
			generated, generationErr := s.generateAcceptedConversationArtifactV2(ctx, preparedConversation, request, verification.Accepted)
			if generationErr != nil {
				return operationResultV2{}, generationErr
			}
			artifactText = generated
		}
		return completedOperationResultV2(request, artifactText, s.now())
	})
	if err != nil {
		var stateErr *operationStateErrorV2
		var executionErr *operationExecutionErrorV2
		switch {
		case errors.Is(err, errOperationAcceptanceExpiredV2):
			writeProblem(w, http.StatusForbidden, "accepted-assertion-expired", "Accepted assertion expired", "the accepted identity binding expired before operation start")
		case errors.As(err, &stateErr):
			writeOperationStatusErrorV2(w, stateErr.Record)
		case errors.As(err, &executionErr):
			writeProblem(w, http.StatusServiceUnavailable, "llm-unavailable", "LLM unavailable", "Agent B could not produce a model response; the operation is indeterminate")
		default:
			writeProblem(w, http.StatusServiceUnavailable, "operation-state", "Operation state unavailable", "durable operation state could not be updated")
		}
		return
	}
	writeOperationResultV2(w, operationResult)
}

func writeOperationStatusErrorV2(w http.ResponseWriter, record operationjournal.Record) {
	reason := "operation-state"
	title := "Operation already reserved"
	detail := "the operation was not executed again"
	switch record.State {
	case operationjournal.StateRunning:
		reason, title = "operation-running", "Operation is running"
	case operationjournal.StateIndeterminate:
		reason, title = "operation-indeterminate", "Operation result is indeterminate"
	case operationjournal.StateSucceeded, operationjournal.StateFailed, operationjournal.StateCanceled:
		reason, title = "operation-complete", "Operation is complete"
	}
	writeProblem(w, http.StatusConflict, reason, title, detail)
}

func prepareConversationInputV2(request a2aSendMessageRequest, expected identitypolicy.BindingV2) (preparedConversationInputV2, error) {
	if len(request.Message.Parts) != 1 || request.Message.Parts[0].MediaType != "text/plain" || !validConversationText(request.Message.Parts[0].Text) {
		return preparedConversationInputV2{}, fmt.Errorf("exactly one valid text/plain part is required")
	}
	if expected.BindingContextSHA256 == "" {
		return preparedConversationInputV2{}, fmt.Errorf("accepted binding context is missing")
	}
	contexts, err := canonicalRequestContextsV2(request)
	if err != nil || contexts.Resource != demoResource || contexts.Operation != demoOperation {
		return preparedConversationInputV2{}, fmt.Errorf("request target is invalid")
	}
	text := request.Message.Parts[0].Text
	return preparedConversationInputV2{
		text:                 text,
		textSHA256:           sha256String([]byte(text)),
		bindingContextSHA256: expected.BindingContextSHA256,
	}, nil
}

func (s *agentBServerV2) generateAcceptedConversationArtifactV2(ctx context.Context, prepared preparedConversationInputV2, request a2aSendMessageRequest, accepted identitypolicy.AcceptedAssertionV2) (string, error) {
	if s == nil || s.generator == nil {
		return "", fmt.Errorf("Agent B generator is unavailable")
	}
	if len(request.Message.Parts) != 1 || request.Message.Parts[0].Text != prepared.text ||
		sha256String([]byte(request.Message.Parts[0].Text)) != prepared.textSHA256 || !validConversationText(prepared.text) {
		return "", fmt.Errorf("prepared conversation input no longer matches the request")
	}
	profile := accepted.AcceptedProfile
	if profile.ProfileType != clients.TokenTypeSessionBinding || profile.ProfileVersion != clients.ProfileVersionV2 ||
		profile.BindingProfile != bindingProfileDraft06V2 || profile.ProtocolID != v2ProtocolID || accepted.Scope.Audience != demoAudience {
		return "", fmt.Errorf("accepted profile does not authorize draft-06 conversation execution")
	}
	if prepared.bindingContextSHA256 == "" || accepted.Scope.BindingContextSHA256 != prepared.bindingContextSHA256 {
		return "", fmt.Errorf("accepted assertion does not match the prepared request")
	}
	if accepted.ReplayCommit.State != identitypolicy.ReplayCommitStateCommittedV2 || accepted.ReplayCommit.RetainUntil.IsZero() ||
		accepted.Expiry.IsZero() || accepted.ReplayCommit.RetainUntil.Before(accepted.Expiry) || !s.now().Before(accepted.Expiry) {
		return "", fmt.Errorf("accepted replay commitment is unavailable or expired")
	}
	interaction := accepted.AcceptedInteraction
	if interaction.Type != v2InteractionType || interaction.TaskID != demoTaskID || interaction.ThreadID != demoThreadID ||
		interaction.IntentRef != demoIntent || accepted.AcceptedActor.ID != demoAgentIssuer {
		return "", fmt.Errorf("accepted interaction does not authorize this conversation")
	}
	if accepted.AcceptedTarget == nil || accepted.AcceptedTarget.Resource != demoResource || accepted.AcceptedTarget.Operation != demoOperation {
		return "", fmt.Errorf("accepted target does not authorize this conversation")
	}
	authorization := accepted.EffectiveAuthorization
	if authorization.CapabilityRef != demoCapability || len(authorization.Scopes) != 1 || authorization.Scopes[0] != demoReadScope ||
		len(authorization.Resources) != 1 || authorization.Resources[0] != demoResource {
		return "", fmt.Errorf("effective authorization does not authorize this conversation")
	}
	generated, err := s.generator.Generate(ctx, llmruntime.Request{System: agentBSystemPrompt, Input: prepared.text})
	if err != nil {
		return "", err
	}
	if !validConversationText(generated.Text) {
		return "", fmt.Errorf("Agent B generator returned invalid conversation text")
	}
	return generated.Text, nil
}

func (s *agentBServerV2) now() time.Time {
	if s != nil && s.clock != nil {
		return s.clock().UTC()
	}
	return time.Now().UTC()
}

func acceptedPeerCredentialExpiryV2(state *tls.ConnectionState, now time.Time) (time.Time, error) {
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return time.Time{}, fmt.Errorf("verified peer certificate path is unavailable")
	}
	earliest := time.Time{}
	for _, certificate := range state.VerifiedChains[0] {
		if certificate == nil || certificate.NotAfter.IsZero() {
			return time.Time{}, fmt.Errorf("verified peer certificate expiry is unavailable")
		}
		expiresAt := certificate.NotAfter.UTC()
		if earliest.IsZero() || expiresAt.Before(earliest) {
			earliest = expiresAt
		}
	}
	if now.IsZero() || !now.Before(earliest) {
		return time.Time{}, fmt.Errorf("verified peer certificate path is expired")
	}
	return earliest, nil
}

func (s *agentBServerV2) validateAttestationPolicyV2(claims *attestationResultClaims) error {
	if claims.Simulation {
		if !s.allowSimulation || claims.Platform != platformSimulated || claims.MeasurementSHA256 != sha256String([]byte(demoMeasurement)) {
			return fmt.Errorf("simulation attestation is not permitted")
		}
		return nil
	}
	measurement, err := decodeExpectedMeasurement(s.expectedMeasurement)
	if err != nil || claims.MeasurementSHA256 != sha256String(measurement) || (claims.Platform != platformSNP && claims.Platform != platformTDX) {
		return fmt.Errorf("hardware measurement mismatch")
	}
	return nil
}

func receiverPolicyV2() identitypolicy.PolicyV2 {
	return identitypolicy.PolicyV2{
		Mode: identitypolicy.ModeRequired, SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.RequirementsV2{D3: true, D4: true, D5: true, D6: true, D7: true},
		Expected: identitypolicy.Values{
			Service: demoService, Deployment: demoDeployment, Workload: demoWorkload,
			Agent: demoAgentIssuer, TaskID: demoTaskID, ThreadID: demoThreadID, IntentRef: demoIntent,
		},
		ExpectedTarget: identitypolicy.TargetV2{Resource: demoResource, Operation: demoOperation},
		ExpectedAuthorization: identitypolicy.AuthorizationV2{
			CapabilityRef: demoCapability, Scopes: []string{demoReadScope}, Resources: []string{demoResource},
		},
	}
}

func classifyVerificationErrorV2(err error) string {
	if errors.Is(err, identitypolicy.ErrReplayDetected) {
		return "replay-detected"
	}
	if errors.Is(err, identitypolicy.ErrMissingReplayCacheV2) {
		return "replay-store"
	}
	var validationErrs identitypolicy.ValidationErrors
	if errors.As(err, &validationErrs) {
		if validationErrs.Has(identitypolicy.LayerSessionBinding, identitypolicy.FieldVerifierNonce, nil) {
			return "replay-store"
		}
		for _, layer := range []string{identitypolicy.LayerD3, identitypolicy.LayerD4, identitypolicy.LayerD5, identitypolicy.LayerD6, identitypolicy.LayerD7} {
			if len(validationErrs.ByLayer(layer)) > 0 {
				return "policy-mismatch"
			}
		}
	}
	return "profile-rejected"
}
