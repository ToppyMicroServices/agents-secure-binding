// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/golang-jwt/jwt/v5"
)

type issueMutationV2 func(claims jwt.MapClaims, sbo *securityBindingObjectV2, request *a2aSendMessageRequest)

func runAgentAV2(ctx context.Context, opts options, out outputWriter) error {
	for name, value := range map[string]string{
		"manager": opts.managerURL, "attester": opts.attesterURL,
		"verifier": opts.verifierURL, "agent-b": opts.agentBURL,
	} {
		if value == "" {
			return fmt.Errorf("%s URL is required", name)
		}
	}
	dir := roleDirectory(opts.stateDir, "agent-a")
	signingKey, err := loadPrivateKey(filepath.Join(dir, signingKeyFile))
	if err != nil {
		return err
	}
	managerClient, err := serviceClient(opts, opts.managerURL)
	if err != nil {
		return err
	}
	attesterClient, err := serviceClient(opts, opts.attesterURL)
	if err != nil {
		return err
	}
	verifierClient, err := serviceClient(opts, opts.verifierURL)
	if err != nil {
		return err
	}
	agentBTLS, err := loadClientTLS(opts.stateDir, "agent-a", opts.agentBURL)
	if err != nil {
		return err
	}
	agentLeaf, err := certificateLeaf(agentBTLS.Certificates[0])
	if err != nil {
		return err
	}
	for _, service := range []struct {
		name   string
		client *http.Client
		url    string
	}{
		{name: "Manager", client: managerClient, url: opts.managerURL},
		{name: "Attester", client: attesterClient, url: opts.attesterURL},
		{name: "Verifier", client: verifierClient, url: opts.verifierURL},
		{name: "Agent B", client: newHTTPClient(agentBTLS.Clone()), url: opts.agentBURL},
	} {
		if err := waitForHealthy(ctx, service.client, service.url, 10*time.Second); err != nil {
			return fmt.Errorf("wait for %s: %w", service.name, err)
		}
	}
	if err := discoverAgentCardV2(ctx, newHTTPClient(agentBTLS.Clone()), opts.agentBURL); err != nil {
		return err
	}

	fmt.Fprintln(out, "Agents Secure Binding: experimental draft-06 v2 multiprocess A2A demonstration")
	fmt.Fprintln(out, "profile: separate draft06-v2 challenge, context, attestation, policy, and replay path")
	fmt.Fprintln(out)

	completed := 0
	report := func(label, risk string, result a2aResult, expectedStatus int, expectedReason string) error {
		if result.status != expectedStatus || result.reason != expectedReason {
			return fmt.Errorf("scenario %q: status=%d reason=%q, want status=%d reason=%q", label, result.status, result.reason, expectedStatus, expectedReason)
		}
		completed++
		action := "ALLOW"
		if expectedStatus >= 400 {
			action = "BLOCK"
		}
		fmt.Fprintf(out, "[PASS] %-32s %-5s status=%d risk=%s", label, action, result.status, risk)
		if result.reason != "" {
			fmt.Fprintf(out, " reason=%s", result.reason)
		}
		fmt.Fprintln(out)
		return nil
	}

	issue := func(conn *a2aConnection, mutation issueMutationV2) (a2aSendMessageRequest, challengeResponseV2, error) {
		challenge, challengeErr := conn.challengeV2()
		if challengeErr != nil {
			return a2aSendMessageRequest{}, challengeResponseV2{}, challengeErr
		}
		request, issueErr := issueBoundRequestV2(ctx, conn, challenge, newTaskRequestV2(), managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf, mutation)
		return request, challenge, issueErr
	}

	validConn, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	validRequest, _, err := issue(validConn, nil)
	if err != nil {
		validConn.close()
		return err
	}
	validResult, err := validConn.sendV2(validRequest)
	if err != nil {
		validConn.close()
		return err
	}
	if err := report("authorized Send Message v2", "none", validResult, http.StatusOK, ""); err != nil {
		validConn.close()
		return err
	}
	validRequest.Message.MessageID += "-another-task"
	reused, err := validConn.sendV2(validRequest)
	validConn.close()
	if err != nil {
		return err
	}
	if err := report("nonce reuse on another task", "replay", reused, http.StatusForbidden, "challenge-rejected"); err != nil {
		return err
	}

	borrowedFrom, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	borrowedChallenge, err := borrowedFrom.challengeV2()
	if err != nil {
		borrowedFrom.close()
		return err
	}
	borrowedTo, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		borrowedFrom.close()
		return err
	}
	borrowedRequest, err := issueBoundRequestV2(ctx, borrowedTo, borrowedChallenge, newTaskRequestV2(), managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf, nil)
	borrowedFrom.close()
	if err != nil {
		borrowedTo.close()
		return err
	}
	borrowedResult, err := borrowedTo.sendV2(borrowedRequest)
	borrowedTo.close()
	if err != nil {
		return err
	}
	if err := report("borrowed challenge on TLS", "session_borrowing", borrowedResult, http.StatusForbidden, "challenge-rejected"); err != nil {
		return err
	}

	type scenario struct {
		label, risk, reason string
		mutation            issueMutationV2
	}
	scenarios := []scenario{
		{label: "target substitution", risk: "data_exfiltration", reason: "binding-context", mutation: func(_ jwt.MapClaims, _ *securityBindingObjectV2, request *a2aSendMessageRequest) {
			request.Message.Parts[0].Metadata["resource"] = demoOtherResource
		}},
		{label: "operation substitution", risk: "authority_expansion", reason: "binding-context", mutation: func(_ jwt.MapClaims, _ *securityBindingObjectV2, request *a2aSendMessageRequest) {
			request.Message.Parts[0].Metadata["operation"] = demoDisallowedOperation
		}},
		{label: "wrong endpoint role", risk: "role_confusion", reason: "profile-rejected", mutation: func(claims jwt.MapClaims, _ *securityBindingObjectV2, _ *a2aSendMessageRequest) {
			claims["endpoint_role"] = demoDisallowedEndpointRole
		}},
		{label: "wrong interaction type", risk: "interaction_confusion", reason: "profile-rejected", mutation: func(claims jwt.MapClaims, _ *securityBindingObjectV2, _ *a2aSendMessageRequest) {
			claims["interaction_type"] = demoDisallowedInteractionType
		}},
		{label: "missing exporter", risk: "channel_unbound", reason: "profile-rejected", mutation: func(claims jwt.MapClaims, _ *securityBindingObjectV2, _ *a2aSendMessageRequest) {
			delete(claims, "tls_exporter_sha256")
		}},
		{label: "reserialized grant hash", risk: "grant_substitution", reason: "profile-rejected", mutation: func(claims jwt.MapClaims, _ *securityBindingObjectV2, _ *a2aSendMessageRequest) {
			claims["grant_hash"] = sha256String([]byte("re-serialized-grant"))
		}},
		{label: "missing attestation binder", risk: "attestation_unbound", reason: "profile-rejected", mutation: func(claims jwt.MapClaims, _ *securityBindingObjectV2, _ *a2aSendMessageRequest) {
			delete(claims, "attestation_binder_sha256")
		}},
		{label: "missing attestation result", risk: "attestation_missing", reason: "invalid-request", mutation: func(_ jwt.MapClaims, _ *securityBindingObjectV2, request *a2aSendMessageRequest) {
			delete(request.Message.Metadata, attestationResultExtensionV2)
		}},
	}
	for _, scenario := range scenarios {
		conn, dialErr := dialAgentB(opts.agentBURL, agentBTLS)
		if dialErr != nil {
			return dialErr
		}
		request, _, issueErr := issue(conn, scenario.mutation)
		if issueErr != nil {
			conn.close()
			return issueErr
		}
		result, sendErr := conn.sendV2(request)
		conn.close()
		if sendErr != nil {
			return sendErr
		}
		if err := report(scenario.label, scenario.risk, result, http.StatusForbidden, scenario.reason); err != nil {
			return err
		}
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "summary: %d/%d expected draft06-v2 decisions observed\n", completed, completed)
	fmt.Fprintln(out, "audit output contains decisions only; grants, proofs, nonces, evidence, and private keys were not logged")
	return nil
}

func newTaskRequestV2() a2aSendMessageRequest {
	request := newTaskRequest(demoResource)
	request.Message.ContextID = demoThreadID
	request.Message.Extensions = []string{securityBindingExtensionV2, attestationResultExtensionV2}
	request.Message.Metadata = map[string]json.RawMessage{
		securityBindingExtensionV2:   json.RawMessage(`{}`),
		attestationResultExtensionV2: json.RawMessage(`"pending"`),
	}
	return request
}

func issueBoundRequestV2(ctx context.Context, conn *a2aConnection, challenge challengeResponseV2, request a2aSendMessageRequest, managerClient *http.Client, managerURL string, attesterClient *http.Client, attesterURL string, verifierClient *http.Client, verifierURL string, signingKey *ecdsa.PrivateKey, agentLeaf *x509.Certificate, mutation issueMutationV2) (a2aSendMessageRequest, error) {
	var grant grantResponse
	if err := postJSONContext(ctx, managerClient, managerURL+"/grants", grantRequest{TaskID: demoTaskID, ContextID: demoThreadID}, &grant); err != nil {
		return request, fmt.Errorf("Manager grant request: %w", err)
	}
	contexts, err := canonicalRequestContextsV2(request)
	if err != nil {
		return request, err
	}
	state := conn.conn.ConnectionState()
	binding, binder, err := deriveAcceptedBindingV2(&state, contexts, grant.IdentityGrant, challenge.VerifierNonce, challenge.AttemptID, agentLeaf)
	if err != nil {
		return request, err
	}
	reportData := sha512.Sum512(binder)
	var evidence evidenceResponse
	if err := postJSONContext(ctx, attesterClient, attesterURL+"/evidence", evidenceRequest{ReportData: base64.RawURLEncoding.EncodeToString(reportData[:])}, &evidence); err != nil {
		return request, fmt.Errorf("attester evidence request: %w", err)
	}
	var appraisal appraisalResponse
	if err := postJSONContext(ctx, verifierClient, verifierURL+"/attest", appraisalRequest{Binder: base64.RawURLEncoding.EncodeToString(binder), Evidence: evidence}, &appraisal); err != nil {
		return request, fmt.Errorf("verifier appraisal request: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	proofExpiresAt := time.Unix(challenge.ExpiresAt, 0).UTC()
	if !now.Before(proofExpiresAt) {
		return request, fmt.Errorf("draft-06 challenge expired before proof construction")
	}
	bindingID, err := randomID("binding-v2-")
	if err != nil {
		return request, err
	}
	claims := jwt.MapClaims{
		"iss": demoAgentIssuer, "aud": demoAudience, "jti": bindingID,
		"iat": now.Unix(), "exp": proofExpiresAt.Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersionV2,
		"grant_hash":    clients.IdentityGrantHash(grant.IdentityGrant),
		"endpoint_role": binding.EndpointRole, "interaction_type": binding.InteractionType,
		"accepted_endpoint_spki_sha256": binding.AcceptedEndpointSPKISHA256,
		"tls_exporter_sha256":           binding.TLSExporterSHA256,
		"binding_context_sha256":        binding.BindingContextSHA256,
		"attestation_binder_sha256":     binding.AttestationBinderSHA256,
		"verifier_nonce":                binding.VerifierNonce, "attempt_id": binding.AttemptID,
	}
	sboID, err := randomID("sbo-v2-")
	if err != nil {
		return request, err
	}
	sbo := securityBindingObjectV2{
		Type: "sbaip.security-binding", Version: 2, Audience: demoAudience, ID: sboID,
		IssuedAt: now.Unix(), ExpiresAt: proofExpiresAt.Unix(), Mode: "identity-grant+jws-session-binding",
		GrantFormat: jwtFormat, Grant: grant.IdentityGrant, GrantSHA256: sha256String([]byte(grant.IdentityGrant)), BindingFormat: jwtFormat,
		EndpointRole: binding.EndpointRole, InteractionType: binding.InteractionType,
		AcceptedEndpointSPKISHA256: binding.AcceptedEndpointSPKISHA256,
		TLSExporterSHA256:          binding.TLSExporterSHA256, BindingContextSHA256: binding.BindingContextSHA256,
		AttestationBinderSHA256: binding.AttestationBinderSHA256,
		VerifierNonce:           binding.VerifierNonce, AttemptID: binding.AttemptID,
	}
	if mutation != nil {
		mutation(claims, &sbo, &request)
	}
	bindingToken, err := signJWTWithTypeV2(demoAgentKeyID, clients.SessionBindingJWTTypeV2, signingKey, claims)
	if err != nil {
		return request, fmt.Errorf("sign Agent A draft-06 session proof: %w", err)
	}
	sbo.Binding = bindingToken
	sbo.BindingSHA256 = sha256String([]byte(bindingToken))
	sboJSON, err := json.Marshal(sbo)
	if err != nil {
		return request, err
	}
	attestationJSON, err := json.Marshal(appraisal.AttestationResult)
	if err != nil {
		return request, err
	}
	if request.Message.Metadata == nil {
		request.Message.Metadata = make(map[string]json.RawMessage)
	}
	request.Message.Metadata[securityBindingExtensionV2] = sboJSON
	if _, present := request.Message.Metadata[attestationResultExtensionV2]; present {
		request.Message.Metadata[attestationResultExtensionV2] = attestationJSON
	}
	return request, nil
}

func signJWTWithTypeV2(keyID, tokenType string, key *ecdsa.PrivateKey, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = tokenType
	return token.SignedString(key)
}

func (c *a2aConnection) challengeV2() (challengeResponseV2, error) {
	payload, err := json.Marshal(challengeRequestV2{})
	if err != nil {
		return challengeResponseV2{}, err
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+c.host+v2ChallengePath, bytes.NewReader(payload))
	if err != nil {
		return challengeResponseV2{}, err
	}
	request.Host = c.host
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("A2A-Version", a2aVersion)
	if err := c.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return challengeResponseV2{}, err
	}
	if err := request.Write(c.conn); err != nil {
		return challengeResponseV2{}, fmt.Errorf("send draft-06 challenge request: %w", err)
	}
	response, err := http.ReadResponse(c.reader, request)
	if err != nil {
		return challengeResponseV2{}, fmt.Errorf("read draft-06 challenge response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var p problem
		_ = json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&p)
		return challengeResponseV2{}, fmt.Errorf("challenge rejected: %s", p.Reason)
	}
	var challenge challengeResponseV2
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&challenge); err != nil {
		return challengeResponseV2{}, fmt.Errorf("decode challenge response: %w", err)
	}
	if _, err := decodeNonceV2(challenge.VerifierNonce, 32); err != nil {
		return challengeResponseV2{}, err
	}
	if challenge.AttemptID != "" {
		if _, err := decodeNonceV2(challenge.AttemptID, 16); err != nil {
			return challengeResponseV2{}, err
		}
	}
	if challenge.ExpiresAt <= time.Now().UTC().Unix() {
		return challengeResponseV2{}, fmt.Errorf("challenge is already expired")
	}
	return challenge, nil
}

func (c *a2aConnection) sendV2(request a2aSendMessageRequest) (a2aResult, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return a2aResult{}, err
	}
	if err := c.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return a2aResult{}, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, "https://"+c.host+"/message:send", bytes.NewReader(payload))
	if err != nil {
		return a2aResult{}, err
	}
	httpRequest.Host = c.host
	httpRequest.Header.Set("Content-Type", a2aMediaType)
	httpRequest.Header.Set("A2A-Version", a2aVersion)
	httpRequest.Header.Set("A2A-Extensions", securityBindingExtensionV2+","+attestationResultExtensionV2)
	if err := httpRequest.Write(c.conn); err != nil {
		return a2aResult{}, fmt.Errorf("send draft-06 A2A request: %w", err)
	}
	response, err := http.ReadResponse(c.reader, httpRequest)
	if err != nil {
		return a2aResult{}, fmt.Errorf("read draft-06 A2A response: %w", err)
	}
	defer response.Body.Close()
	result := a2aResult{status: response.StatusCode}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if err := json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&result.task); err != nil {
			return a2aResult{}, fmt.Errorf("decode A2A task: %w", err)
		}
		return result, nil
	}
	var p problem
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&p); err != nil {
		return a2aResult{}, fmt.Errorf("decode A2A problem: %w", err)
	}
	result.reason = p.Reason
	return result, nil
}

func discoverAgentCardV2(ctx context.Context, client *http.Client, baseURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/.well-known/agent-card.json", nil)
	if err != nil {
		return err
	}
	request.Header.Set("A2A-Version", a2aVersion)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("discover draft-06 Agent B card: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("discover draft-06 Agent B card: status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBodySize))
	if err != nil {
		return err
	}
	if !bytes.Contains(raw, []byte(securityBindingExtensionV2)) || !bytes.Contains(raw, []byte(attestationResultExtensionV2)) {
		return fmt.Errorf("Agent B card does not advertise the draft-06 extension profile")
	}
	return nil
}
