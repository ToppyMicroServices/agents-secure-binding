// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

type a2aConnection struct {
	conn   *tls.Conn
	reader *bufio.Reader
	host   string
}

type a2aResult struct {
	status int
	reason string
	task   a2aTaskResponse
}

var demoMessageSequence atomic.Uint64

func runAgentA(ctx context.Context, opts options, out outputWriter) error {
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
	if err := discoverAgentCard(ctx, newHTTPClient(agentBTLS.Clone()), opts.agentBURL); err != nil {
		return err
	}

	fmt.Fprintln(out, "Agents Secure Binding: multiprocess A2A 1.0 demonstration")
	fmt.Fprintf(out, "processes: Manager, Attester (%s), Verifier, durable Replay Store, Agent B, Agent A\n", opts.attestationMode)
	fmt.Fprintln(out, "transport: TLS 1.3 mutual authentication; application: A2A HTTP+JSON Send Message subset")
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
		fmt.Fprintf(out, "[PASS] %-24s %-5s status=%d risk=%s", label, action, result.status, risk)
		if result.reason != "" {
			fmt.Fprintf(out, " reason=%s", result.reason)
		}
		fmt.Fprintln(out)
		return nil
	}

	validConn, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	validRequest := newTaskRequest(demoResource)
	validRequest, err = issueBoundRequest(ctx, validConn, validRequest, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf)
	if err != nil {
		validConn.close()
		return err
	}
	validResult, err := validConn.send(validRequest, a2aVersion)
	validConn.close()
	if err != nil {
		return err
	}
	if err := report("authorized Send Message", "none", validResult, http.StatusOK, ""); err != nil {
		return err
	}

	if err := runTamperedEvidenceScenario(ctx, attesterClient, verifierClient, opts.attesterURL, opts.verifierURL); err != nil {
		return err
	}
	completed++
	fmt.Fprintln(out, "[PASS] tampered evidence        BLOCK status=403 risk=attestation_forgery reason=attestation-rejected")

	replayConn, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	replayRequest := newTaskRequest(demoResource)
	replayRequest, err = issueBoundRequest(ctx, replayConn, replayRequest, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf)
	if err != nil {
		replayConn.close()
		return err
	}
	first, err := replayConn.send(replayRequest, a2aVersion)
	if err != nil || first.status != http.StatusOK {
		replayConn.close()
		return fmt.Errorf("prepare replay scenario: first use status=%d: %w", first.status, err)
	}
	second, err := replayConn.send(replayRequest, a2aVersion)
	replayConn.close()
	if err != nil {
		return err
	}
	if err := report("durable replay", "replay", second, http.StatusForbidden, "replay-detected"); err != nil {
		return err
	}

	borrowedFrom, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	borrowedRequest := newTaskRequest(demoResource)
	borrowedRequest, err = issueBoundRequest(ctx, borrowedFrom, borrowedRequest, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf)
	borrowedFrom.close()
	if err != nil {
		return err
	}
	borrowedTo, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	borrowedResult, err := borrowedTo.send(borrowedRequest, a2aVersion)
	borrowedTo.close()
	if err != nil {
		return err
	}
	if err := report("borrowed TLS session", "session_borrowing", borrowedResult, http.StatusForbidden, "attestation-result"); err != nil {
		return err
	}

	substitutionConn, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	substitutionRequest := newTaskRequest(demoResource)
	substitutionRequest, err = issueBoundRequest(ctx, substitutionConn, substitutionRequest, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf)
	if err != nil {
		substitutionConn.close()
		return err
	}
	substitutionRequest.Message.Parts[0].Metadata["resource"] = "urn:example:document:other"
	substitutionResult, err := substitutionConn.send(substitutionRequest, a2aVersion)
	substitutionConn.close()
	if err != nil {
		return err
	}
	if err := report("resource substitution", "data_exfiltration", substitutionResult, http.StatusForbidden, "message-policy"); err != nil {
		return err
	}

	versionConn, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	versionResult, err := versionConn.send(newTaskRequest(demoResource), "0.3")
	versionConn.close()
	if err != nil {
		return err
	}
	if err := report("version downgrade", "protocol_confusion", versionResult, http.StatusBadRequest, "a2a-version"); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "summary: %d/%d expected decisions observed\n", completed, completed)
	fmt.Fprintln(out, "audit output contains decisions only; grants, bindings, evidence, and private keys were not logged")
	return nil
}

func newTaskRequest(resource string) a2aSendMessageRequest {
	return a2aSendMessageRequest{
		Message: a2aMessage{
			MessageID: fmt.Sprintf("message-%s-%d", demoTaskID, demoMessageSequence.Add(1)), ContextID: demoContextID, TaskID: demoTaskID, Role: "ROLE_USER",
			Parts:      []a2aPart{{Text: "Summarize the authorized document", MediaType: "text/plain", Metadata: map[string]string{"operation": demoOperation, "resource": resource}}},
			Extensions: []string{securityBindingExtension, attestationResultExtension},
		},
		Configuration: &a2aConfiguration{AcceptedOutputModes: []string{"text/plain"}},
	}
}

func issueBoundRequest(ctx context.Context, conn *a2aConnection, request a2aSendMessageRequest, managerClient *http.Client, managerURL string, attesterClient *http.Client, attesterURL string, verifierClient *http.Client, verifierURL string, signingKey *ecdsa.PrivateKey, agentLeaf *x509.Certificate) (a2aSendMessageRequest, error) {
	var grant grantResponse
	if err := postJSONContext(ctx, managerClient, managerURL+"/grants", grantRequest{TaskID: demoTaskID, ContextID: demoContextID}, &grant); err != nil {
		return request, fmt.Errorf("Manager grant request: %w", err)
	}
	contextValue, err := canonicalRequestContext(request)
	if err != nil {
		return request, err
	}
	state := conn.conn.ConnectionState()
	binding, binder, err := deriveAcceptedBinding(&state, contextValue, agentLeaf)
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
	nonce, err := randomID("nonce-")
	if err != nil {
		return request, err
	}
	bindingID, err := randomID("binding-")
	if err != nil {
		return request, err
	}
	bindingToken, err := signJWT(demoAgentKeyID, signingKey, jwt.MapClaims{
		"iss": demoAgentIssuer, "aud": demoAudience, "jti": bindingID,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":                clients.IdentityGrantHash(grant.IdentityGrant),
		"leaf_public_key_sha256":    binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":       binding.TLSExporterSHA256,
		"request_context_sha256":    binding.RequestContextSHA256,
		"attestation_binder_sha256": binding.AttestationBinderSHA256,
		"nonce":                     nonce,
	})
	if err != nil {
		return request, fmt.Errorf("sign Agent A session binding: %w", err)
	}
	sboID, err := randomID("sbo-")
	if err != nil {
		return request, err
	}
	sbo := securityBindingObject{
		Type: "sbaip.security-binding", Version: 1, Audience: demoAudience, ID: sboID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Mode: "identity-grant+jws-session-binding",
		GrantFormat: "jwt", Grant: grant.IdentityGrant, GrantSHA256: sha256String([]byte(grant.IdentityGrant)),
		BindingFormat: "jwt", Binding: bindingToken, BindingSHA256: sha256String([]byte(bindingToken)),
		RequestContextSHA256: binding.RequestContextSHA256, TLSExporterSHA256: binding.TLSExporterSHA256, Nonce: nonce,
	}
	sboJSON, err := json.Marshal(sbo)
	if err != nil {
		return request, err
	}
	attestationJSON, err := json.Marshal(appraisal.AttestationResult)
	if err != nil {
		return request, err
	}
	request.Message.Metadata = map[string]json.RawMessage{
		securityBindingExtension: sboJSON, attestationResultExtension: attestationJSON,
	}
	return request, nil
}

func runTamperedEvidenceScenario(ctx context.Context, attesterClient, verifierClient *http.Client, attesterURL, verifierURL string) error {
	binder := []byte("tamper-scenario-binder")
	reportData := sha512.Sum512(binder)
	var evidence evidenceResponse
	if err := postJSONContext(ctx, attesterClient, attesterURL+"/evidence", evidenceRequest{ReportData: base64.RawURLEncoding.EncodeToString(reportData[:])}, &evidence); err != nil {
		return err
	}
	tampered, err := tamperCompactJWT(evidence.Evidence)
	if err != nil {
		return err
	}
	evidence.Evidence = tampered
	var appraisal appraisalResponse
	err = postJSONContext(ctx, verifierClient, verifierURL+"/attest", appraisalRequest{Binder: base64.RawURLEncoding.EncodeToString(binder), Evidence: evidence}, &appraisal)
	if err == nil || !strings.Contains(err.Error(), "attestation-rejected") {
		return fmt.Errorf("tampered evidence was not rejected as expected")
	}
	return nil
}

func tamperCompactJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("evidence is not a compact JWT")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		return "", fmt.Errorf("evidence JWT signature is malformed")
	}
	signature[0] ^= 0x01
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, "."), nil
}

func serviceClient(opts options, rawURL string) (*http.Client, error) {
	config, err := loadClientTLS(opts.stateDir, "agent-a", rawURL)
	if err != nil {
		return nil, err
	}
	return newHTTPClient(config), nil
}

func discoverAgentCard(ctx context.Context, client *http.Client, baseURL string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/.well-known/agent-card.json", nil)
	if err != nil {
		return fmt.Errorf("create Agent B card request: %w", err)
	}
	request.Header.Set("A2A-Version", a2aVersion)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("discover Agent B card: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("discover Agent B card: status %d", response.StatusCode)
	}
	var card struct {
		SupportedInterfaces []struct {
			ProtocolBinding string `json:"protocolBinding"`
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"supportedInterfaces"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxBodySize)).Decode(&card); err != nil {
		return fmt.Errorf("decode Agent B card: %w", err)
	}
	if len(card.SupportedInterfaces) == 0 || card.SupportedInterfaces[0].ProtocolBinding != "HTTP+JSON" || card.SupportedInterfaces[0].ProtocolVersion != a2aVersion {
		return fmt.Errorf("Agent B card does not advertise the required A2A 1.0 HTTP+JSON interface")
	}
	return nil
}

func waitForHealthy(ctx context.Context, client *http.Client, baseURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastError error
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/healthz", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			lastError = fmt.Errorf("status %d", response.StatusCode)
		} else {
			lastError = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("service did not become healthy: %w", lastError)
}

func dialAgentB(rawURL string, config *tls.Config) (*a2aConnection, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Agent B URL %q", rawURL)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", parsed.Host, config.Clone())
	if err != nil {
		return nil, fmt.Errorf("connect to Agent B: %w", err)
	}
	return &a2aConnection{conn: conn, reader: bufio.NewReader(conn), host: parsed.Host}, nil
}

func (c *a2aConnection) send(request a2aSendMessageRequest, version string) (a2aResult, error) {
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
	httpRequest.Header.Set("A2A-Version", version)
	httpRequest.Header.Set("A2A-Extensions", securityBindingExtension+","+attestationResultExtension)
	if err := httpRequest.Write(c.conn); err != nil {
		return a2aResult{}, fmt.Errorf("send A2A request: %w", err)
	}
	response, err := http.ReadResponse(c.reader, httpRequest)
	if err != nil {
		return a2aResult{}, fmt.Errorf("read A2A response: %w", err)
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

func (c *a2aConnection) close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

func certificateLeaf(certificate tls.Certificate) (*x509.Certificate, error) {
	if certificate.Leaf != nil {
		return certificate.Leaf, nil
	}
	if len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("TLS certificate has no leaf")
	}
	return x509.ParseCertificate(certificate.Certificate[0])
}
