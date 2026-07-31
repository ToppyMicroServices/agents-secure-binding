// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/ea"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
)

const (
	demoAudience       = "agent-b"
	demoManagerIssuer  = "demo-manager"
	demoAgentIssuer    = "agent-a"
	demoManagerKeyID   = "demo-manager-key"
	demoAgentKeyID     = "demo-agent-a-key"
	demoTaskID         = "task-demo-1"
	demoOperation      = "summarize"
	demoService        = "task-executor"
	demoDeployment     = "local-demo"
	demoWorkload       = "coordinator"
	demoIntent         = "urn:example:intent:summarize"
	demoCapability     = "urn:example:capability:summarize"
	demoReadScope      = "documents:read"
	demoWriteScope     = "documents:write"
	demoResource       = "urn:example:document:demo"
	identityGrantHdr   = "X-ASB-Identity-Grant"
	sessionBindingHdr  = "X-ASB-Session-Binding"
	maxRequestBodySize = 32 * 1024
)

type taskMessage struct {
	TaskID    string `json:"task_id"`
	Operation string `json:"operation"`
	InputRef  string `json:"input_ref"`
}

type decisionResponse struct {
	Decision string   `json:"decision"`
	Reason   string   `json:"reason,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	TaskID   string   `json:"task_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

type grantSpec struct {
	ID       string
	Audience string
	Scope    string
	Nonce    string
}

type credentials struct {
	Grant   string
	Binding string
}

type demoRuntime struct {
	address       string
	server        *http.Server
	serveErrors   chan error
	clientTLS     *tls.Config
	clientLeaf    *x509.Certificate
	managerKey    *ecdsa.PrivateKey
	agentKey      *ecdsa.PrivateKey
	bindingReplay identitypolicy.ReplayCache
}

type agentConnection struct {
	conn   *tls.Conn
	reader *bufio.Reader
}

func main() {
	if err := runDemo(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "a2a demo failed: %v\n", err)
		os.Exit(1)
	}
}

func runDemo(out io.Writer) (runErr error) {
	runtime, err := newDemoRuntime()
	if err != nil {
		return err
	}
	defer func() {
		if err := runtime.close(); runErr == nil && err != nil {
			runErr = err
		}
	}()

	message := taskMessage{
		TaskID:    demoTaskID,
		Operation: demoOperation,
		InputRef:  demoResource,
	}
	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode task message: %w", err)
	}

	fmt.Fprintln(out, "Agents Secure Binding: Agent-to-Agent communication demo")
	fmt.Fprintln(out, "transport: local mTLS 1.3; binding: live TLS exporter + request context")
	fmt.Fprintln(out, "attestation: disabled for this software-only demonstration")
	fmt.Fprintln(out)

	completed := 0
	run := func(label, risk string, got decisionResponse, status, wantStatus int, wantDecision, wantReason string) error {
		completed++
		return reportScenario(out, label, risk, got, status, wantStatus, wantDecision, wantReason)
	}

	validConn, err := runtime.dial()
	if err != nil {
		return err
	}
	validCredentials, err := runtime.issueCredentials(validConn, body, grantSpec{
		ID:       "allowed",
		Audience: demoAudience,
		Scope:    demoReadScope,
		Nonce:    "nonce-allowed",
	})
	if err != nil {
		validConn.close()
		return err
	}
	validResult, validStatus, err := validConn.send(body, validCredentials)
	validConn.close()
	if err != nil {
		return err
	}
	if err := run("allowed task", "none", validResult, validStatus, http.StatusOK, "accepted", ""); err != nil {
		return err
	}

	scopeResult, scopeStatus, err := runtime.singleRequest(body, grantSpec{
		ID:       "scope-escalation",
		Audience: demoAudience,
		Scope:    demoWriteScope,
		Nonce:    "nonce-scope-escalation",
	})
	if err != nil {
		return err
	}
	if err := run("scope escalation", "privilege_escalation", scopeResult, scopeStatus, http.StatusForbidden, "rejected", "policy_mismatch"); err != nil {
		return err
	}

	otherResourceMessage := message
	otherResourceMessage.InputRef = "urn:example:document:other"
	otherResourceBody, err := json.Marshal(otherResourceMessage)
	if err != nil {
		return fmt.Errorf("encode resource substitution message: %w", err)
	}
	resourceResult, resourceStatus, err := runtime.singleRequest(otherResourceBody, grantSpec{
		ID:       "resource-substitution",
		Audience: demoAudience,
		Scope:    demoReadScope,
		Nonce:    "nonce-resource-substitution",
	})
	if err != nil {
		return err
	}
	if err := run("resource substitution", "data_exfiltration", resourceResult, resourceStatus, http.StatusForbidden, "rejected", "message_policy_mismatch"); err != nil {
		return err
	}

	audienceResult, audienceStatus, err := runtime.singleRequest(body, grantSpec{
		ID:       "wrong-audience",
		Audience: "agent-c",
		Scope:    demoReadScope,
		Nonce:    "nonce-wrong-audience",
	})
	if err != nil {
		return err
	}
	if err := run("wrong audience", "cross_audience_confusion", audienceResult, audienceStatus, http.StatusForbidden, "rejected", "audience_mismatch"); err != nil {
		return err
	}

	borrowedFrom, err := runtime.dial()
	if err != nil {
		return err
	}
	borrowedCredentials, err := runtime.issueCredentials(borrowedFrom, body, grantSpec{
		ID:       "borrowed-session",
		Audience: demoAudience,
		Scope:    demoReadScope,
		Nonce:    "nonce-borrowed-session",
	})
	borrowedFrom.close()
	if err != nil {
		return err
	}
	borrowedTo, err := runtime.dial()
	if err != nil {
		return err
	}
	borrowedResult, borrowedStatus, err := borrowedTo.send(body, borrowedCredentials)
	borrowedTo.close()
	if err != nil {
		return err
	}
	if err := run("borrowed session", "session_borrowing", borrowedResult, borrowedStatus, http.StatusForbidden, "rejected", "session_binding_mismatch"); err != nil {
		return err
	}

	replayConn, err := runtime.dial()
	if err != nil {
		return err
	}
	defer replayConn.close()
	replayCredentials, err := runtime.issueCredentials(replayConn, body, grantSpec{
		ID:       "replay",
		Audience: demoAudience,
		Scope:    demoReadScope,
		Nonce:    "nonce-replay",
	})
	if err != nil {
		return err
	}
	firstResult, firstStatus, err := replayConn.send(body, replayCredentials)
	if err != nil {
		return err
	}
	if err := run("replay first use", "none", firstResult, firstStatus, http.StatusOK, "accepted", ""); err != nil {
		return err
	}
	secondResult, secondStatus, err := replayConn.send(body, replayCredentials)
	if err != nil {
		return err
	}
	if err := run("replayed request", "replay", secondResult, secondStatus, http.StatusForbidden, "rejected", "replay_detected"); err != nil {
		return err
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "summary: %d/%d expected decisions observed\n", completed, completed)
	fmt.Fprintln(out, "ephemeral certificates and signing keys were not written to disk")
	return nil
}

func newDemoRuntime() (*demoRuntime, error) {
	now := time.Now().UTC()
	serverTLS, clientTLS, clientLeaf, err := newDemoTLS(now)
	if err != nil {
		return nil, err
	}
	managerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate manager signing key: %w", err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent signing key: %w", err)
	}

	runtime := &demoRuntime{
		clientTLS:     clientTLS,
		clientLeaf:    clientLeaf,
		managerKey:    managerKey,
		agentKey:      agentKey,
		bindingReplay: identitypolicy.NewMemoryReplayCache(),
		serveErrors:   make(chan error, 1),
	}
	runtime.server = &http.Server{
		Handler:           http.HandlerFunc(runtime.handleTask),
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for Agent B: %w", err)
	}
	runtime.address = listener.Addr().String()
	tlsListener := tls.NewListener(listener, serverTLS)
	go func() {
		runtime.serveErrors <- runtime.server.Serve(tlsListener)
	}()
	return runtime, nil
}

func (d *demoRuntime) close() error {
	if d == nil || d.server == nil {
		return nil
	}
	closeErr := d.server.Close()
	serveErr := <-d.serveErrors
	if closeErr != nil {
		return fmt.Errorf("close Agent B server: %w", closeErr)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve Agent B: %w", serveErr)
	}
	return nil
}

func (d *demoRuntime) dial() (*agentConnection, error) {
	conn, err := tls.Dial("tcp", d.address, d.clientTLS.Clone())
	if err != nil {
		return nil, fmt.Errorf("Agent A connect to Agent B: %w", err)
	}
	return &agentConnection{conn: conn, reader: bufio.NewReader(conn)}, nil
}

func (d *demoRuntime) singleRequest(body []byte, spec grantSpec) (decisionResponse, int, error) {
	conn, err := d.dial()
	if err != nil {
		return decisionResponse{}, 0, err
	}
	defer conn.close()
	credentials, err := d.issueCredentials(conn, body, spec)
	if err != nil {
		return decisionResponse{}, 0, err
	}
	return conn.send(body, credentials)
}

func (d *demoRuntime) issueCredentials(conn *agentConnection, body []byte, spec grantSpec) (credentials, error) {
	if spec.Audience == "" {
		spec.Audience = demoAudience
	}
	now := time.Now().UTC().Truncate(time.Second)
	grant, err := signJWT(demoManagerKeyID, d.managerKey, jwt.MapClaims{
		"iss":             demoManagerIssuer,
		"sub":             demoAgentIssuer,
		"aud":             spec.Audience,
		"jti":             "grant-" + spec.ID,
		"iat":             now.Unix(),
		"exp":             now.Add(2 * time.Minute).Unix(),
		"profile_type":    clients.TokenTypeIdentityGrant,
		"profile_version": clients.ProfileVersion,
		"cnf":             map[string]any{"kid": demoAgentKeyID},
		"service":         demoService,
		"deployment":      demoDeployment,
		"workload":        demoWorkload,
		"agent":           demoAgentIssuer,
		"task_id":         demoTaskID,
		"intent_ref":      demoIntent,
		"capability_ref":  demoCapability,
		"scope":           spec.Scope,
		"resource":        demoResource,
	})
	if err != nil {
		return credentials{}, fmt.Errorf("manager issue grant: %w", err)
	}

	state := conn.conn.ConnectionState()
	binding, err := atls.IdentityBindingFromConnectionState(&state, &ea.ValidationResult{
		Context: requestContext(body),
		Chain:   []*x509.Certificate{d.clientLeaf},
	})
	if err != nil {
		return credentials{}, fmt.Errorf("Agent A derive session binding: %w", err)
	}
	bindingToken, err := signJWT(demoAgentKeyID, d.agentKey, jwt.MapClaims{
		"iss":                    demoAgentIssuer,
		"aud":                    spec.Audience,
		"jti":                    "binding-" + spec.ID,
		"iat":                    now.Unix(),
		"exp":                    now.Add(2 * time.Minute).Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  spec.Nonce,
	})
	if err != nil {
		return credentials{}, fmt.Errorf("Agent A issue session binding: %w", err)
	}
	return credentials{Grant: grant, Binding: bindingToken}, nil
}

func (d *demoRuntime) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/tasks" {
		writeDecision(w, http.StatusNotFound, decisionResponse{Decision: "rejected", Reason: "route_not_found"})
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeDecision(w, http.StatusForbidden, decisionResponse{Decision: "rejected", Reason: "mutual_tls_required"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
	if err != nil || len(body) > maxRequestBodySize {
		writeDecision(w, http.StatusBadRequest, decisionResponse{Decision: "rejected", Reason: "invalid_message"})
		return
	}
	var message taskMessage
	if err := json.Unmarshal(body, &message); err != nil {
		writeDecision(w, http.StatusBadRequest, decisionResponse{Decision: "rejected", Reason: "invalid_message"})
		return
	}

	expectedBinding, err := atls.IdentityBindingFromConnectionState(r.TLS, &ea.ValidationResult{
		Context: requestContext(body),
		Chain:   []*x509.Certificate{r.TLS.PeerCertificates[0]},
	})
	if err != nil {
		writeDecision(w, http.StatusForbidden, decisionResponse{Decision: "rejected", Reason: "session_binding_unavailable"})
		return
	}
	now := time.Now().UTC()
	result, err := clients.VerifySessionIdentityJWT(
		r.Header.Get(identityGrantHdr),
		r.Header.Get(sessionBindingHdr),
		clients.SessionIdentityJWTOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer:   demoManagerIssuer,
				ExpectedAudience: demoAudience,
				ValidMethods:     []string{jwt.SigningMethodES256.Alg()},
				LocalKeys:        []clients.LocalKey{{KeyID: demoManagerKeyID, Key: &d.managerKey.PublicKey}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer:   demoAgentIssuer,
				ExpectedAudience: demoAudience,
				ValidMethods:     []string{jwt.SigningMethodES256.Alg()},
				LocalKeys:        []clients.LocalKey{{KeyID: demoAgentKeyID, Key: &d.agentKey.PublicKey}},
			},
			Policy:          receiverPolicy(),
			ExpectedBinding: expectedBinding,
			ReplayCache:     d.bindingReplay,
			Now:             now,
		},
	)
	if err != nil {
		writeDecision(w, http.StatusForbidden, decisionResponse{Decision: "rejected", Reason: classifyVerificationError(err)})
		return
	}
	if message.TaskID != result.Assertion.Values.TaskID ||
		message.Operation != demoOperation ||
		result.Assertion.Values.CapabilityRef != demoCapability ||
		!contains(result.Assertion.Values.Resources, message.InputRef) {
		writeDecision(w, http.StatusForbidden, decisionResponse{Decision: "rejected", Reason: "message_policy_mismatch"})
		return
	}
	writeDecision(w, http.StatusOK, decisionResponse{
		Decision: "accepted",
		Agent:    result.Assertion.Values.Agent,
		TaskID:   result.Assertion.Values.TaskID,
		Scopes:   result.Assertion.Values.Scopes,
	})
}

func receiverPolicy() identitypolicy.Policy {
	return identitypolicy.Policy{
		Mode:    identitypolicy.ModeRequired,
		SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service:       demoService,
			Deployment:    demoDeployment,
			Workload:      demoWorkload,
			Agent:         demoAgentIssuer,
			TaskID:        demoTaskID,
			IntentRef:     demoIntent,
			CapabilityRef: demoCapability,
			Scopes:        []string{demoReadScope},
			Resources:     []string{demoResource},
		},
	}
}

func classifyVerificationError(err error) string {
	if errors.Is(err, identitypolicy.ErrReplayDetected) {
		return "replay_detected"
	}
	if errors.Is(err, jwt.ErrTokenInvalidAudience) {
		return "audience_mismatch"
	}
	var validationErrs identitypolicy.ValidationErrors
	if errors.As(err, &validationErrs) {
		if validationErrs.Has("binding", identitypolicy.FieldTLSExporterHash, identitypolicy.ErrMismatch) ||
			validationErrs.Has("binding", identitypolicy.FieldLeafPublicKeyHash, identitypolicy.ErrMismatch) ||
			validationErrs.Has("binding", identitypolicy.FieldRequestContextHash, identitypolicy.ErrMismatch) {
			return "session_binding_mismatch"
		}
		for _, layer := range []string{identitypolicy.LayerL3, identitypolicy.LayerL4, identitypolicy.LayerL5, identitypolicy.LayerL6} {
			if len(validationErrs.ByLayer(layer)) > 0 {
				return "policy_mismatch"
			}
		}
	}
	return "profile_rejected"
}

func (c *agentConnection) send(body []byte, credentials credentials) (decisionResponse, int, error) {
	if err := c.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return decisionResponse{}, 0, fmt.Errorf("set Agent A deadline: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://agent-b/tasks", bytes.NewReader(body))
	if err != nil {
		return decisionResponse{}, 0, fmt.Errorf("create Agent A request: %w", err)
	}
	req.Host = "agent-b"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(identityGrantHdr, credentials.Grant)
	req.Header.Set(sessionBindingHdr, credentials.Binding)
	if err := req.Write(c.conn); err != nil {
		return decisionResponse{}, 0, fmt.Errorf("Agent A send request: %w", err)
	}
	resp, err := http.ReadResponse(c.reader, req)
	if err != nil {
		return decisionResponse{}, 0, fmt.Errorf("Agent A read response: %w", err)
	}
	defer resp.Body.Close()
	var decision decisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return decisionResponse{}, 0, fmt.Errorf("Agent A decode response: %w", err)
	}
	return decision, resp.StatusCode, nil
}

func (c *agentConnection) close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

func reportScenario(out io.Writer, label, risk string, got decisionResponse, status, wantStatus int, wantDecision, wantReason string) error {
	if status != wantStatus || got.Decision != wantDecision || got.Reason != wantReason {
		return fmt.Errorf("scenario %q: status=%d decision=%q reason=%q, want status=%d decision=%q reason=%q", label, status, got.Decision, got.Reason, wantStatus, wantDecision, wantReason)
	}
	action := "ALLOW"
	if got.Decision == "rejected" {
		action = "BLOCK"
	}
	fmt.Fprintf(out, "[PASS] %-20s %-5s status=%d risk=%s", label, action, status, risk)
	if got.Reason != "" {
		fmt.Fprintf(out, " reason=%s", got.Reason)
	}
	fmt.Fprintln(out)
	return nil
}

func writeDecision(w http.ResponseWriter, status int, decision decisionResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		return
	}
}

func requestContext(body []byte) []byte {
	context := make([]byte, 0, len(body)+len("POST\n/tasks\n"))
	context = append(context, []byte("POST\n/tasks\n")...)
	return append(context, body...)
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func signJWT(keyID string, key *ecdsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID
	return token.SignedString(key)
}

func newDemoTLS(now time.Time) (*tls.Config, *tls.Config, *x509.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate demo CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ASB demo CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create demo CA: %w", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse demo CA: %w", err)
	}

	serverCertificate, _, err := issueDemoCertificate(now, big.NewInt(2), "agent-b", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca, caKey, []string{"agent-b"})
	if err != nil {
		return nil, nil, nil, err
	}
	clientCertificate, clientLeaf, err := issueDemoCertificate(now, big.NewInt(3), "agent-a", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca, caKey, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      pool,
		ServerName:   "agent-b",
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	return serverTLS, clientTLS, clientLeaf, nil
}

func issueDemoCertificate(now time.Time, serial *big.Int, commonName string, usages []x509.ExtKeyUsage, ca *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string) (tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate %s TLS key: %w", commonName, err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create %s TLS certificate: %w", commonName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse %s TLS certificate: %w", commonName, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, leaf, nil
}
