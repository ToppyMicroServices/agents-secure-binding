// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	"github.com/golang-jwt/jwt/v5"
)

const (
	taskMaxMessageBytes = 16 << 10
	taskTimeout         = 5 * time.Second
	taskNonceLifetime   = time.Minute
	taskMaxNonces       = 64
)

type taskRequest struct {
	TaskID string  `json:"task_id"`
	Values []int64 `json:"values"`
}

type taskResult struct {
	TaskID     string `json:"task_id"`
	AgentID    string `json:"agent_id"`
	Caller     string `json:"caller"`
	Sum        int64  `json:"sum"`
	PID        int    `json:"pid"`
	Executions int64  `json:"executions"`
}

type taskNonceEntry struct {
	value   string
	expires time.Time
}

type taskNonceStore struct {
	mu      sync.Mutex
	entries map[string]taskNonceEntry
}

func (s *taskNonceStore) issue(state *tls.ConnectionState) (string, error) {
	key, err := taskSessionKey(state)
	if err != nil {
		return "", err
	}
	value, err := taskRandomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for existing, entry := range s.entries {
		if !entry.expires.After(now) {
			delete(s.entries, existing)
		}
	}
	if _, exists := s.entries[key]; !exists && len(s.entries) >= taskMaxNonces {
		return "", errors.New("task nonce capacity reached")
	}
	s.entries[key] = taskNonceEntry{value: value, expires: now.Add(taskNonceLifetime)}
	return value, nil
}

func (s *taskNonceStore) consume(state *tls.ConnectionState, value string) error {
	key, err := taskSessionKey(state)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[key]
	delete(s.entries, key)
	if !exists || value == "" || value != entry.value || !entry.expires.After(time.Now()) {
		return errors.New("task nonce unavailable")
	}
	return nil
}

func taskSessionKey(state *tls.ConnectionState) (string, error) {
	if state == nil {
		return "", errors.New("task TLS session unavailable")
	}
	value, err := state.ExportKeyingMaterial("EXPORTER-ASB-Agent-Task-Nonce-v1", []byte(roleAgentB), 32)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:]), nil
}

func validateTask(request taskRequest) error {
	if request.TaskID != taskID || len(request.Values) == 0 || len(request.Values) > 16 {
		return errors.New("task must select the configured sum and 1 to 16 values")
	}
	for _, value := range request.Values {
		if value < -1_000_000 || value > 1_000_000 {
			return errors.New("task value is outside the supported range")
		}
	}
	return nil
}

func taskActionContext(body []byte) ([]byte, error) {
	digest := sha256.Sum256(body)
	return json.Marshal(struct {
		Profile    string `json:"profile"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		Sender     string `json:"sender"`
		Receiver   string `json:"receiver"`
		BodySHA256 string `json:"body_sha256"`
	}{"asb.agent-interaction/v1", http.MethodPost, taskPath, roleAgentA, roleAgentB, hex.EncodeToString(digest[:])})
}

func (config processConfig) taskEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != httpsScheme || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.ForceQuery {
		return nil, errors.New("invalid task endpoint")
	}
	if err := config.validateEndpoint(endpoint.Host); err != nil {
		return nil, err
	}
	return endpoint, nil
}

func startTaskServer(ctx context.Context, config processConfig) (func(context.Context) error, error) {
	if config.Self.Role != roleAgentB || config.Target.AgentID != roleAgentB || config.Target.Audience == "" || config.StateDir == "" {
		return nil, errors.New("task server requires the configured Agent B")
	}
	endpoint, err := config.taskEndpoint(config.Target.Endpoint)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := configTLS(config)
	if err != nil {
		return nil, err
	}
	serverLeaf, err := certificateFromPEM(config.Self.Certificate)
	if err != nil || publicKeyPin(serverLeaf) != config.Target.ServerPin {
		return nil, errors.New("task server certificate does not match target policy")
	}
	caller, err := config.identity(roleAgentA)
	if err != nil {
		return nil, err
	}
	callerLeaf, err := certificateFromPEM(caller.Certificate)
	if err != nil {
		return nil, err
	}
	callerPin := publicKeyPin(callerLeaf)
	replay, err := peer.NewFileReplayCache(filepath.Join(config.StateDir, "task-replay.json"), nil)
	if err != nil {
		return nil, err
	}
	profile, err := profileFor(config, caller, config.Target.Audience, replay)
	if err != nil {
		return nil, err
	}
	profile.IdentityPolicy = identitypolicy.Policy{
		Mode: identitypolicy.ModeRequired, SetMode: identitypolicy.SetModeExact, Expected: taskValues(),
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
	}
	if err := profile.Validate(ctx); err != nil {
		return nil, err
	}
	nonces := &taskNonceStore{entries: make(map[string]taskNonceEntry)}
	var executions atomic.Int64
	trusted := func(request *http.Request) bool {
		state := request.TLS
		return state != nil && state.HandshakeComplete && state.Version == tls.VersionTLS13 && len(state.PeerCertificates) > 0 &&
			len(state.VerifiedChains) > 0 && publicKeyPin(state.PeerCertificates[0]) == callerPin
	}
	mux := http.NewServeMux()
	mux.HandleFunc(taskNoncePath, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" || !trusted(request) {
			http.Error(writer, "authentication failed", http.StatusUnauthorized)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, 0)
		if _, err := io.Copy(io.Discard, request.Body); err != nil {
			http.Error(writer, "request body not allowed", http.StatusBadRequest)
			return
		}
		nonce, err := nonces.issue(request.TLS)
		if err != nil {
			http.Error(writer, "nonce unavailable", http.StatusServiceUnavailable)
			return
		}
		writeTaskJSON(writer, struct {
			Nonce string `json:"nonce"`
		}{nonce})
	})
	mux.HandleFunc(taskPath, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" || !trusted(request) {
			http.Error(writer, "authentication failed", http.StatusUnauthorized)
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			http.Error(writer, "invalid request", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, taskMaxMessageBytes))
		var task taskRequest
		if err != nil || decodeTaskJSON(body, &task) != nil || validateTask(task) != nil {
			http.Error(writer, "invalid task", http.StatusBadRequest)
			return
		}
		nonce := request.Header.Get(peer.VerifierNonceHeader)
		if nonces.consume(request.TLS, nonce) != nil {
			http.Error(writer, "authentication failed", http.StatusUnauthorized)
			return
		}
		action, err := taskActionContext(body)
		if err != nil {
			http.Error(writer, "invalid task", http.StatusBadRequest)
			return
		}
		binding, err := production.SoftwareBindingFromTLS(request.TLS, request.TLS.PeerCertificates[0], action, nonce)
		if err != nil {
			http.Error(writer, "authentication failed", http.StatusUnauthorized)
			return
		}
		accepted, err := profile.Verify(request.Context(), production.SoftwareOnlyVerifyRequest{
			GrantJWT: request.Header.Get(peer.IdentityGrantHeader), SessionBindingJWT: request.Header.Get(peer.SessionBindingHeader), ExpectedBinding: binding,
		})
		if err != nil {
			http.Error(writer, "authentication failed", http.StatusUnauthorized)
			return
		}
		var sum int64
		for _, value := range task.Values {
			sum += value
		}
		writeTaskJSON(writer, taskResult{
			TaskID: task.TaskID, AgentID: roleAgentB, Caller: accepted.Agent,
			Sum: sum, PID: os.Getpid(), Executions: executions.Add(1),
		})
	})
	listener, err := net.Listen("tcp", endpoint.Host)
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler: mux, TLSConfig: tlsConfig, ReadHeaderTimeout: taskTimeout,
		ReadTimeout: taskTimeout, WriteTimeout: taskTimeout, IdleTimeout: taskTimeout,
		MaxHeaderBytes: taskMaxMessageBytes,
	}
	done := make(chan error, 1)
	go func() {
		err := server.ServeTLS(listener, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()
	var stopOnce sync.Once
	var stopErr error
	return func(ctx context.Context) error {
		if ctx == nil {
			return errors.New("missing task shutdown context")
		}
		stopOnce.Do(func() {
			stopErr = server.Shutdown(ctx)
			if stopErr != nil {
				stopErr = errors.Join(stopErr, server.Close())
			}
			stopErr = errors.Join(stopErr, <-done)
		})
		return stopErr
	}, nil
}

func sendTask(ctx context.Context, config processConfig, discoveredEndpoint string, request taskRequest, authorize bool) (taskResult, int, error) {
	if ctx == nil || config.Self.Role != roleAgentA || config.Target.AgentID != roleAgentB || discoveredEndpoint != config.Target.Endpoint {
		return taskResult{}, 0, errors.New("discovered task endpoint does not match local target policy")
	}
	if err := validateTask(request); err != nil {
		return taskResult{}, 0, err
	}
	if authorize && (config.TaskGrant == "" || len(config.SigningKey) != ed25519.PrivateKeySize) {
		return taskResult{}, 0, errors.New("task credentials are unavailable")
	}
	endpoint, err := config.taskEndpoint(discoveredEndpoint)
	if err != nil {
		return taskResult{}, 0, err
	}
	tlsConfig, err := configTLS(config)
	if err != nil {
		return taskResult{}, 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, taskTimeout)
	defer cancel()
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: taskTimeout}, Config: tlsConfig}
	connection, err := dialer.DialContext(ctx, "tcp", endpoint.Host)
	if err != nil {
		return taskResult{}, 0, err
	}
	defer func() { _ = connection.Close() }()
	stopCancel := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopCancel()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return taskResult{}, 0, err
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		return taskResult{}, 0, errors.New("task requires TLS")
	}
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 || publicKeyPin(state.PeerCertificates[0]) != config.Target.ServerPin {
		return taskResult{}, 0, errors.New("task server identity does not match local policy")
	}
	// Bound both HTTP response bodies and the total headers/data on this one
	// connection. The nonce and task proof use this exact TLS session.
	reader := bufio.NewReader(io.LimitReader(connection, 4*taskMaxMessageBytes))
	nonceRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, discoveredEndpoint+taskNoncePath, http.NoBody)
	if err != nil {
		return taskResult{}, 0, err
	}
	responseBody, status, err := exchangeTaskHTTP(connection, reader, nonceRequest)
	if err != nil {
		return taskResult{}, status, err
	}
	if status != http.StatusOK {
		return taskResult{}, status, fmt.Errorf("task nonce status %d", status)
	}
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	if err := decodeTaskJSON(responseBody, &nonce); err != nil || nonce.Nonce == "" || len(nonce.Nonce) > 128 {
		return taskResult{}, status, errors.New("invalid task nonce response")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return taskResult{}, 0, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, discoveredEndpoint+taskPath, bytes.NewReader(body))
	if err != nil {
		return taskResult{}, 0, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set(peer.VerifierNonceHeader, nonce.Nonce)
	if authorize {
		proof, err := signTaskBinding(config, &state, body, nonce.Nonce)
		if err != nil {
			return taskResult{}, 0, err
		}
		httpRequest.Header.Set(peer.IdentityGrantHeader, config.TaskGrant)
		httpRequest.Header.Set(peer.SessionBindingHeader, proof)
	}
	responseBody, status, err = exchangeTaskHTTP(connection, reader, httpRequest)
	if err != nil || status != http.StatusOK {
		return taskResult{}, status, err
	}
	var result taskResult
	if err := decodeTaskJSON(responseBody, &result); err != nil {
		return taskResult{}, status, err
	}
	var expectedSum int64
	for _, value := range request.Values {
		expectedSum += value
	}
	if result.TaskID != request.TaskID || result.AgentID != config.Target.AgentID || result.Caller != roleAgentA || result.Sum != expectedSum || result.PID <= 0 || result.Executions < 1 {
		return taskResult{}, status, errors.New("task response does not match the authorized interaction")
	}
	return result, status, nil
}

func signTaskBinding(config processConfig, state *tls.ConnectionState, body []byte, nonce string) (string, error) {
	leaf, err := certificateFromPEM(config.Self.Certificate)
	if err != nil {
		return "", err
	}
	action, err := taskActionContext(body)
	if err != nil {
		return "", err
	}
	binding, err := production.SoftwareBindingFromTLS(state, leaf, action, nonce)
	if err != nil {
		return "", err
	}
	id, err := taskRandomID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": roleIssuer(roleAgentA), "aud": config.Target.Audience, "jti": id,
		"iat": now.Add(-time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(config.TaskGrant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256, "tls_exporter_sha256": binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256, "nonce": binding.Nonce,
	})
	token.Header["kid"] = roleKeyID(roleAgentA)
	return token.SignedString(ed25519.PrivateKey(config.SigningKey))
}

func exchangeTaskHTTP(connection net.Conn, reader *bufio.Reader, request *http.Request) ([]byte, int, error) {
	request.Close = false
	if err := request.Write(connection); err != nil {
		return nil, 0, err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, taskMaxMessageBytes+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(body) > taskMaxMessageBytes {
		return nil, response.StatusCode, errors.New("task response exceeds limit")
	}
	if response.StatusCode == http.StatusOK {
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			return nil, response.StatusCode, errors.New("invalid task response media type")
		}
	}
	return body, response.StatusCode, nil
}

func decodeTaskJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("task must contain one JSON object")
	}
	return nil
}

func writeTaskJSON(writer http.ResponseWriter, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		http.Error(writer, "response encoding failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	if _, err := writer.Write(append(raw, '\n')); err != nil {
		// A partial response is an uncertain outcome; do not retry the task.
		return
	}
}

func taskRandomID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
