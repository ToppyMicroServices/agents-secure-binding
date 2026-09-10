// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	authorityIssuer = "urn:asb-human:local-authority"
	authorityKeyID  = "local-authority"
	localAudience   = "asb-human.local"
)

type challenge struct {
	ID        string    `json:"challenge_id"`
	Nonce     string    `json:"nonce"`
	Grant     string    `json:"grant_jwt"`
	ExpiresAt time.Time `json:"expires_at"`
}

type executeEnvelope struct {
	Command     Command `json:"command"`
	ChallengeID string  `json:"challenge_id"`
	GrantJWT    string  `json:"grant_jwt"`
	SessionJWT  string  `json:"session_binding_jwt"`
}

type pendingProof struct {
	challenge challenge
	actor     string
	digest    string
	binding   identitypolicy.Binding
}

// CoreServer accepts only the two fixed local client identities. Its grant
// authority is intentionally local and is not a remote Human matching service.
type CoreServer struct {
	store       *Store
	credentials *credentials
	mu          sync.Mutex
	pending     map[string]pendingProof
}

func NewCoreServer(dir string, store *Store) (*CoreServer, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	creds, err := loadCredentials(dir)
	if err != nil {
		return nil, err
	}
	return &CoreServer{store: store, credentials: creds, pending: make(map[string]pendingProof)}, nil
}

func (s *CoreServer) TLSConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.credentials.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: s.credentials.ca, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
}

func (s *CoreServer) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

func (s *CoreServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || (r.URL.Path != ChallengePath && r.URL.Path != CommandPath) {
		writeAPIError(w, ErrNotFound)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeAPIError(w, ErrInvalid)
		return
	}
	actor, err := s.peerActor(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	if r.URL.Path == ChallengePath {
		var cmd Command
		if err := decodeJSON(r.Body, &cmd); err != nil {
			writeAPIError(w, err)
			return
		}
		proof, err := s.issue(r, actor, cmd)
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, proof)
		return
	}
	var envelope executeEnvelope
	if err := decodeJSON(r.Body, &envelope); err != nil {
		writeAPIError(w, err)
		return
	}
	raw, err := s.execute(r, actor, envelope)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	_, _ = w.Write(raw)
}

func (s *CoreServer) peerActor(r *http.Request) (string, error) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return "", ErrUnauthorized
	}
	for actor, peer := range s.credentials.peers {
		if bytes.Equal(peer.RawSubjectPublicKeyInfo, r.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo) {
			return actor, nil
		}
	}
	return "", ErrUnauthorized
}

func (s *CoreServer) issue(r *http.Request, actor string, cmd Command) (challenge, error) {
	if err := cmd.Validate(); err != nil {
		return challenge{}, err
	}
	if !ActorAllowed(actor, cmd.Kind) {
		return challenge{}, ErrUnauthorized
	}
	contextBytes, err := CommandContext(cmd)
	if err != nil {
		return challenge{}, err
	}
	digest, err := CommandDigest(cmd)
	if err != nil {
		return challenge{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return challenge{}, ErrUnavailable
	}
	now := time.Now().UTC()
	proof := challenge{ID: uuid.NewString(), Nonce: base64.RawURLEncoding.EncodeToString(nonce), ExpiresAt: now.Add(time.Minute)}
	binding, err := production.SoftwareBindingFromTLS(r.TLS, r.TLS.PeerCertificates[0], contextBytes, proof.Nonce)
	if err != nil {
		return challenge{}, ErrUnauthorized
	}
	values := CommandPolicy(cmd, actor).Expected
	proof.Grant, err = signToken(s.credentials.authority, authorityKeyID, jwt.MapClaims{
		"iss": authorityIssuer, "sub": actor, "aud": localAudience, "jti": uuid.NewString(), "iat": now.Add(-time.Second).Unix(), "exp": proof.ExpiresAt.Unix(),
		"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion, "cnf": map[string]string{"kid": actor},
		"service": values.Service, "agent": values.Agent, "task_id": values.TaskID, "intent_ref": values.IntentRef, "capability_ref": values.CapabilityRef,
		"scopes": values.Scopes, "resources": values.Resources, "authorization_details": values.AuthorizationDetails,
	})
	if err != nil {
		return challenge{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.pending {
		if !p.challenge.ExpiresAt.After(now) {
			delete(s.pending, id)
		}
	}
	if len(s.pending) >= 256 {
		return challenge{}, ErrUnavailable
	}
	s.pending[proof.ID] = pendingProof{challenge: proof, actor: actor, digest: digest, binding: binding}
	return proof, nil
}

func (s *CoreServer) execute(r *http.Request, actor string, envelope executeEnvelope) ([]byte, error) {
	cmd := envelope.Command
	if err := cmd.Validate(); err != nil {
		return nil, err
	}
	if !ActorAllowed(actor, cmd.Kind) {
		return nil, ErrUnauthorized
	}
	digest, err := CommandDigest(cmd)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	p, ok := s.pending[envelope.ChallengeID]
	delete(s.pending, envelope.ChallengeID)
	s.mu.Unlock()
	if !ok || p.actor != actor || p.digest != digest || p.challenge.Grant != envelope.GrantJWT || !p.challenge.ExpiresAt.After(time.Now()) {
		return nil, ErrUnauthorized
	}
	contextBytes, err := CommandContext(cmd)
	if err != nil {
		return nil, err
	}
	binding, err := production.SoftwareBindingFromTLS(r.TLS, r.TLS.PeerCertificates[0], contextBytes, p.challenge.Nonce)
	if err != nil || binding.TLSExporterSHA256 != p.binding.TLSExporterSHA256 || binding.LeafPublicKeySHA256 != p.binding.LeafPublicKeySHA256 {
		return nil, ErrUnauthorized
	}
	ctx := r.Context()
	return s.store.Execute(ctx, cmd, func(replay identitypolicy.ReplayCache) (production.AcceptedIdentity, error) {
		profile := production.SoftwareOnlyProfile{
			GrantAuthority:   localAuthority(authorityIssuer, authorityKeyID, s.credentials.authority.Public()),
			BindingAuthority: localAuthority(actor, actor, s.credentials.peers[actor].PublicKey),
			IdentityPolicy:   CommandPolicy(cmd, actor), ReplayCache: replay,
		}
		accepted, err := profile.Verify(ctx, production.SoftwareOnlyVerifyRequest{GrantJWT: envelope.GrantJWT, SessionBindingJWT: envelope.SessionJWT, ExpectedBinding: binding})
		if err != nil {
			if errors.Is(err, ErrUnavailable) {
				return production.AcceptedIdentity{}, ErrUnavailable
			}
			return production.AcceptedIdentity{}, ErrUnauthorized
		}
		return accepted, nil
	})
}

func localAuthority(issuer, kid string, key any) production.AuthorityPolicy {
	return production.AuthorityPolicy{ExpectedIssuer: issuer, ExpectedAudience: localAudience, ValidMethods: []string{jwt.SigningMethodEdDSA.Alg()}, TrustSource: production.StaticTrustSource{Trust: production.TrustSnapshot{Keys: []clients.LocalKey{{KeyID: kid, Key: key}}}}, MaxTokenLifetime: 2 * time.Minute, ClockSkew: 2 * time.Second}
}

func signToken(key ed25519.PrivateKey, kid string, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func writeAPIError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusServiceUnavailable, "OUTCOME_UNKNOWN", ErrUnavailable.Error()
	switch {
	case errors.Is(err, ErrInvalid):
		status, code, message = http.StatusBadRequest, "INVALID_REQUEST", ErrInvalid.Error()
	case errors.Is(err, ErrUnauthorized):
		status, code, message = http.StatusUnauthorized, "UNAUTHORIZED", ErrUnauthorized.Error()
	case errors.Is(err, ErrNotFound):
		status, code, message = http.StatusNotFound, "NOT_FOUND", ErrNotFound.Error()
	case errors.Is(err, ErrConflict):
		status, code, message = http.StatusConflict, "CONFLICT", ErrConflict.Error()
	}
	writeJSONResponse(w, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message})
}

// writeJSONResponse encodes fresh responses before committing their status.
// A socket write failure ends this response; it cannot undo an earlier commit.
func writeJSONResponse(w http.ResponseWriter, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		status = http.StatusServiceUnavailable
		raw = []byte(`{"code":"OUTCOME_UNKNOWN","message":"response unavailable"}`)
	}
	w.WriteHeader(status)
	if _, err := w.Write(append(raw, '\n')); err != nil {
		return
	}
}

// Client derives its holder proof from its own live TLS connection. A fresh
// connection/challenge/proof is used for each command, including result lookup.
type Client struct {
	address   string
	actor     string
	tlsConfig *tls.Config
	pair      tls.Certificate
}

func NewClient(dir, actor, address string) (*Client, error) {
	if !loopbackAddress(address) {
		return nil, fmt.Errorf("core address must be a loopback IP and port")
	}
	name := ""
	switch actor {
	case ActorAgent:
		name = "agent"
	case ActorGateway:
		name = "gateway"
	default:
		return nil, ErrUnauthorized
	}
	roots, err := loadRoots(dir)
	if err != nil {
		return nil, err
	}
	pair, err := loadPair(dir, name)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	return &Client{address, actor, config, pair}, nil
}

func (c *Client) Execute(ctx context.Context, cmd Command) ([]byte, error) {
	if ctx == nil || c == nil {
		return nil, ErrInvalid
	}
	if err := cmd.Validate(); err != nil {
		return nil, err
	}
	if !ActorAllowed(c.actor, cmd.Kind) {
		return nil, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: c.tlsConfig.Clone()}
	conn, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return nil, fmt.Errorf("connect to local core: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, ErrUnauthorized
	}
	reader := bufio.NewReader(conn)
	raw, err := c.exchange(conn, reader, ChallengePath, cmd)
	if err != nil {
		return nil, err
	}
	var proof challenge
	if json.Unmarshal(raw, &proof) != nil || proof.ID == "" || proof.Nonce == "" {
		return nil, ErrUnauthorized
	}
	contextBytes, err := CommandContext(cmd)
	if err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	binding, err := production.SoftwareBindingFromTLS(&state, c.pair.Leaf, contextBytes, proof.Nonce)
	if err != nil {
		return nil, ErrUnauthorized
	}
	now := time.Now().UTC()
	if !proof.ExpiresAt.After(now) || proof.ExpiresAt.After(now.Add(2*time.Minute)) {
		return nil, ErrUnauthorized
	}
	sessionJWT, err := signToken(c.pair.PrivateKey.(ed25519.PrivateKey), c.actor, jwt.MapClaims{
		"iss": c.actor, "aud": localAudience, "jti": uuid.NewString(), "iat": now.Add(-time.Second).Unix(), "exp": proof.ExpiresAt.Unix(),
		"profile_type": clients.TokenTypeSessionBinding, "profile_version": clients.ProfileVersion, "grant_hash": clients.IdentityGrantHash(proof.Grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256, "tls_exporter_sha256": binding.TLSExporterSHA256, "request_context_sha256": binding.RequestContextSHA256, "nonce": binding.Nonce,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	return c.exchange(conn, reader, CommandPath, executeEnvelope{Command: cmd, ChallengeID: proof.ID, GrantJWT: proof.Grant, SessionJWT: sessionJWT})
}

func (c *Client) exchange(conn net.Conn, reader *bufio.Reader, path string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrInvalid
	}
	request, err := http.NewRequest(http.MethodPost, "https://"+c.address+path, bytes.NewReader(raw))
	if err != nil {
		return nil, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	if err := request.Write(conn); err != nil {
		return nil, fmt.Errorf("%w: request connection closed", ErrUnavailable)
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("%w: response connection closed", ErrUnavailable)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusBadRequest:
			return nil, ErrInvalid
		case http.StatusUnauthorized:
			return nil, ErrUnauthorized
		case http.StatusNotFound:
			return nil, ErrNotFound
		case http.StatusConflict:
			return nil, ErrConflict
		default:
			return nil, ErrUnavailable
		}
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") || !json.Valid(body) {
		return nil, ErrUnavailable
	}
	return body, nil
}
