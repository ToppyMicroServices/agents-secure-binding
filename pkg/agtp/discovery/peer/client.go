// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
	"github.com/golang-jwt/jwt/v5"
)

// RemoteAuthorization contains verifier-specific values for one destination.
// Identity Grants are issued out of band by the Manager and may be reused
// until expiry; each request receives a fresh verifier nonce and binding proof.
type RemoteAuthorization struct {
	Audience                string
	ServerName              string
	ServerCertificateSHA256 string
	Grants                  map[Action]string
}

// Client performs one mTLS+ASB peer action per TLS connection.
type Client struct {
	AgentID          string
	Issuer           string
	KeyID            string
	PrivateKey       ed25519.PrivateKey
	TLSConfig        *tls.Config
	Remotes          map[string]RemoteAuthorization
	Timeout          time.Duration
	MaxResponseBytes int64
	Now              func() time.Time
}

// Replicate exchanges Presence and ANS deltas with one peer.
func (c *Client) Replicate(ctx context.Context, peer discovery.NodeInfo, request ReplicateRequest) (ReplicateResponse, error) {
	if request.Sender.ID != c.AgentID || request.Protocol != ProtocolVersion {
		return ReplicateResponse{}, ErrInvalidProtocol
	}
	body, err := json.Marshal(request)
	if err != nil {
		return ReplicateResponse{}, err
	}
	var response ReplicateResponse
	if err := c.do(ctx, peer, ActionReplicate, body, &response); err != nil {
		return ReplicateResponse{}, err
	}
	if response.Protocol != ProtocolVersion {
		return ReplicateResponse{}, ErrInvalidProtocol
	}
	return response, nil
}

// FindNode performs one authenticated DHT lookup hop.
func (c *Client) FindNode(ctx context.Context, peer discovery.NodeInfo, request FindNodeRequest) (FindNodeResponse, error) {
	if request.Sender.ID != c.AgentID || request.Protocol != ProtocolVersion {
		return FindNodeResponse{}, ErrInvalidProtocol
	}
	body, err := json.Marshal(request)
	if err != nil {
		return FindNodeResponse{}, err
	}
	var response FindNodeResponse
	if err := c.do(ctx, peer, ActionFindNode, body, &response); err != nil {
		return FindNodeResponse{}, err
	}
	if response.Protocol != ProtocolVersion {
		return FindNodeResponse{}, ErrInvalidProtocol
	}
	return response, nil
}

func (c *Client) do(ctx context.Context, peer discovery.NodeInfo, action Action, body []byte, target any) error {
	if c == nil || ctx == nil || c.TLSConfig == nil || len(c.PrivateKey) != ed25519.PrivateKeySize {
		return ErrUnauthorized
	}
	authorization, ok := c.Remotes[peer.ID]
	if !ok || authorization.Audience == "" || authorization.ServerName == "" || authorization.ServerCertificateSHA256 == "" || authorization.Grants[action] == "" {
		return ErrUnauthorized
	}
	path, err := actionPath(action)
	if err != nil {
		return err
	}
	config := c.TLSConfig.Clone()
	config.MinVersion = tls.VersionTLS13
	config.ServerName = authorization.ServerName
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: c.timeout()}, Config: config}
	connection, err := dialer.DialContext(ctx, "tcp", peer.Endpoint)
	if err != nil {
		return err
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		_ = connection.Close()
		return ErrUnauthorized
	}
	defer tlsConnection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConnection.SetDeadline(deadline)
	} else {
		_ = tlsConnection.SetDeadline(time.Now().Add(c.timeout()))
	}
	reader := bufio.NewReader(tlsConnection)
	state := tlsConnection.ConnectionState()
	if len(state.PeerCertificates) == 0 || certificateKey(state.PeerCertificates[0]) != authorization.ServerCertificateSHA256 {
		return ErrUnauthorized
	}
	nonce, err := requestNonce(ctx, tlsConnection, reader, peer.Endpoint, c.maxResponseBytes())
	if err != nil {
		return err
	}
	leaf, err := clientLeaf(config)
	if err != nil {
		return err
	}
	actionContext, err := canonicalActionContext(action, c.AgentID, peer.ID, body)
	if err != nil {
		return err
	}
	binding, err := production.SoftwareBindingFromTLS(&state, leaf, actionContext, nonce)
	if err != nil {
		return err
	}
	bindingJWT, err := c.signBinding(authorization, authorization.Grants[action], binding)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+peer.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(IdentityGrantHeader, authorization.Grants[action])
	request.Header.Set(SessionBindingHeader, bindingJWT)
	request.Header.Set(VerifierNonceHeader, nonce)
	responseBody, status, err := exchangeHTTP(tlsConnection, reader, request, c.maxResponseBytes())
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("agtp discovery peer: status %d", status)
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidProtocol
	}
	return nil
}

func requestNonce(ctx context.Context, connection *tls.Conn, reader *bufio.Reader, host string, maximum int64) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+NoncePath, http.NoBody)
	if err != nil {
		return "", err
	}
	body, status, err := exchangeHTTP(connection, reader, request, maximum)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", ErrUnauthorized
	}
	var response nonceResponse
	if err := json.Unmarshal(body, &response); err != nil || response.Nonce == "" {
		return "", ErrUnauthorized
	}
	return response.Nonce, nil
}

func exchangeHTTP(connection *tls.Conn, reader *bufio.Reader, request *http.Request, maximum int64) ([]byte, int, error) {
	request.Close = false
	if err := request.Write(connection); err != nil {
		return nil, 0, err
	}
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(body)) > maximum {
		return nil, 0, ErrInvalidProtocol
	}
	return body, response.StatusCode, nil
}

func (c *Client) signBinding(remote RemoteAuthorization, grant string, binding identitypolicy.Binding) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	now := c.now()
	claims := jwt.MapClaims{
		"iss":                    c.Issuer,
		"aud":                    remote.Audience,
		"jti":                    jti,
		"iat":                    now.Add(-time.Second).Unix(),
		"exp":                    now.Add(2 * time.Minute).Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  binding.Nonce,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = c.KeyID
	return token.SignedString(c.PrivateKey)
}

func (c *Client) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

func (c *Client) maxResponseBytes() int64 {
	if c.MaxResponseBytes <= 0 {
		return 1 << 20
	}
	return c.MaxResponseBytes
}

func (c *Client) now() time.Time {
	if c.Now == nil {
		return time.Now().UTC()
	}
	return c.Now().UTC()
}

func clientLeaf(config *tls.Config) (*x509.Certificate, error) {
	if len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		return nil, ErrUnauthorized
	}
	if config.Certificates[0].Leaf != nil {
		return config.Certificates[0].Leaf, nil
	}
	return x509.ParseCertificate(config.Certificates[0].Certificate[0])
}

func randomID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
