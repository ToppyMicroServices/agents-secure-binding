// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const (
	roleAgentA         = "agent-a"
	roleAgentB         = "agent-b"
	roleRelay          = "relay"
	managerIssuer      = "https://manager.interaction.test"
	managerKeyID       = "interaction-manager-ed25519-1"
	taskID             = "sum-demo-1"
	taskPath           = "/v1/task"
	taskNoncePath      = "/v1/task/nonce"
	loopbackServerName = "localhost"
	httpsScheme        = "https"
)

type trustedIdentity struct {
	Role             string             `json:"role"`
	Node             discovery.NodeInfo `json:"node"`
	Certificate      []byte             `json:"certificate_pem"`
	SigningPublicKey []byte             `json:"signing_public_key"`
}

type targetConfig struct {
	AgentID    string `json:"agent_id"`
	Name       string `json:"name"`
	Capability string `json:"capability"`
	Endpoint   string `json:"endpoint"`
	Audience   string `json:"audience"`
	ServerPin  string `json:"server_public_key_sha256"`
}

// processConfig is generated for one demo child and stored with mode 0600.
// Only that child's private keys and pre-authorized grants are included.
type processConfig struct {
	Self       trustedIdentity                   `json:"self"`
	Peers      []trustedIdentity                 `json:"peers"`
	CAPEM      []byte                            `json:"ca_pem"`
	TLSKey     []byte                            `json:"tls_key_pem"`
	SigningKey []byte                            `json:"signing_private_key"`
	ManagerKey []byte                            `json:"manager_public_key"`
	PeerGrants map[string]map[peer.Action]string `json:"peer_grants"`
	TaskGrant  string                            `json:"task_grant,omitempty"`
	Target     targetConfig                      `json:"target"`
	StateDir   string                            `json:"state_dir"`
	// Optional exact private host routes for an explicitly prepared Linux lab.
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

func (c processConfig) identity(role string) (trustedIdentity, error) {
	if c.Self.Role == role {
		return c.Self, nil
	}
	for _, candidate := range c.Peers {
		if candidate.Role == role {
			return candidate, nil
		}
	}
	return trustedIdentity{}, fmt.Errorf("identity %s is not configured", role)
}

func roleIssuer(role string) string   { return "https://" + role + ".interaction.test" }
func roleKeyID(role string) string    { return role + "-ed25519-1" }
func peerAudience(role string) string { return "https://" + role + ".discovery.test" }

func certificateFromPEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("missing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func publicKeyPin(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(digest[:])
}

func configTLS(c processConfig) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(c.Self.Certificate, c.TLSKey)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.CAPEM) {
		return nil, errors.New("invalid demo CA")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate}, RootCAs: pool, ClientCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, ServerName: loopbackServerName,
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true,
	}, nil
}

func profileFor(c processConfig, signer trustedIdentity, audience string, replay identitypolicy.ReplayCache) (production.SoftwareOnlyProfile, error) {
	if len(c.ManagerKey) != ed25519.PublicKeySize || len(signer.SigningPublicKey) != ed25519.PublicKeySize {
		return production.SoftwareOnlyProfile{}, errors.New("invalid authority key")
	}
	return production.SoftwareOnlyProfile{
		GrantAuthority: production.AuthorityPolicy{
			ExpectedIssuer: managerIssuer, ExpectedAudience: audience, ValidMethods: []string{"EdDSA"}, MaxTokenLifetime: 15 * time.Minute,
			TrustSource: production.StaticTrustSource{Trust: production.TrustSnapshot{Keys: []clients.LocalKey{{KeyID: managerKeyID, Key: ed25519.PublicKey(c.ManagerKey)}}}},
		},
		BindingAuthority: production.AuthorityPolicy{
			ExpectedIssuer: roleIssuer(signer.Role), ExpectedAudience: audience, ValidMethods: []string{"EdDSA"}, MaxTokenLifetime: 5 * time.Minute,
			TrustSource: production.StaticTrustSource{Trust: production.TrustSnapshot{Keys: []clients.LocalKey{{KeyID: roleKeyID(signer.Role), Key: ed25519.PublicKey(signer.SigningPublicKey)}}}},
		},
		ReplayCache: replay,
	}, nil
}

func taskValues() identitypolicy.Values {
	return identitypolicy.Values{
		Service: "asb-agent-interaction", Agent: roleAgentA, TaskID: taskID,
		IntentRef: "interaction:intent:sum", CapabilityRef: "interaction:sum:v1", OntologyID: "interaction:operation:v1",
		Scopes: []string{"agent.sum"}, Resources: []string{"agent:agent-b"},
	}
}

func validateLoopbackEndpoint(endpoint string) error {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || address.String() != endpoint || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
		return errors.New("demo endpoints must be fixed literal loopback addresses")
	}
	return nil
}

func (c processConfig) networkPrefixes() ([]netip.Prefix, error) {
	if len(c.AllowedCIDRs) == 0 {
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, nil
	}
	if len(c.AllowedCIDRs) != 3 {
		return nil, errors.New("private demo network requires three exact host routes")
	}
	prefixes := make([]netip.Prefix, 0, 3)
	seen := make(map[netip.Prefix]bool)
	for _, value := range c.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.String() != value || !prefix.Addr().IsPrivate() || prefix.Addr().Is4In6() || prefix.Bits() != prefix.Addr().BitLen() || seen[prefix] {
			return nil, errors.New("private demo routes must be distinct canonical private host addresses")
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func (c processConfig) validateEndpoint(endpoint string) error {
	if len(c.AllowedCIDRs) == 0 {
		return validateLoopbackEndpoint(endpoint)
	}
	prefixes, err := c.networkPrefixes()
	if err != nil {
		return err
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || address.String() != endpoint || address.Port() == 0 || address.Addr().Zone() != "" {
		return errors.New("private demo endpoint must be a fixed canonical IP and port")
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address.Addr()) {
			return nil
		}
	}
	return errors.New("demo endpoint is outside the configured host routes")
}

func readConfig(path string) (processConfig, error) {
	var config processConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	if len(raw) > 1<<20 {
		return config, errors.New("demo config exceeds limit")
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return config, err
	}
	if config.Self.Role != roleAgentA && config.Self.Role != roleAgentB && config.Self.Role != roleRelay {
		return config, errors.New("unknown role")
	}
	if len(config.SigningKey) != ed25519.PrivateKeySize || len(config.Peers) != 2 {
		return config, errors.New("invalid role credentials or peers")
	}
	for _, identity := range append([]trustedIdentity{config.Self}, config.Peers...) {
		if err := config.validateEndpoint(identity.Node.Endpoint); err != nil {
			return config, err
		}
	}
	endpoint, err := url.Parse(config.Target.Endpoint)
	if err != nil || endpoint.Scheme != httpsScheme || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return config, errors.New("invalid task endpoint")
	}
	if err := config.validateEndpoint(endpoint.Host); err != nil {
		return config, err
	}
	return config, nil
}
