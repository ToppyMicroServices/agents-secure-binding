// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/golang-jwt/jwt/v5"
)

func TestBootstrapDemoSeparatesCredentialsAndTrust(t *testing.T) {
	root := t.TempDir()
	configs, err := bootstrapDemo(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 3 {
		t.Fatalf("got %d role configurations", len(configs))
	}
	usedKeys := make(map[string]bool)
	usedEndpoints := make(map[string]bool)
	for _, role := range []string{roleAgentA, roleRelay, roleAgentB} {
		config, ok := configs[role]
		if !ok || config.Self.Role != role {
			t.Fatalf("missing configuration for %s", role)
		}
		digest := sha256.Sum256([]byte("asb-interaction:" + role))
		if config.Self.Node.ID != hex.EncodeToString(digest[:]) {
			t.Fatalf("unexpected stable Node ID for %s", role)
		}
		if err := validateLoopbackEndpoint(config.Self.Node.Endpoint); err != nil {
			t.Fatal(err)
		}
		if usedEndpoints[config.Self.Node.Endpoint] {
			t.Fatal("discovery endpoint shared by two roles")
		}
		usedEndpoints[config.Self.Node.Endpoint] = true
		if len(config.ManagerKey) != ed25519.PublicKeySize || !bytes.Equal(config.ManagerKey, configs[roleAgentA].ManagerKey) {
			t.Fatalf("unexpected Manager public key for %s", role)
		}
		if len(config.SigningKey) != ed25519.PrivateKeySize {
			t.Fatalf("invalid signing key for %s", role)
		}
		signingPublic := ed25519.PrivateKey(config.SigningKey).Public().(ed25519.PublicKey)
		if !bytes.Equal(signingPublic, config.Self.SigningPublicKey) {
			t.Fatalf("signing key mismatch for %s", role)
		}
		certificate, err := certificateFromPEM(config.Self.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := certificateFromPEM(config.CAPEM)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
			if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: loopbackServerName, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				t.Fatalf("certificate verification for %s: %v", role, err)
			}
		}
		if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		if certificate.Subject.CommonName != role || certificate.NotAfter.Sub(certificate.NotBefore) > time.Hour+time.Second {
			t.Fatalf("unexpected certificate identity or lifetime for %s", role)
		}
		tlsPublic, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("TLS key for %s is not Ed25519", role)
		}
		keyBlock, _ := pem.Decode(config.TLSKey)
		if keyBlock == nil {
			t.Fatalf("missing private TLS key for %s", role)
		}
		private, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		tlsPrivate, ok := private.(ed25519.PrivateKey)
		if !ok || !bytes.Equal(tlsPrivate.Public().(ed25519.PublicKey), tlsPublic) {
			t.Fatalf("TLS key mismatch for %s", role)
		}
		for _, key := range []ed25519.PublicKey{signingPublic, tlsPublic} {
			if usedKeys[string(key)] || bytes.Equal(key, config.ManagerKey) || key.Equal(ca.PublicKey) {
				t.Fatalf("private key reused across identities or purposes for %s", role)
			}
			usedKeys[string(key)] = true
		}
		if len(config.Peers) != 2 || len(config.PeerGrants) != 2 {
			t.Fatalf("incomplete explicit peer membership for %s", role)
		}
		seenPeers := make(map[string]bool)
		for _, remote := range config.Peers {
			expected, ok := configs[remote.Role]
			if !ok || remote.Role == role || seenPeers[remote.Role] || !reflect.DeepEqual(remote, expected.Self) {
				t.Fatalf("unexpected peer identity for %s", role)
			}
			seenPeers[remote.Role] = true
		}
		if config.StateDir != filepath.Join(root, role) {
			t.Fatalf("unexpected state path for %s", role)
		}
		stat, err := os.Stat(config.StateDir)
		if err != nil || !stat.IsDir() || stat.Mode().Perm() != 0700 {
			t.Fatalf("state directory for %s does not have private permissions", role)
		}
		serialized, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		for remoteRole, remote := range configs {
			if remoteRole == role {
				continue
			}
			for _, secret := range [][]byte{remote.TLSKey, remote.SigningKey} {
				if bytes.Contains(serialized, []byte(base64.StdEncoding.EncodeToString(secret))) {
					t.Fatalf("configuration for %s contains another role's private key", role)
				}
			}
		}
		if role != roleAgentA && config.TaskGrant != "" {
			t.Fatalf("task execution granted to %s", role)
		}
		if config.Target != configs[roleAgentA].Target {
			t.Fatalf("inconsistent target for %s", role)
		}
		files, err := os.ReadDir(config.StateDir)
		if err != nil || len(files) != 0 {
			t.Fatalf("bootstrap persisted unexpected files for %s", role)
		}
	}
	target := configs[roleAgentA].Target
	endpoint, err := url.Parse(target.Endpoint)
	if err != nil || endpoint.Scheme != "https" || usedEndpoints[endpoint.Host] {
		t.Fatal("task listener does not have a separate HTTPS endpoint")
	}
	if err := validateLoopbackEndpoint(endpoint.Host); err != nil {
		t.Fatal(err)
	}
	bCertificate, err := certificateFromPEM(configs[roleAgentB].Self.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if target.AgentID != roleAgentB || target.Name != "sum.internal" || target.Capability != "sum" || target.Audience != "https://agent-b.interaction.test/v1/task" || target.ServerPin != publicKeyPin(bCertificate) {
		t.Fatal("target identity or public key pin mismatch")
	}
}

func TestBootstrapDemoGrantScopes(t *testing.T) {
	configs, err := bootstrapDemo(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ids := make(map[string]bool)
	for role, config := range configs {
		for _, remote := range config.Peers {
			grants := config.PeerGrants[remote.Node.ID]
			if len(grants) != 2 {
				t.Fatalf("incorrect grant count for %s", role)
			}
			for _, action := range []peer.Action{peer.ActionReplicate, peer.ActionFindNode} {
				claims := verifyBootstrapGrant(t, config, grants[action], peerAudience(remote.Role), ids)
				assertBootstrapClaims(t, claims, jwt.MapClaims{
					"sub": config.Self.Node.ID, "cnf": map[string]any{"kid": roleKeyID(role)},
					"service": "agtp-discovery-peer", "agent": config.Self.Node.ID,
					"capability_ref": "agtp:peer-action:" + string(action), "ontology_id": "agtp:peer-action:v1",
					"scopes": []any{"agtp.peer." + string(action)}, "resources": []any{"agtp-node:" + remote.Node.ID},
				})
				if _, exists := claims["task_id"]; exists {
					t.Fatal("peer grant contains a task authorization")
				}
			}
		}
	}
	config := configs[roleAgentA]
	claims := verifyBootstrapGrant(t, config, config.TaskGrant, config.Target.Audience, ids)
	values := taskValues()
	assertBootstrapClaims(t, claims, jwt.MapClaims{
		"sub": values.Agent, "cnf": map[string]any{"kid": roleKeyID(roleAgentA)},
		"service": values.Service, "agent": values.Agent, "task_id": values.TaskID,
		"intent_ref": values.IntentRef, "capability_ref": values.CapabilityRef, "ontology_id": values.OntologyID,
		"scopes": []any{"agent.sum"}, "resources": []any{"agent:agent-b"},
	})
	if len(ids) != 13 {
		t.Fatalf("got %d unique grants", len(ids))
	}
}

func verifyBootstrapGrant(t *testing.T, config processConfig, raw, audience string, ids map[string]bool) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if token.Header["kid"] != managerKeyID {
			t.Fatal("incorrect grant signing key ID")
		}
		return ed25519.PublicKey(config.ManagerKey), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(managerIssuer), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid {
		t.Fatalf("grant verification failed: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	assertBootstrapClaims(t, claims, jwt.MapClaims{"profile_type": clients.TokenTypeIdentityGrant, "profile_version": clients.ProfileVersion})
	id, ok := claims["jti"].(string)
	decodedID, err := hex.DecodeString(id)
	if !ok || err != nil || len(decodedID) != 16 || ids[id] {
		t.Fatal("grant does not have a unique random ID")
	}
	ids[id] = true
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		t.Fatal("grant missing issuance time")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || exp.Sub(iat.Time) != 10*time.Minute+time.Second {
		t.Fatal("unexpected grant lifetime")
	}
	return claims
}

func assertBootstrapClaims(t *testing.T, actual, expected jwt.MapClaims) {
	t.Helper()
	for name, value := range expected {
		if !reflect.DeepEqual(actual[name], value) {
			t.Fatalf("unexpected grant claim %s", name)
		}
	}
}
