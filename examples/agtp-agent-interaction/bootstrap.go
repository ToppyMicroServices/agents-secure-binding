// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/golang-jwt/jwt/v5"
)

// bootstrapDemo prepares separate process credentials. The signing authorities'
// private keys stay here; child processes receive only their public keys.
func bootstrapDemo(rootDir string) (map[string]processConfig, error) {
	managerPublic, managerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	serial, err := bootstrapSerial()
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ASB interaction demo CA"},
		NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Hold all reservations together so no two processes get the same port.
	// Child startup still fails closed if another process claims a released port.
	listeners := make([]net.Listener, 0, 4)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for range 4 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("reserve demo port: %w", err)
		}
		listeners = append(listeners, listener)
	}

	roles := []string{roleAgentA, roleRelay, roleAgentB}
	configs := make(map[string]processConfig, len(roles))
	for index, role := range roles {
		tlsPublic, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		serial, err := bootstrapSerial()
		if err != nil {
			return nil, err
		}
		leaf := &x509.Certificate{
			SerialNumber: serial, Subject: pkix.Name{CommonName: role},
			NotBefore: now.Add(-time.Second), NotAfter: now.Add(time.Hour),
			DNSNames: []string{loopbackServerName}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, tlsPublic, caPrivate)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(tlsPrivate)
		if err != nil {
			return nil, err
		}
		nodeID := sha256.Sum256([]byte("asb-interaction:" + role))
		stateDir := filepath.Join(rootDir, role)
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return nil, err
		}
		configs[role] = processConfig{
			Self: trustedIdentity{
				Role:             role,
				Node:             discovery.NodeInfo{ID: hex.EncodeToString(nodeID[:]), Endpoint: listeners[index].Addr().String()},
				Certificate:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
				SigningPublicKey: signingPublic,
			},
			CAPEM: caPEM, TLSKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
			SigningKey: signingPrivate, ManagerKey: managerPublic,
			PeerGrants: make(map[string]map[peer.Action]string), StateDir: stateDir,
		}
	}
	bCertificate, err := certificateFromPEM(configs[roleAgentB].Self.Certificate)
	if err != nil {
		return nil, err
	}
	target := targetConfig{
		AgentID: roleAgentB, Name: "sum.internal", Capability: "sum",
		Endpoint: "https://" + listeners[3].Addr().String(),
		Audience: "https://agent-b.interaction.test/v1/task", ServerPin: publicKeyPin(bCertificate),
	}
	for _, role := range roles {
		config := configs[role]
		config.Target = target
		for _, remoteRole := range roles {
			if role == remoteRole {
				continue
			}
			remote := configs[remoteRole].Self
			config.Peers = append(config.Peers, remote)
			grants := make(map[peer.Action]string)
			for _, action := range []peer.Action{peer.ActionReplicate, peer.ActionFindNode} {
				claims := jwt.MapClaims{
					"sub": config.Self.Node.ID, "aud": peerAudience(remote.Role),
					"cnf":     map[string]string{"kid": roleKeyID(role)},
					"service": "agtp-discovery-peer", "agent": config.Self.Node.ID,
					"capability_ref": "agtp:peer-action:" + string(action), "ontology_id": "agtp:peer-action:v1",
					"scopes": []string{"agtp.peer." + string(action)}, "resources": []string{"agtp-node:" + remote.Node.ID},
				}
				grant, err := signBootstrapGrant(claims, managerPrivate, now)
				if err != nil {
					return nil, err
				}
				grants[action] = grant
			}
			config.PeerGrants[remote.Node.ID] = grants
		}
		if role == roleAgentA {
			values := taskValues()
			config.TaskGrant, err = signBootstrapGrant(jwt.MapClaims{
				"sub": values.Agent, "aud": target.Audience,
				"cnf":     map[string]string{"kid": roleKeyID(role)},
				"service": values.Service, "agent": values.Agent, "task_id": values.TaskID,
				"intent_ref": values.IntentRef, "capability_ref": values.CapabilityRef, "ontology_id": values.OntologyID,
				"scopes": values.Scopes, "resources": values.Resources,
			}, managerPrivate, now)
			if err != nil {
				return nil, err
			}
		}
		configs[role] = config
	}
	return configs, nil
}

func bootstrapSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serial.Add(serial, big.NewInt(1)), nil
}

func signBootstrapGrant(claims jwt.MapClaims, key ed25519.PrivateKey, now time.Time) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	claims["iss"] = managerIssuer
	claims["jti"] = hex.EncodeToString(id)
	claims["iat"] = now.Add(-time.Second).Unix()
	claims["exp"] = now.Add(10 * time.Minute).Unix()
	claims["profile_type"] = clients.TokenTypeIdentityGrant
	claims["profile_version"] = clients.ProfileVersion
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = managerKeyID
	return token.SignedString(key)
}
