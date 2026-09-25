// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
)

type discoveryEvidence struct {
	InitialMatches int    `json:"initial_matches"`
	InitialPeers   int    `json:"initial_peers"`
	DHTFound       bool   `json:"dht_found"`
	PeerCount      int    `json:"peer_count"`
	AgentID        string `json:"agent_id"`
	Name           string `json:"name"`
	Endpoint       string `json:"endpoint"`
}

func startDiscovery(ctx context.Context, config processConfig) (_ *peer.Node, result error) {
	if config.StateDir == "" || len(config.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("missing discovery state or signing key")
	}
	tlsConfig, err := configTLS(config)
	if err != nil {
		return nil, err
	}
	replay, err := peer.NewFileReplayCache(filepath.Join(config.StateDir, "peer-replay.json"), nil)
	if err != nil {
		return nil, err
	}
	directory := peer.NewPeerDirectory()
	client := &peer.Client{
		AgentID: config.Self.Node.ID, Issuer: roleIssuer(config.Self.Role), KeyID: roleKeyID(config.Self.Role),
		PrivateKey: ed25519.PrivateKey(config.SigningKey), TLSConfig: tlsConfig,
		Remotes: make(map[string]peer.RemoteAuthorization), Timeout: 5 * time.Second,
	}
	for _, remote := range config.Peers {
		certificate, certificateErr := certificateFromPEM(remote.Certificate)
		if certificateErr != nil {
			return nil, certificateErr
		}
		profile, profileErr := profileFor(config, remote, peerAudience(config.Self.Role), replay)
		if profileErr != nil {
			return nil, profileErr
		}
		if err := directory.Add(certificate, peer.PeerIdentity{Node: remote.Node, Profile: profile}); err != nil {
			return nil, err
		}
		grants := config.PeerGrants[remote.Node.ID]
		if grants[peer.ActionReplicate] == "" || grants[peer.ActionFindNode] == "" {
			return nil, fmt.Errorf("missing discovery grants for %s", remote.Role)
		}
		client.Remotes[remote.Node.ID] = peer.RemoteAuthorization{
			Audience: peerAudience(remote.Role), ServerName: loopbackServerName,
			ServerCertificateSHA256: publicKeyPin(certificate), Grants: grants,
		}
	}
	prefixes, err := config.networkPrefixes()
	if err != nil {
		return nil, err
	}
	node, err := peer.NewNode(peer.Config{
		Info: config.Self.Node, ListenAddress: config.Self.Node.Endpoint,
		NetworkPolicy: &peer.NetworkPolicy{AllowedCIDRs: prefixes},
		TLSConfig:     tlsConfig, Directory: directory, Client: client,
		StatePath: discoveryStatePath(config), AuditPath: filepath.Join(config.StateDir, "peer-audit.jsonl"),
		GossipInterval: time.Hour, RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			result = errors.Join(result, node.Stop(stopCtx))
		}
	}()
	seedRoles := []string{roleRelay}
	if config.Self.Role == roleRelay {
		seedRoles = []string{roleAgentA, roleAgentB}
	}
	for _, role := range seedRoles {
		identity, identityErr := config.identity(role)
		if identityErr != nil {
			return nil, identityErr
		}
		if err := node.AddPeer(identity.Node); err != nil {
			return nil, err
		}
	}
	if config.Self.Role == roleAgentB {
		_, err := node.Register(discovery.NameBinding{
			Name: config.Target.Name, AgentID: config.Target.AgentID, Endpoint: config.Target.Endpoint,
			Capabilities: []string{config.Target.Capability}, Version: 1, ExpiresAt: time.Now().Add(10 * time.Minute),
			Visibility: discovery.Visibility{Mode: discovery.VisibilityExplicitOnly, AllowedAgents: []string{roleAgentA}},
		})
		if err != nil {
			return nil, err
		}
	}
	//nolint:contextcheck // Node owns the gossip context; deferred Stop cancels and joins it.
	if err := node.Start(); err != nil {
		return nil, err
	}
	return node, nil
}

// discoverTaskTarget reads Agent A's trusted local catalog. This is not an
// HTTP DISCOVER authorization exchange. Peer lookup and replication still use
// their separate ASB grants, and a discovered endpoint does not authorize a task.
func discoverTaskTarget(ctx context.Context, node *peer.Node, config processConfig) (discoveryEvidence, error) {
	var evidence discoveryEvidence
	if ctx == nil || node == nil || config.Self.Role != roleAgentA || node.Info() != config.Self.Node {
		return evidence, errors.New("discovery requires the configured Agent A node")
	}
	query := discovery.Query{Capability: config.Target.Capability, Limit: 1}
	requester := discovery.Requester{AgentID: roleAgentA}
	initial, err := node.Discover(ctx, query, requester)
	if err != nil {
		return evidence, err
	}
	evidence.InitialMatches = initial.TotalMatches
	_, _, evidence.InitialPeers = node.Counts()
	if initial.TotalMatches != 0 || initial.Returned != 0 || len(initial.Results) != 0 || evidence.InitialPeers != 1 {
		return evidence, errors.New("agent-a must begin with an empty task catalog and one relay route")
	}
	relay, err := config.identity(roleRelay)
	if err != nil {
		return evidence, err
	}
	state, err := peer.NewStateStore(discoveryStatePath(config))
	if err != nil {
		return evidence, err
	}
	snapshot, found, err := state.Load()
	if err != nil {
		return evidence, err
	}
	if !found || len(snapshot.Peers) != 1 || snapshot.Peers[0] != relay.Node {
		return evidence, errors.New("agent-a's initial persisted route is not the configured relay")
	}
	worker, err := config.identity(roleAgentB)
	if err != nil {
		return evidence, err
	}
	located, err := node.Locate(ctx, worker.Node.ID, peer.DefaultMaxPeers)
	if err != nil {
		return evidence, err
	}
	for _, candidate := range located {
		if candidate == worker.Node {
			evidence.DHTFound = true
		}
	}
	_, _, evidence.PeerCount = node.Counts()
	if !evidence.DHTFound || evidence.PeerCount != 2 {
		return evidence, errors.New("DHT lookup did not learn the configured worker through the relay")
	}
	if err := node.GossipOnce(ctx); err != nil {
		return evidence, err
	}
	response, err := node.Discover(ctx, query, requester)
	if err != nil {
		return evidence, err
	}
	binding, err := selectDiscoveredTarget(response, node.Resolve, config.Target)
	if err != nil {
		return evidence, err
	}
	evidence.AgentID, evidence.Name, evidence.Endpoint = binding.AgentID, binding.Name, binding.Endpoint
	return evidence, nil
}

func selectDiscoveredTarget(response discovery.Response, resolve func(string) (discovery.NameBinding, bool), target targetConfig) (discovery.NameBinding, error) {
	if response.TotalMatches != 1 || response.Returned != 1 || len(response.Results) != 1 || resolve == nil {
		return discovery.NameBinding{}, errors.New("discovery must return exactly one task target")
	}
	match := response.Results[0]
	if match.AgentID != target.AgentID || match.Name != target.Name || len(match.Capabilities) != 1 || match.Capabilities[0] != target.Capability {
		return discovery.NameBinding{}, errors.New("discovered task identity does not match local policy")
	}
	binding, found := resolve(match.Name)
	if !found || binding.AgentID != match.AgentID || binding.Name != match.Name || binding.Endpoint != target.Endpoint || len(binding.Capabilities) != 1 || binding.Capabilities[0] != target.Capability {
		return discovery.NameBinding{}, errors.New("resolved task endpoint does not match local policy")
	}
	return binding, nil
}

func discoveryStatePath(config processConfig) string {
	return filepath.Join(config.StateDir, "peer-state.json")
}
