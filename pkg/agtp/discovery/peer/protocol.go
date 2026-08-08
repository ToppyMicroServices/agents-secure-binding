// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/thinksyncs/agents-secure-binding/pkg/agtp/discovery"
)

const (
	ProtocolVersion = 1
	NoncePath       = "/v1/peer/nonce"
	ReplicatePath   = "/v1/peer/replicate"
	FindNodePath    = "/v1/peer/find-node"
	HealthPath      = "/healthz"
	MetricsPath     = "/metrics"

	IdentityGrantHeader  = "ASB-Identity-Grant"
	SessionBindingHeader = "ASB-Session-Binding"
	VerifierNonceHeader  = "ASB-Verifier-Nonce"
)

// Action is a separately authorized peer operation.
type Action string

const (
	ActionReplicate Action = "replicate"
	ActionFindNode  Action = "find-node"
)

var (
	ErrInvalidProtocol = errors.New("agtp discovery peer: invalid protocol message")
	ErrUnauthorized    = errors.New("agtp discovery peer: unauthorized peer")
	ErrRateLimited     = errors.New("agtp discovery peer: rate limited")
)

// ReplicateRequest exchanges Presence and ANS digests and deltas.
type ReplicateRequest struct {
	Protocol   int                     `json:"protocol"`
	Sender     discovery.NodeInfo      `json:"sender"`
	Digest     discovery.Digest        `json:"digest"`
	Delta      discovery.Delta         `json:"delta"`
	NameDigest map[string]uint64       `json:"name_digest"`
	Names      []discovery.NameBinding `json:"names"`
}

// ReplicateResponse returns state newer than the requester's digest.
type ReplicateResponse struct {
	Protocol   int                     `json:"protocol"`
	Digest     discovery.Digest        `json:"digest"`
	Delta      discovery.Delta         `json:"delta"`
	NameDigest map[string]uint64       `json:"name_digest"`
	Names      []discovery.NameBinding `json:"names"`
}

// FindNodeRequest performs one authenticated DHT lookup hop.
type FindNodeRequest struct {
	Protocol int                `json:"protocol"`
	Sender   discovery.NodeInfo `json:"sender"`
	Target   string             `json:"target"`
	Count    int                `json:"count"`
}

// FindNodeResponse contains the receiver's nearest trusted peers.
type FindNodeResponse struct {
	Protocol int                  `json:"protocol"`
	Peers    []discovery.NodeInfo `json:"peers"`
}

type nonceResponse struct {
	Nonce string `json:"nonce"`
}

type canonicalAction struct {
	Profile    string `json:"profile"`
	Action     Action `json:"action"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Sender     string `json:"sender"`
	Receiver   string `json:"receiver"`
	BodySHA256 string `json:"body_sha256"`
}

func actionPath(action Action) (string, error) {
	switch action {
	case ActionReplicate:
		return ReplicatePath, nil
	case ActionFindNode:
		return FindNodePath, nil
	default:
		return "", ErrInvalidProtocol
	}
}

func canonicalActionContext(action Action, sender, receiver string, body []byte) ([]byte, error) {
	path, err := actionPath(action)
	if err != nil || sender == "" || receiver == "" || len(body) == 0 {
		return nil, ErrInvalidProtocol
	}
	digest := sha256.Sum256(body)
	return json.Marshal(canonicalAction{
		Profile:    "asb.agtp-discovery-peer/v1",
		Action:     action,
		Method:     "POST",
		Path:       path,
		Sender:     sender,
		Receiver:   receiver,
		BodySHA256: hex.EncodeToString(digest[:]),
	})
}

func capabilityReference(action Action) string {
	return "agtp:peer-action:" + string(action)
}

func actionScope(action Action) string {
	return "agtp.peer." + string(action)
}

func nodeResource(nodeID string) string {
	return "agtp-node:" + nodeID
}
