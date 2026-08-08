// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
	"sort"
	"sync"
)

var ErrInvalidNode = errors.New("agtp discovery: invalid DHT node")

// NodeInfo identifies one local discovery coordinator in the DHT.
type NodeInfo struct {
	ID       string `json:"node_id"`
	Endpoint string `json:"endpoint"`
}

// RoutingTable is a 256-bucket Kademlia-style routing table. It provides XOR
// routing only; transport and authentication remain caller responsibilities.
type RoutingTable struct {
	mu      sync.Mutex
	self    NodeInfo
	k       int
	buckets [256][]NodeInfo
}

// NewRoutingTable creates a routing table for one node.
func NewRoutingTable(self NodeInfo, k int) (*RoutingTable, error) {
	if err := validateNode(self); err != nil {
		return nil, err
	}
	if k < 1 {
		return nil, ErrInvalidNode
	}
	return &RoutingTable{self: self, k: k}, nil
}

// HashKey maps an Agent-ID or ANS name into the DHT key space.
func HashKey(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// Observe adds or refreshes a peer. When a bucket is full, the least recently
// observed entry is returned as evicted.
func (r *RoutingTable) Observe(peer NodeInfo) (*NodeInfo, error) {
	if err := validateNode(peer); err != nil {
		return nil, err
	}
	if peer.ID == r.self.ID {
		return nil, nil
	}
	index, err := bucketIndex(r.self.ID, peer.ID)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket := r.buckets[index]
	for i := range bucket {
		if bucket[i].ID == peer.ID {
			bucket = append(bucket[:i], bucket[i+1:]...)
			bucket = append(bucket, peer)
			r.buckets[index] = bucket
			return nil, nil
		}
	}
	if len(bucket) < r.k {
		r.buckets[index] = append(bucket, peer)
		return nil, nil
	}
	evicted := bucket[0]
	r.buckets[index] = append(bucket[1:], peer)
	return &evicted, nil
}

// Closest returns up to count known peers in XOR-distance order.
func (r *RoutingTable) Closest(target string, count int) ([]NodeInfo, error) {
	if _, err := decodeNodeID(target); err != nil || count < 1 {
		return nil, ErrInvalidNode
	}
	r.mu.Lock()
	peers := make([]NodeInfo, 0)
	for _, bucket := range r.buckets {
		peers = append(peers, bucket...)
	}
	r.mu.Unlock()
	sort.Slice(peers, func(i, j int) bool {
		return compareDistance(peers[i].ID, peers[j].ID, target) < 0
	})
	if len(peers) > count {
		peers = peers[:count]
	}
	return peers, nil
}

// LocateRPC represents an authenticated FIND_NODE exchange.
type LocateRPC func(context.Context, NodeInfo, string) ([]NodeInfo, error)

// IterativeLocate follows the nearest peers until no known peer remains
// unqueried. Alpha limits each lookup round; this implementation keeps
// transport scheduling deterministic for local tests.
func (r *RoutingTable) IterativeLocate(ctx context.Context, target string, count, alpha int, call LocateRPC) ([]NodeInfo, error) {
	if call == nil || count < 1 || alpha < 1 {
		return nil, ErrInvalidNode
	}
	shortlist, err := r.Closest(target, count)
	if err != nil {
		return nil, err
	}
	known := make(map[string]NodeInfo, len(shortlist))
	queried := make(map[string]bool)
	for _, peer := range shortlist {
		known[peer.ID] = peer
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ordered := orderedPeers(known, target)
		round := make([]NodeInfo, 0, alpha)
		for _, peer := range ordered {
			if !queried[peer.ID] {
				round = append(round, peer)
				if len(round) == alpha {
					break
				}
			}
		}
		if len(round) == 0 {
			break
		}
		for _, peer := range round {
			queried[peer.ID] = true
			learned, callErr := call(ctx, peer, target)
			if callErr != nil {
				continue
			}
			for _, candidate := range learned {
				if validateNode(candidate) != nil || candidate.ID == r.self.ID {
					continue
				}
				known[candidate.ID] = candidate
				_, _ = r.Observe(candidate)
			}
		}
	}
	ordered := orderedPeers(known, target)
	if len(ordered) > count {
		ordered = ordered[:count]
	}
	return ordered, nil
}

// HandleLocate answers one FIND_NODE request from the local routing table.
func (r *RoutingTable) HandleLocate(target string, count int) ([]NodeInfo, error) {
	return r.Closest(target, count)
}

func orderedPeers(peers map[string]NodeInfo, target string) []NodeInfo {
	ordered := make([]NodeInfo, 0, len(peers))
	for _, peer := range peers {
		ordered = append(ordered, peer)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return compareDistance(ordered[i].ID, ordered[j].ID, target) < 0
	})
	return ordered
}

func validateNode(node NodeInfo) error {
	if _, err := decodeNodeID(node.ID); err != nil || node.Endpoint == "" {
		return ErrInvalidNode
	}
	return nil
}

func bucketIndex(left, right string) (int, error) {
	a, err := decodeNodeID(left)
	if err != nil {
		return 0, err
	}
	b, err := decodeNodeID(right)
	if err != nil {
		return 0, err
	}
	for i := range a {
		xor := a[i] ^ b[i]
		if xor != 0 {
			return (len(a)-1-i)*8 + (7 - bits.LeadingZeros8(xor)), nil
		}
	}
	return 0, ErrInvalidNode
}

func compareDistance(left, right, target string) int {
	a, _ := decodeNodeID(left)
	b, _ := decodeNodeID(right)
	t, _ := decodeNodeID(target)
	leftDistance := make([]byte, len(a))
	rightDistance := make([]byte, len(b))
	for i := range a {
		leftDistance[i] = a[i] ^ t[i]
		rightDistance[i] = b[i] ^ t[i]
	}
	return bytes.Compare(leftDistance, rightDistance)
}

func decodeNodeID(value string) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, ErrInvalidNode
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil, ErrInvalidNode
	}
	return decoded, nil
}
