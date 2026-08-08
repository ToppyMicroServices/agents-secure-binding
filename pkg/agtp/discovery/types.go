// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package discovery implements the small AGTP discovery slice used by ASB:
// Presence, capability DISCOVER, Kademlia-style peer lookup, and ANS bindings.
// It is not a complete AGTP wire-protocol implementation.
package discovery

import (
	"errors"
	"strings"
	"time"
)

const (
	PopulationTarget   = "population"
	DefaultResultLimit = 25
	MaxResultLimit     = 100
)

var (
	ErrInvalidAgentID    = errors.New("agtp discovery: invalid Agent-ID")
	ErrInvalidCapability = errors.New("agtp discovery: invalid capability")
	ErrInvalidName       = errors.New("agtp discovery: invalid ANS name")
	ErrInvalidRecord     = errors.New("agtp discovery: invalid presence record")
	ErrInvalidVersion    = errors.New("agtp discovery: invalid version")
	ErrNameConflict      = errors.New("agtp discovery: ANS name is already bound")
)

// VisibilityMode controls which authenticated requester can see a record.
type VisibilityMode string

const (
	VisibilityPublic       VisibilityMode = "public"
	VisibilityOwnerDomain  VisibilityMode = "owner-domain"
	VisibilityExplicitOnly VisibilityMode = "explicit-only"
	VisibilityInvisible    VisibilityMode = "invisible"
)

// Visibility is evaluated locally after ASB has authenticated the requester.
type Visibility struct {
	Mode          VisibilityMode `json:"mode"`
	OwnerDomain   string         `json:"owner_domain,omitempty"`
	AllowedAgents []string       `json:"allowed_agents,omitempty"`
}

// Requester is the authenticated identity used for visibility evaluation.
type Requester struct {
	AgentID     string `json:"agent_id"`
	OwnerDomain string `json:"owner_domain,omitempty"`
}

// Record is a live Presence record. Version is a per-Agent-ID monotonic
// revision. ExpiresAt is a finite lease when non-zero.
type Record struct {
	AgentID      string     `json:"agent_id"`
	Name         string     `json:"name,omitempty"`
	Capabilities []string   `json:"capabilities"`
	Visibility   Visibility `json:"visibility"`
	Version      uint64     `json:"version"`
	ExpiresAt    time.Time  `json:"expires_at,omitempty"`
}

// Tombstone prevents an older Presence record from reappearing after a
// partition. Its local expiry is receiver policy and is not serialized.
type Tombstone struct {
	AgentID       string    `json:"agent_id"`
	Version       uint64    `json:"version"`
	SuppressUntil time.Time `json:"suppress_until,omitempty"`
	Indefinite    bool      `json:"indefinite,omitempty"`
	received      time.Time
	expiresAt     time.Time
}

// Query is an exact capability DISCOVER request.
type Query struct {
	Capability string `json:"capability"`
	Limit      int    `json:"limit"`
}

// Match is a live, visible Presence match. Network endpoints are resolved
// separately through ANS and are intentionally absent here.
type Match struct {
	AgentID      string   `json:"agent_id"`
	Name         string   `json:"name,omitempty"`
	Capabilities []string `json:"capabilities"`
}

// Response mirrors the useful subset of AGTP DISCOVER /population output.
type Response struct {
	Method       string  `json:"method"`
	Target       string  `json:"target"`
	Query        Query   `json:"query"`
	TotalMatches int     `json:"total_matches"`
	Returned     int     `json:"returned"`
	Results      []Match `json:"results"`
}

func validateAgentID(value string) error {
	if !validCanonicalToken(value, 256, ":") {
		return ErrInvalidAgentID
	}
	return nil
}

func validateCapability(value string) error {
	if !validCanonicalToken(value, 64, "") {
		return ErrInvalidCapability
	}
	return nil
}

func validateName(value string) error {
	if !validCanonicalToken(value, 253, "") {
		return ErrInvalidName
	}
	return nil
}

func validCanonicalToken(value string, maximum int, extra string) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || strings.ContainsRune(extra, r) {
			continue
		}
		return false
	}
	return true
}

func normalizedQuery(query Query) (Query, error) {
	if err := validateCapability(query.Capability); err != nil {
		return Query{}, err
	}
	if query.Limit == 0 {
		query.Limit = DefaultResultLimit
	}
	if query.Limit < 1 || query.Limit > MaxResultLimit {
		return Query{}, ErrInvalidRecord
	}
	return query, nil
}

func copyStrings(values []string) []string {
	return append([]string(nil), values...)
}
