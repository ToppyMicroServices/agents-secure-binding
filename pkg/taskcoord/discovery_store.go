// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// AgentDirectory indexes only records whose Participant binding resolves to
// an active AGENT. Human matching is a separate interface.
type AgentDirectory interface {
	RegisterAgentDiscoveryRecord(context.Context, AgentDiscoveryRecord) error
	SearchAgents(context.Context, AgentSearchQuery) ([]AgentDiscoveryRecord, error)
}

var _ AgentDirectory = (*MemoryAgentDirectory)(nil)

// MemoryAgentDirectory is a concurrency-safe application stub, not an Agent
// discovery wire protocol or production registry.
type MemoryAgentDirectory struct {
	mu           sync.RWMutex
	participants ParticipantResolver
	now          func() time.Time
	records      map[string]AgentDiscoveryRecord
}

// NewMemoryAgentDirectory returns an in-process Agent-only index.
func NewMemoryAgentDirectory(participants ParticipantResolver) *MemoryAgentDirectory {
	return newMemoryAgentDirectory(participants, time.Now)
}

func newMemoryAgentDirectory(participants ParticipantResolver, now func() time.Time) *MemoryAgentDirectory {
	return &MemoryAgentDirectory{
		participants: participants,
		now:          now,
		records:      make(map[string]AgentDiscoveryRecord),
	}
}

// RegisterAgentDiscoveryRecord re-resolves the Participant binding so a
// forged kind field cannot place a Human in the Agent index.
func (d *MemoryAgentDirectory) RegisterAgentDiscoveryRecord(ctx context.Context, record AgentDiscoveryRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	participant, err := d.resolveParticipant(ctx, record.ParticipantID)
	if err != nil {
		return err
	}
	if participant.Kind == ParticipantHuman {
		return ErrHumanNotDiscoverable
	}
	if participant.Kind != ParticipantAgent {
		return invalidDiscovery("discovery binding does not resolve to an AGENT")
	}
	if participant.Status != ParticipantActive {
		return ErrParticipantUnavailable
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if existing, ok := d.records[record.RecordID]; ok {
		if sameAgentDiscoveryRecord(existing, record) {
			return nil
		}
		return fmt.Errorf("%w: Agent discovery record %s", ErrEventConflict, record.RecordID)
	}
	d.records[record.RecordID] = record
	return nil
}

// SearchAgents returns only active, unexpired AGENT records for one exact
// capability. The Participant binding is rechecked at read time.
func (d *MemoryAgentDirectory) SearchAgents(ctx context.Context, query AgentSearchQuery) ([]AgentDiscoveryRecord, error) {
	if err := query.Validate(); err != nil {
		return nil, err
	}
	if d == nil || d.participants == nil || d.now == nil {
		return nil, invalidDiscovery("Participant resolver and clock are required")
	}
	now := d.now()
	d.mu.RLock()
	records := make([]AgentDiscoveryRecord, 0, len(d.records))
	for _, record := range d.records {
		if record.Capability == query.Capability && !now.Before(record.PublishedAt) && now.Before(record.ExpiresAt) {
			records = append(records, record)
		}
	}
	d.mu.RUnlock()

	results := make([]AgentDiscoveryRecord, 0, len(records))
	for _, record := range records {
		participant, err := d.resolveParticipant(ctx, record.ParticipantID)
		if err != nil || participant.Kind != ParticipantAgent || participant.Status != ParticipantActive {
			continue
		}
		results = append(results, record)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RecordID < results[j].RecordID })
	if len(results) > int(query.Limit) {
		results = results[:query.Limit]
	}
	return results, nil
}

func (d *MemoryAgentDirectory) resolveParticipant(ctx context.Context, participantID string) (Participant, error) {
	if d == nil || d.participants == nil {
		return Participant{}, invalidDiscovery("Participant resolver is required")
	}
	return d.participants.LoadParticipant(ctx, participantID)
}

func sameAgentDiscoveryRecord(a, b AgentDiscoveryRecord) bool {
	return a.Schema == b.Schema &&
		a.RecordID == b.RecordID &&
		a.ParticipantID == b.ParticipantID &&
		a.Kind == b.Kind &&
		a.Capability == b.Capability &&
		a.InvocationRef == b.InvocationRef &&
		a.PublishedAt.Equal(b.PublishedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}
