// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"fmt"
	"strings"
	"time"
)

const (
	// AgentDiscoveryRecordSchemaV1 identifies an application-layer Agent-only
	// discovery record. It does not turn this package into a discovery protocol.
	AgentDiscoveryRecordSchemaV1        = "asb.agent-discovery-record/v1"
	MaxAgentSearchResults        uint32 = 20
)

// AgentDiscoveryDefinition contains the public fields for one Agent search
// candidate. Human Participants must use the separate opt-in matching layer.
type AgentDiscoveryDefinition struct {
	RecordID      string
	Capability    string
	InvocationRef string
	PublishedAt   time.Time
	ExpiresAt     time.Time
}

// AgentDiscoveryRecord is safe to place in an Agent-only search index after it
// has been constructed with NewAgentDiscoveryRecord.
type AgentDiscoveryRecord struct {
	Schema        string          `json:"schema"`
	RecordID      string          `json:"record_id"`
	ParticipantID string          `json:"participant_id"`
	Kind          ParticipantKind `json:"kind"`
	Capability    string          `json:"capability"`
	InvocationRef string          `json:"invocation_ref"`
	PublishedAt   time.Time       `json:"published_at"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

// NewAgentDiscoveryRecord refuses to coerce a Human or automated service into
// an Agent search result.
func NewAgentDiscoveryRecord(participant Participant, def AgentDiscoveryDefinition) (AgentDiscoveryRecord, error) {
	if err := participant.Validate(); err != nil {
		return AgentDiscoveryRecord{}, err
	}
	if participant.Kind == ParticipantHuman {
		return AgentDiscoveryRecord{}, ErrHumanNotDiscoverable
	}
	if participant.Kind != ParticipantAgent {
		return AgentDiscoveryRecord{}, fmt.Errorf("%w: only AGENT Participants may be indexed", ErrInvalidDiscovery)
	}
	if participant.Status != ParticipantActive {
		return AgentDiscoveryRecord{}, ErrParticipantUnavailable
	}
	record := AgentDiscoveryRecord{
		Schema:        AgentDiscoveryRecordSchemaV1,
		RecordID:      def.RecordID,
		ParticipantID: participant.ParticipantID,
		Kind:          participant.Kind,
		Capability:    def.Capability,
		InvocationRef: def.InvocationRef,
		PublishedAt:   def.PublishedAt,
		ExpiresAt:     def.ExpiresAt,
	}
	if err := record.Validate(); err != nil {
		return AgentDiscoveryRecord{}, err
	}
	return record, nil
}

// Validate checks the public Agent discovery record shape. A registry must
// additionally resolve ParticipantID and confirm that it still names an Agent.
func (r AgentDiscoveryRecord) Validate() error {
	if r.Schema != AgentDiscoveryRecordSchemaV1 {
		return invalidDiscovery("unsupported schema")
	}
	if err := validateID("record_id", r.RecordID); err != nil {
		return invalidDiscoveryError(err)
	}
	if err := validateID("participant_id", r.ParticipantID); err != nil {
		return invalidDiscoveryError(err)
	}
	if r.Kind == ParticipantHuman {
		return ErrHumanNotDiscoverable
	}
	if r.Kind != ParticipantAgent {
		return invalidDiscovery("kind must be AGENT")
	}
	if err := validateID("capability", r.Capability); err != nil {
		return invalidDiscoveryError(err)
	}
	if err := validateHTTPSReference("invocation_ref", r.InvocationRef); err != nil {
		return invalidDiscoveryError(err)
	}
	if r.PublishedAt.IsZero() || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(r.PublishedAt) {
		return invalidDiscovery("invalid publication window")
	}
	return nil
}

// AgentSearchQuery is exact and bounded; wildcard enumeration is not part of
// this application-layer stub.
type AgentSearchQuery struct {
	Capability string
	Limit      uint32
}

// Validate checks an exact, bounded Agent search query.
func (q AgentSearchQuery) Validate() error {
	if err := validateID("capability", q.Capability); err != nil {
		return invalidDiscoveryError(err)
	}
	if strings.ContainsAny(q.Capability, "*?") {
		return invalidDiscovery("capability must not contain wildcard characters")
	}
	if q.Limit == 0 || q.Limit > MaxAgentSearchResults {
		return invalidDiscovery("query limit is outside the allowed range")
	}
	return nil
}

func invalidDiscovery(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDiscovery, message)
}

func invalidDiscoveryError(err error) error {
	return fmt.Errorf("%w: %v", ErrInvalidDiscovery, err)
}
