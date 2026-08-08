// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"sort"
	"sync"
	"time"
)

const DefaultTombstoneRetention = 24 * time.Hour

// PresenceOptions controls receiver-local expiry behavior.
type PresenceOptions struct {
	TombstoneRetention time.Duration
	MaxRecords         int
	MaxTombstones      int
	Now                func() time.Time
}

// Digest is the compact state exchanged during anti-entropy.
type Digest struct {
	Records    map[string]uint64 `json:"records"`
	Tombstones map[string]uint64 `json:"tombstones"`
}

// Delta contains states that are newer than a peer's digest.
type Delta struct {
	Records    []Record    `json:"records"`
	Tombstones []Tombstone `json:"tombstones"`
}

// PresenceStore stores live records and retained withdrawals. Mutations are
// expected to occur only after the caller has been authenticated by ASB or an
// equivalent local coordinator policy.
type PresenceStore struct {
	mu                 sync.Mutex
	records            map[string]Record
	tombstones         map[string]Tombstone
	tombstoneRetention time.Duration
	maxRecords         int
	maxTombstones      int
	now                func() time.Time
}

// NewPresenceStore creates a store with a 24-hour receiver-local tombstone
// retention period.
func NewPresenceStore() *PresenceStore {
	return NewPresenceStoreWithOptions(PresenceOptions{TombstoneRetention: DefaultTombstoneRetention})
}

// NewPresenceStoreWithOptions creates a store with an injectable clock. A zero
// retention disables time-based tombstone GC; callers then need durable state
// if that behavior must survive a restart.
func NewPresenceStoreWithOptions(options PresenceOptions) *PresenceStore {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &PresenceStore{
		records:            make(map[string]Record),
		tombstones:         make(map[string]Tombstone),
		tombstoneRetention: options.TombstoneRetention,
		maxRecords:         options.MaxRecords,
		maxTombstones:      options.MaxTombstones,
		now:                now,
	}
}

// Announce inserts or updates one live Presence record. A newer tombstone wins
// over an older record, including at the same version.
func (s *PresenceStore) Announce(record Record) (bool, error) {
	if err := validateRecord(record); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.sweepLocked(now)
	if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now) {
		return false, nil
	}
	if tombstone, ok := s.tombstones[record.AgentID]; ok {
		if tombstone.Version >= record.Version {
			// A newly learned stale record can reveal that the deletion marker
			// must outlive a longer lease than was previously known.
			extendTombstoneForRecord(&tombstone, record)
			s.tombstones[record.AgentID] = tombstone
			return false, nil
		}
		if _, exists := s.records[record.AgentID]; !exists && s.maxRecords > 0 && len(s.records) >= s.maxRecords {
			return false, ErrLimitExceeded
		}
		delete(s.tombstones, record.AgentID)
	} else if _, exists := s.records[record.AgentID]; !exists && s.maxRecords > 0 && len(s.records) >= s.maxRecords {
		return false, ErrLimitExceeded
	}
	if current, ok := s.records[record.AgentID]; ok && current.Version >= record.Version {
		return false, nil
	}
	s.records[record.AgentID] = cloneRecord(record)
	return true, nil
}

// Withdraw removes a live record and retains a local tombstone. Retention is a
// receiver policy rather than a value supplied by the withdrawing peer.
func (s *PresenceStore) Withdraw(agentID string, version uint64) (bool, error) {
	if err := validateAgentID(agentID); err != nil {
		return false, err
	}
	if version == 0 {
		return false, ErrInvalidVersion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.sweepLocked(now)
	if current, ok := s.records[agentID]; ok && current.Version > version {
		return false, nil
	}
	if current, ok := s.tombstones[agentID]; ok && current.Version >= version {
		return false, nil
	}
	if _, exists := s.tombstones[agentID]; !exists && s.maxTombstones > 0 && len(s.tombstones) >= s.maxTombstones {
		return false, ErrLimitExceeded
	}
	tombstone := Tombstone{AgentID: agentID, Version: version}
	if current, ok := s.records[agentID]; ok {
		if current.ExpiresAt.IsZero() {
			tombstone.Indefinite = true
		} else {
			tombstone.SuppressUntil = current.ExpiresAt
		}
	}
	s.installTombstoneLocked(tombstone, now)
	delete(s.records, agentID)
	return true, nil
}

// Merge applies tombstones before records so a delete wins equal versions.
func (s *PresenceStore) Merge(delta Delta) error {
	for _, tombstone := range delta.Tombstones {
		if _, err := s.mergeTombstone(tombstone); err != nil {
			return err
		}
	}
	for _, record := range delta.Records {
		if _, err := s.Announce(record); err != nil {
			return err
		}
	}
	return nil
}

func (s *PresenceStore) mergeTombstone(tombstone Tombstone) (bool, error) {
	if err := validateAgentID(tombstone.AgentID); err != nil {
		return false, err
	}
	if tombstone.Version == 0 {
		return false, ErrInvalidVersion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.sweepLocked(now)
	if current, ok := s.records[tombstone.AgentID]; ok {
		if current.Version > tombstone.Version {
			return false, nil
		}
		extendTombstoneForRecord(&tombstone, current)
	}
	if current, ok := s.tombstones[tombstone.AgentID]; ok {
		if current.Version > tombstone.Version {
			return false, nil
		}
		if current.Version == tombstone.Version {
			mergeSuppressionFloor(&tombstone, current)
		}
	}
	if _, exists := s.tombstones[tombstone.AgentID]; !exists && s.maxTombstones > 0 && len(s.tombstones) >= s.maxTombstones {
		return false, ErrLimitExceeded
	}
	s.installTombstoneLocked(tombstone, now)
	delete(s.records, tombstone.AgentID)
	return true, nil
}

// Probe returns one live Presence record.
func (s *PresenceStore) Probe(agentID string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
	record, ok := s.records[agentID]
	return cloneRecord(record), ok
}

// Discover executes an exact capability query against live, visible records.
func (s *PresenceStore) Discover(_ context.Context, query Query, requester Requester) (Response, error) {
	query, err := normalizedQuery(query)
	if err != nil {
		return Response{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
	matches := make([]Match, 0)
	for _, record := range s.records {
		if !contains(record.Capabilities, query.Capability) || !visibleTo(record.Visibility, requester) {
			continue
		}
		matches = append(matches, Match{
			AgentID:      record.AgentID,
			Name:         record.Name,
			Capabilities: copyStrings(record.Capabilities),
		})
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].AgentID < matches[j].AgentID })
	total := len(matches)
	if len(matches) > query.Limit {
		matches = matches[:query.Limit]
	}
	return Response{
		Method:       "DISCOVER",
		Target:       PopulationTarget,
		Query:        query,
		TotalMatches: total,
		Returned:     len(matches),
		Results:      matches,
	}, nil
}

// Digest reports the highest local record and tombstone revisions.
func (s *PresenceStore) Digest() Digest {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
	digest := Digest{Records: make(map[string]uint64), Tombstones: make(map[string]uint64)}
	for agentID, record := range s.records {
		digest.Records[agentID] = record.Version
	}
	for agentID, tombstone := range s.tombstones {
		digest.Tombstones[agentID] = tombstone.Version
	}
	return digest
}

// Snapshot returns a defensive copy of every live record and retained
// tombstone for persistence or a trusted local backup.
func (s *PresenceStore) Snapshot() Delta {
	return s.Delta(Digest{})
}

// Counts reports bounded state after applying TTL and tombstone GC.
func (s *PresenceStore) Counts() (records, tombstones int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
	return len(s.records), len(s.tombstones)
}

// Delta returns states that are newer than the supplied peer digest.
func (s *PresenceStore) Delta(peer Digest) Delta {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now().UTC())
	delta := Delta{}
	for agentID, tombstone := range s.tombstones {
		if peer.Tombstones[agentID] < tombstone.Version {
			delta.Tombstones = append(delta.Tombstones, publicTombstone(tombstone))
		}
	}
	for agentID, record := range s.records {
		if peer.Records[agentID] < record.Version && peer.Tombstones[agentID] < record.Version {
			delta.Records = append(delta.Records, cloneRecord(record))
		}
	}
	sort.Slice(delta.Tombstones, func(i, j int) bool { return delta.Tombstones[i].AgentID < delta.Tombstones[j].AgentID })
	sort.Slice(delta.Records, func(i, j int) bool { return delta.Records[i].AgentID < delta.Records[j].AgentID })
	return delta
}

func (s *PresenceStore) sweepLocked(now time.Time) {
	for agentID, record := range s.records {
		if !record.ExpiresAt.IsZero() && !record.ExpiresAt.After(now) {
			delete(s.records, agentID)
		}
	}
	for agentID, tombstone := range s.tombstones {
		if !tombstone.expiresAt.IsZero() && !tombstone.expiresAt.After(now) {
			delete(s.tombstones, agentID)
		}
	}
}

func validateRecord(record Record) error {
	if err := validateAgentID(record.AgentID); err != nil {
		return err
	}
	if record.Name != "" {
		if err := validateName(record.Name); err != nil {
			return err
		}
	}
	if record.Version == 0 || len(record.Capabilities) == 0 {
		return ErrInvalidRecord
	}
	seen := make(map[string]struct{}, len(record.Capabilities))
	for _, capability := range record.Capabilities {
		if err := validateCapability(capability); err != nil {
			return err
		}
		if _, ok := seen[capability]; ok {
			return ErrInvalidRecord
		}
		seen[capability] = struct{}{}
	}
	switch record.Visibility.Mode {
	case "", VisibilityPublic:
		record.Visibility.Mode = VisibilityPublic
	case VisibilityOwnerDomain:
		if record.Visibility.OwnerDomain == "" {
			return ErrInvalidRecord
		}
	case VisibilityExplicitOnly:
		if len(record.Visibility.AllowedAgents) == 0 {
			return ErrInvalidRecord
		}
		for _, agentID := range record.Visibility.AllowedAgents {
			if err := validateAgentID(agentID); err != nil {
				return err
			}
		}
	case VisibilityInvisible:
	default:
		return ErrInvalidRecord
	}
	return nil
}

func visibleTo(visibility Visibility, requester Requester) bool {
	switch visibility.Mode {
	case "", VisibilityPublic:
		return true
	case VisibilityOwnerDomain:
		return requester.OwnerDomain != "" && requester.OwnerDomain == visibility.OwnerDomain
	case VisibilityExplicitOnly:
		return contains(visibility.AllowedAgents, requester.AgentID)
	case VisibilityInvisible:
		return false
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneRecord(record Record) Record {
	record.Capabilities = copyStrings(record.Capabilities)
	record.Visibility.AllowedAgents = copyStrings(record.Visibility.AllowedAgents)
	return record
}

func publicTombstone(tombstone Tombstone) Tombstone {
	return Tombstone{
		AgentID:       tombstone.AgentID,
		Version:       tombstone.Version,
		SuppressUntil: tombstone.SuppressUntil,
		Indefinite:    tombstone.Indefinite,
	}
}

func (s *PresenceStore) installTombstoneLocked(tombstone Tombstone, now time.Time) {
	tombstone.received = now
	if tombstone.Indefinite {
		tombstone.expiresAt = time.Time{}
	} else {
		tombstone.expiresAt = tombstone.SuppressUntil
		if s.tombstoneRetention == 0 {
			tombstone.expiresAt = time.Time{}
		} else if localDeadline := now.Add(s.tombstoneRetention); tombstone.expiresAt.Before(localDeadline) {
			tombstone.expiresAt = localDeadline
		}
	}
	s.tombstones[tombstone.AgentID] = tombstone
}

func extendTombstoneForRecord(tombstone *Tombstone, record Record) {
	if record.ExpiresAt.IsZero() {
		tombstone.Indefinite = true
		tombstone.SuppressUntil = time.Time{}
		tombstone.expiresAt = time.Time{}
		return
	}
	if !tombstone.Indefinite && tombstone.SuppressUntil.Before(record.ExpiresAt) {
		tombstone.SuppressUntil = record.ExpiresAt
		if tombstone.expiresAt.Before(record.ExpiresAt) {
			tombstone.expiresAt = record.ExpiresAt
		}
	}
}

func mergeSuppressionFloor(target *Tombstone, current Tombstone) {
	if current.Indefinite {
		target.Indefinite = true
		target.SuppressUntil = time.Time{}
		return
	}
	if !target.Indefinite && target.SuppressUntil.Before(current.SuppressUntil) {
		target.SuppressUntil = current.SuppressUntil
	}
}
