// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"sync"
	"time"
)

// NameBinding maps an ANS name to an Agent-ID and coordinator endpoint.
type NameBinding struct {
	Name         string     `json:"name"`
	AgentID      string     `json:"agent_id"`
	Endpoint     string     `json:"endpoint"`
	Capabilities []string   `json:"capabilities"`
	Version      uint64     `json:"version"`
	RegisteredAt time.Time  `json:"registered_at"`
	RefreshedAt  time.Time  `json:"refreshed_at"`
	ExpiresAt    time.Time  `json:"expires_at,omitempty"`
	Visibility   Visibility `json:"visibility"`
}

// NameService is an in-memory ANS registry coupled to Presence. Register and
// deregister update both views atomically under its local lock.
type NameService struct {
	mu       sync.Mutex
	presence *PresenceStore
	byName   map[string]NameBinding
	byAgent  map[string]string
	now      func() time.Time
}

// NewNameService creates an ANS registry backed by the supplied Presence
// store.
func NewNameService(presence *PresenceStore, now func() time.Time) *NameService {
	if presence == nil {
		presence = NewPresenceStore()
	}
	if now == nil {
		now = time.Now
	}
	return &NameService{
		presence: presence,
		byName:   make(map[string]NameBinding),
		byAgent:  make(map[string]string),
		now:      now,
	}
}

// Register binds one canonical name and publishes the corresponding Presence
// record. A name cannot silently transfer to a different Agent-ID.
func (s *NameService) Register(binding NameBinding) (bool, error) {
	if err := validateBinding(binding); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.byName[binding.Name]; ok {
		if current.AgentID != binding.AgentID {
			return false, ErrNameConflict
		}
		if current.Version >= binding.Version {
			return false, nil
		}
		binding.RegisteredAt = current.RegisteredAt
	}
	now := s.now().UTC()
	if binding.RegisteredAt.IsZero() {
		binding.RegisteredAt = now
	}
	binding.RefreshedAt = now
	changed, err := s.presence.Announce(Record{
		AgentID:      binding.AgentID,
		Name:         binding.Name,
		Capabilities: copyStrings(binding.Capabilities),
		Visibility:   binding.Visibility,
		Version:      binding.Version,
		ExpiresAt:    binding.ExpiresAt,
	})
	if err != nil || !changed {
		return changed, err
	}
	if previousName, ok := s.byAgent[binding.AgentID]; ok && previousName != binding.Name {
		delete(s.byName, previousName)
	}
	s.byName[binding.Name] = cloneBinding(binding)
	s.byAgent[binding.AgentID] = binding.Name
	return true, nil
}

// Resolve returns an active ANS binding by canonical name.
func (s *NameService) Resolve(name string) (NameBinding, bool) {
	if validateName(name) != nil {
		return NameBinding{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.byName[name]
	if !ok || !s.bindingIsLive(binding) {
		return NameBinding{}, false
	}
	return cloneBinding(binding), true
}

// ResolveAgent returns an active ANS binding by Agent-ID.
func (s *NameService) ResolveAgent(agentID string) (NameBinding, bool) {
	if validateAgentID(agentID) != nil {
		return NameBinding{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name, ok := s.byAgent[agentID]
	if !ok {
		return NameBinding{}, false
	}
	binding, ok := s.byName[name]
	if !ok || !s.bindingIsLive(binding) {
		return NameBinding{}, false
	}
	return cloneBinding(binding), true
}

// Deregister removes an ANS binding and creates the matching Presence
// tombstone.
func (s *NameService) Deregister(name string, version uint64) (bool, error) {
	if err := validateName(name); err != nil {
		return false, err
	}
	if version == 0 {
		return false, ErrInvalidVersion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, ok := s.byName[name]
	if !ok || binding.Version > version {
		return false, nil
	}
	changed, err := s.presence.Withdraw(binding.AgentID, version)
	if err != nil || !changed {
		return changed, err
	}
	delete(s.byName, name)
	delete(s.byAgent, binding.AgentID)
	return true, nil
}

func (s *NameService) bindingIsLive(binding NameBinding) bool {
	if !binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(s.now().UTC()) {
		return false
	}
	_, ok := s.presence.Probe(binding.AgentID)
	return ok
}

func validateBinding(binding NameBinding) error {
	if err := validateName(binding.Name); err != nil {
		return err
	}
	if err := validateAgentID(binding.AgentID); err != nil {
		return err
	}
	if binding.Endpoint == "" || binding.Version == 0 || len(binding.Capabilities) == 0 {
		return ErrInvalidRecord
	}
	for _, capability := range binding.Capabilities {
		if err := validateCapability(capability); err != nil {
			return err
		}
	}
	return validateRecord(Record{
		AgentID:      binding.AgentID,
		Name:         binding.Name,
		Capabilities: binding.Capabilities,
		Visibility:   binding.Visibility,
		Version:      binding.Version,
		ExpiresAt:    binding.ExpiresAt,
	})
}

func cloneBinding(binding NameBinding) NameBinding {
	binding.Capabilities = copyStrings(binding.Capabilities)
	binding.Visibility.AllowedAgents = copyStrings(binding.Visibility.AllowedAgents)
	return binding
}
