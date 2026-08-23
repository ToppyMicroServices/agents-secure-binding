// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type memoryDecision struct {
	binding             DecisionBinding
	audience            string
	approvals           map[string]Approval
	principals          map[string]string
	credentials         map[string]string
	selectedApprovalIDs []string
	revocation          *DecisionRevocation
	consumption         *VerifiedQuorum
}

// MemoryStore is a concurrency-safe development implementation. It exercises
// the Store atomicity contract in one process but does not survive restart and
// must not be used as production quorum durability.
type MemoryStore struct {
	mu               sync.RWMutex
	now              func() time.Time
	policies         map[string]VerifiedPolicy
	decisions        map[string]*memoryDecision
	approvalsByID    map[string]Approval
	consumptionsByID map[string]VerifiedQuorum
	revocationsByID  map[string]DecisionRevocation
}

func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithClock(time.Now)
}

func NewMemoryStoreWithClock(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		now:              now,
		policies:         make(map[string]VerifiedPolicy),
		decisions:        make(map[string]*memoryDecision),
		approvalsByID:    make(map[string]Approval),
		consumptionsByID: make(map[string]VerifiedQuorum),
		revocationsByID:  make(map[string]DecisionRevocation),
	}
}

func (s *MemoryStore) AppendApproval(ctx context.Context, policy VerifiedPolicy, approval Approval) (Approval, error) {
	if ctx == nil {
		return Approval{}, fmt.Errorf("%w: missing context", ErrInvalidApproval)
	}
	if s == nil {
		return Approval{}, ErrMissingStore
	}
	if err := approval.Validate(); err != nil {
		return Approval{}, err
	}
	if err := policy.Validate(); err != nil {
		return Approval{}, err
	}
	if approval.PolicyDigest != policy.PolicyDigest || approval.Audience != policy.Audience {
		return Approval{}, ErrPolicyMismatch
	}
	if !policy.Allows(approval.AuthorityID) {
		return Approval{}, ErrAuthorityNotAllowed
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPolicyLocked(policy); err != nil {
		return Approval{}, err
	}
	if existing, ok := s.approvalsByID[approval.ApprovalID]; ok {
		if sameApprovalProof(existing, approval) {
			return existing, nil
		}
		return Approval{}, fmt.Errorf("%w: %s", ErrApprovalConflict, approval.ApprovalID)
	}
	now := s.currentTime()
	if err := policy.ValidateAt(now); err != nil {
		return Approval{}, err
	}
	if now.Before(approval.ApprovedAt) {
		return Approval{}, ErrNotYetValid
	}
	if !now.Before(approval.ExpiresAt) {
		return Approval{}, ErrExpired
	}
	record, ok := s.decisions[approval.DecisionID]
	if !ok {
		record = &memoryDecision{
			binding: approval.Binding(), audience: approval.Audience,
			approvals: make(map[string]Approval), principals: make(map[string]string),
			credentials: make(map[string]string),
		}
		s.decisions[approval.DecisionID] = record
	}
	if record.revocation != nil {
		return Approval{}, ErrDecisionRevoked
	}
	if record.consumption != nil {
		return Approval{}, ErrDecisionConsumed
	}
	if record.binding != approval.Binding() || record.audience != approval.Audience {
		return Approval{}, ErrDecisionConflict
	}
	if _, exists := record.approvals[approval.AuthorityID]; exists {
		return Approval{}, fmt.Errorf("%w: %s", ErrAuthorityAlreadyApproved, approval.AuthorityID)
	}
	if authorityID, exists := record.principals[approval.PrincipalTag]; exists && authorityID != approval.AuthorityID {
		return Approval{}, fmt.Errorf("%w: %s", ErrPrincipalAlreadyApproved, authorityID)
	}
	if authorityID, exists := record.credentials[approval.CredentialTag]; exists && authorityID != approval.AuthorityID {
		return Approval{}, fmt.Errorf("%w: %s", ErrCredentialAlreadyApproved, authorityID)
	}
	s.storePolicyLocked(policy)
	record.approvals[approval.AuthorityID] = approval
	record.principals[approval.PrincipalTag] = approval.AuthorityID
	record.credentials[approval.CredentialTag] = approval.AuthorityID
	s.approvalsByID[approval.ApprovalID] = approval
	return approval, nil
}

func (s *MemoryStore) ConsumeQuorum(
	ctx context.Context,
	policy VerifiedPolicy,
	request ConsumeRequest,
) (VerifiedQuorum, error) {
	if ctx == nil {
		return VerifiedQuorum{}, fmt.Errorf("%w: missing context", ErrInvalidRequest)
	}
	if s == nil {
		return VerifiedQuorum{}, ErrMissingStore
	}
	if err := request.Validate(); err != nil {
		return VerifiedQuorum{}, err
	}
	if err := policy.Validate(); err != nil {
		return VerifiedQuorum{}, err
	}
	if request.Binding.PolicyDigest != policy.PolicyDigest {
		return VerifiedQuorum{}, ErrPolicyMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkPolicyLocked(policy); err != nil {
		return VerifiedQuorum{}, err
	}
	now := s.currentTime()
	if existing, ok := s.consumptionsByID[request.ConsumptionID]; ok {
		if existing.DecisionID != request.Binding.DecisionID ||
			existing.PolicyDigest != request.Binding.PolicyDigest ||
			existing.OperationDigest != request.Binding.OperationDigest ||
			existing.Audience != policy.Audience {
			return VerifiedQuorum{}, ErrConsumptionConflict
		}
		if err := existing.ValidateAt(now); err != nil {
			return VerifiedQuorum{}, err
		}
		return existing, nil
	}
	record, ok := s.decisions[request.Binding.DecisionID]
	if !ok {
		return VerifiedQuorum{}, ErrNotFound
	}
	if record.revocation != nil {
		return VerifiedQuorum{}, ErrDecisionRevoked
	}
	if record.consumption != nil {
		return VerifiedQuorum{}, ErrDecisionConsumed
	}
	if err := policy.ValidateAt(now); err != nil {
		return VerifiedQuorum{}, err
	}
	if record.binding != request.Binding || record.audience != policy.Audience {
		return VerifiedQuorum{}, ErrDecisionConflict
	}

	candidates := make([]Approval, 0, len(record.approvals))
	for authorityID, approval := range record.approvals {
		if err := approval.Validate(); err != nil {
			return VerifiedQuorum{}, err
		}
		if approval.Binding() != request.Binding || approval.Audience != policy.Audience {
			return VerifiedQuorum{}, ErrDecisionConflict
		}
		if approval.AuthorityID != authorityID || !policy.Allows(authorityID) {
			return VerifiedQuorum{}, ErrAuthorityNotAllowed
		}
		if now.Before(approval.ApprovedAt) || !now.Before(approval.ExpiresAt) {
			continue
		}
		candidates = append(candidates, approval)
	}
	if len(candidates) < int(policy.Threshold) {
		return VerifiedQuorum{}, ErrBelowThreshold
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].ExpiresAt.Equal(candidates[j].ExpiresAt) {
			return candidates[i].ExpiresAt.After(candidates[j].ExpiresAt)
		}
		if candidates[i].AuthorityID != candidates[j].AuthorityID {
			return candidates[i].AuthorityID < candidates[j].AuthorityID
		}
		return candidates[i].ApprovalID < candidates[j].ApprovalID
	})
	selected := candidates[:policy.Threshold]
	acceptedUntil := policy.ExpiresAt
	for _, approval := range selected {
		if approval.ExpiresAt.Before(acceptedUntil) {
			acceptedUntil = approval.ExpiresAt
		}
	}
	if !now.Before(acceptedUntil) {
		return VerifiedQuorum{}, ErrExpired
	}
	quorum := VerifiedQuorum{
		Schema: QuorumSchemaV1, ConsumptionID: request.ConsumptionID,
		DecisionID: request.Binding.DecisionID, PolicyDigest: request.Binding.PolicyDigest,
		OperationDigest: request.Binding.OperationDigest, Audience: policy.Audience,
		Threshold: policy.Threshold, ApprovalCount: policy.Threshold,
		ConsumedAt: now, AcceptedUntil: acceptedUntil,
	}
	if err := quorum.ValidateAt(now); err != nil {
		return VerifiedQuorum{}, err
	}
	selectedIDs := make([]string, len(selected))
	for index, approval := range selected {
		selectedIDs[index] = approval.ApprovalID
	}
	sort.Strings(selectedIDs)
	s.storePolicyLocked(policy)
	record.selectedApprovalIDs = selectedIDs
	record.consumption = &quorum
	s.consumptionsByID[request.ConsumptionID] = quorum
	return quorum, nil
}

func (s *MemoryStore) currentTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *MemoryStore) RevokeDecision(ctx context.Context, revocation DecisionRevocation) error {
	if ctx == nil {
		return fmt.Errorf("%w: missing context", ErrInvalidRevocation)
	}
	if s == nil {
		return ErrMissingStore
	}
	if err := revocation.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.revocationsByID[revocation.RevocationID]; ok {
		if sameRevocation(existing, revocation) {
			return nil
		}
		return fmt.Errorf("%w: revocation identifier conflict", ErrInvalidRevocation)
	}
	record, ok := s.decisions[revocation.DecisionID]
	if !ok {
		record = &memoryDecision{
			approvals: make(map[string]Approval), principals: make(map[string]string),
			credentials: make(map[string]string),
		}
		s.decisions[revocation.DecisionID] = record
	}
	if record.consumption != nil {
		return ErrDecisionConsumed
	}
	if record.revocation != nil {
		return ErrDecisionRevoked
	}
	record.revocation = &revocation
	s.revocationsByID[revocation.RevocationID] = revocation
	return nil
}

func (s *MemoryStore) checkPolicyLocked(policy VerifiedPolicy) error {
	if existing, ok := s.policies[policy.PolicyDigest]; ok {
		if samePolicy(existing, policy) {
			return nil
		}
		return ErrPolicyConflict
	}
	return nil
}

func (s *MemoryStore) storePolicyLocked(policy VerifiedPolicy) {
	if _, exists := s.policies[policy.PolicyDigest]; !exists {
		s.policies[policy.PolicyDigest] = clonePolicy(policy)
	}
}

func clonePolicy(policy VerifiedPolicy) VerifiedPolicy {
	cloned := policy
	cloned.AuthorityIDs = append([]string(nil), policy.AuthorityIDs...)
	return cloned
}

func samePolicy(left, right VerifiedPolicy) bool {
	if left.Schema != right.Schema || left.PolicyID != right.PolicyID ||
		left.PolicyDigest != right.PolicyDigest || left.Audience != right.Audience ||
		left.AuthorityMapDigest != right.AuthorityMapDigest ||
		left.Epoch != right.Epoch || left.Threshold != right.Threshold ||
		!left.ValidFrom.Equal(right.ValidFrom) || !left.ExpiresAt.Equal(right.ExpiresAt) ||
		len(left.AuthorityIDs) != len(right.AuthorityIDs) {
		return false
	}
	for index := range left.AuthorityIDs {
		if left.AuthorityIDs[index] != right.AuthorityIDs[index] {
			return false
		}
	}
	return true
}

func sameApprovalProof(left, right Approval) bool {
	return left.Schema == right.Schema && left.ApprovalID == right.ApprovalID &&
		left.DecisionID == right.DecisionID && left.PolicyDigest == right.PolicyDigest &&
		left.OperationDigest == right.OperationDigest && left.Audience == right.Audience &&
		left.AuthorityID == right.AuthorityID && left.PrincipalTag == right.PrincipalTag &&
		left.CredentialTag == right.CredentialTag && left.AuthorizationTag == right.AuthorizationTag &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func sameRevocation(left, right DecisionRevocation) bool {
	return left.Schema == right.Schema && left.RevocationID == right.RevocationID &&
		left.DecisionID == right.DecisionID && left.RevokedAt.Equal(right.RevokedAt)
}
