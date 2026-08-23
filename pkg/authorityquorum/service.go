// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package authorityquorum

import (
	"context"
	"fmt"
	"time"
)

// PolicyResolver returns the current trusted policy for a decision. Failure to
// load current policy must fail closed.
type PolicyResolver interface {
	ResolveAuthorityQuorumPolicy(context.Context, string) (VerifiedPolicy, error)
}

type PolicyResolverFunc func(context.Context, string) (VerifiedPolicy, error)

func (f PolicyResolverFunc) ResolveAuthorityQuorumPolicy(ctx context.Context, decisionID string) (VerifiedPolicy, error) {
	return f(ctx, decisionID)
}

// Service keeps policy lookup, immutable approval construction, and atomic
// store operations behind one application boundary.
type Service struct {
	Store    Store
	Policies PolicyResolver
	Now      func() time.Time
}

func (s Service) Approve(ctx context.Context, request ApprovalRequest, accepted AcceptedAuthority) (Approval, error) {
	if ctx == nil {
		return Approval{}, fmt.Errorf("%w: missing context", ErrInvalidRequest)
	}
	if s.Store == nil {
		return Approval{}, ErrMissingStore
	}
	if err := request.Validate(); err != nil {
		return Approval{}, err
	}
	policy, now, err := s.currentPolicy(ctx, request.DecisionID)
	if err != nil {
		return Approval{}, err
	}
	if request.PolicyDigest != policy.PolicyDigest || accepted.Audience != policy.Audience ||
		accepted.AuthorityMapDigest != policy.AuthorityMapDigest {
		return Approval{}, ErrPolicyMismatch
	}
	if !policy.Allows(accepted.AuthorityID) {
		return Approval{}, ErrAuthorityNotAllowed
	}
	approval, err := NewApproval(request, accepted, now)
	if err != nil {
		return Approval{}, err
	}
	stored, err := s.Store.AppendApproval(ctx, policy, approval)
	if err != nil {
		return Approval{}, err
	}
	return stored, nil
}

func (s Service) Consume(ctx context.Context, request ConsumeRequest) (VerifiedQuorum, error) {
	if ctx == nil {
		return VerifiedQuorum{}, fmt.Errorf("%w: missing context", ErrInvalidRequest)
	}
	if s.Store == nil {
		return VerifiedQuorum{}, ErrMissingStore
	}
	if err := request.Validate(); err != nil {
		return VerifiedQuorum{}, err
	}
	policy, _, err := s.currentPolicy(ctx, request.Binding.DecisionID)
	if err != nil {
		return VerifiedQuorum{}, err
	}
	return s.Store.ConsumeQuorum(ctx, policy, request)
}

func (s Service) currentPolicy(ctx context.Context, decisionID string) (VerifiedPolicy, time.Time, error) {
	if s.Policies == nil {
		return VerifiedPolicy{}, time.Time{}, ErrMissingPolicyResolver
	}
	policy, err := s.Policies.ResolveAuthorityQuorumPolicy(ctx, decisionID)
	if err != nil {
		return VerifiedPolicy{}, time.Time{}, fmt.Errorf("authorityquorum: resolve current policy: %w", err)
	}
	now := s.currentTime()
	if err := policy.ValidateAt(now); err != nil {
		return VerifiedPolicy{}, time.Time{}, err
	}
	return policy, now, nil
}

func (s Service) currentTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
