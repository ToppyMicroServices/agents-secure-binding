// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"fmt"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
)

func validateDerivedTransition(
	current actionlifecycle.Snapshot,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
) error {
	derived, err := actionlifecycle.Apply(current, event)
	if err != nil {
		return err
	}
	if !sameJSON(derived, transition) {
		return fmt.Errorf("%w: transition was not derived from the supplied Event", ErrInvalidBinding)
	}
	return nil
}

func validateAuthenticatedCommitAt(
	current actionlifecycle.Snapshot,
	event actionlifecycle.Event,
	transition actionlifecycle.Transition,
	now time.Time,
) error {
	if event.Auth == nil {
		return actionlifecycle.ErrAuthenticationRequired
	}
	digest, err := actionlifecycle.MutationRequestDigest(event)
	if err != nil {
		return fmt.Errorf("%w: mutation request digest: %v", actionlifecycle.ErrInvalidEvent, err)
	}
	if digest == "" || event.Auth.MutationDigest != digest || transition.Record.MutationDigest != digest {
		return fmt.Errorf("%w: mutation digest changed before commit", ErrStoreConflict)
	}
	if transition.Record.At.After(now) {
		return fmt.Errorf("%w: transition timestamp is after the transaction clock", actionlifecycle.ErrInvalidEvent)
	}
	issuedAt := event.Auth.IssuedAt.UTC()
	expiresAt := event.Auth.ExpiresAt.UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(issuedAt) ||
		now.Before(issuedAt) || !now.Before(expiresAt) {
		return fmt.Errorf("%w: authorization expired before commit", actionlifecycle.ErrInvalidEvent)
	}
	if event.Fence != nil && current.ExecutorLease != nil && !now.Before(current.ExecutorLease.ExpiresAt) {
		return actionlifecycle.ErrLeaseExpired
	}
	if transition.Snapshot.ExecutorLease != nil &&
		!now.Before(transition.Snapshot.ExecutorLease.ExpiresAt) {
		return actionlifecycle.ErrLeaseExpired
	}
	return nil
}
