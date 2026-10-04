// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"fmt"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery"
)

// ErrEpochMismatch rejects stale snapshots, reused migration instructions, and
// configuration rollback. The configured epoch is the external rollback floor.
var ErrEpochMismatch = errors.New("agtp discovery peer: reclamation epoch mismatch")

// prepareEpoch runs before any saved records are admitted or a listener starts.
// It never adopts an epoch from a peer or guesses a migration from a mismatch.
func (n *Node) prepareEpoch(state *PersistentState, found bool) (bool, error) {
	if n.config.InitializeEpoch {
		if found || n.config.Epoch == 0 || n.config.ReclaimFromEpoch != nil {
			return false, ErrEpochMismatch
		}
		return true, nil
	}
	if from := n.config.ReclaimFromEpoch; from != nil {
		if !found || state.Epoch != *from || n.config.Epoch <= *from {
			return false, ErrEpochMismatch
		}
		if err := n.recordAudit(AuditEvent{
			NodeID: n.Info().ID, Action: "reclaim-epoch", Result: "requested",
			Reason: fmt.Sprintf("epoch-%d-to-%d", *from, n.config.Epoch),
		}); err != nil {
			return false, err
		}
		// Keeping records would retag stale data as current and defeat retirement.
		// Routing identities may survive: every exchange still checks the epoch.
		state.Presence = discovery.Delta{}
		state.Names = nil
		state.Epoch = n.config.Epoch
		return true, nil
	}
	if found && state.Epoch != n.config.Epoch || !found && n.config.Epoch != 0 {
		return false, ErrEpochMismatch
	}
	return false, nil
}
