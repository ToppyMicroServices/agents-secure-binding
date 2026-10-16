// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestHumanDecisionKindsHaveSeparateAuthenticatedBindings(t *testing.T) {
	digests := map[string]string{}
	for _, kind := range []string{KindApprove, KindDecline, KindNotApplicable, KindUndetermined} {
		command := Command{CommandID: "decision", Kind: kind, OperationID: "proposal", ProposalDigest: "sha256:" + strings.Repeat("a", 64)}
		if err := command.Validate(); err != nil || !command.Mutation() || !ActorAllowed(ActorGateway, kind) || ActorAllowed(ActorAgent, kind) {
			t.Fatalf("invalid decision authorization for %s: %v", kind, err)
		}
		digest, err := CommandDigest(command)
		if err != nil {
			t.Fatal(err)
		}
		if previous := digests[digest]; previous != "" {
			t.Fatalf("%s and %s share an authenticated request digest", previous, kind)
		}
		digests[digest] = kind
	}
	for _, kind := range []string{"", "ALLOW", "UNKNOWN", "OUTCOME_UNKNOWN", "INDETERMINATE", "undetermined"} {
		command := Command{CommandID: "decision", Kind: kind, OperationID: "proposal", ProposalDigest: "sha256:" + strings.Repeat("a", 64)}
		if !errors.Is(command.Validate(), ErrInvalid) || command.Mutation() || ActorAllowed(ActorGateway, kind) {
			t.Fatalf("unknown kind %q was treated as a Human decision", kind)
		}
	}
}

func TestNonAllowStoredDecisionCannotContainSettingEffect(t *testing.T) {
	for _, kind := range []string{KindDecline, KindNotApplicable, KindUndetermined} {
		t.Run(kind, func(t *testing.T) {
			store := openTestStore(t, filepath.Join(t.TempDir(), "state.sqlite"))
			_, proposed := executeStore(t, store, testProposal("proposal", true, 0), ActorAgent, "propose")
			_, decided := executeStore(t, store, testDecision("decision", kind, *proposed.Operation), ActorGateway, "decision")
			decided.Operation.After = &Setting{Tenant: Tenant, Name: SettingName, Enabled: true, Revision: 1}
			document, err := json.Marshal(decided.Operation)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.ExecContext(t.Context(), "UPDATE operations SET document = ? WHERE operation_id = ?", document, proposed.Operation.OperationID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Execute(t.Context(), testStatus(*proposed.Operation), testStoreAuth(ActorAgent, "status")); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted non-authorizing decision with setting effect: %v", err)
			}
		})
	}
}
