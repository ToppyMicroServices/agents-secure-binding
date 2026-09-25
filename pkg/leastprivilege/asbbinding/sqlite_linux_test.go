// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

func TestHTTPWithSQLiteAdmissionAndRestartReadback(t *testing.T) {
	var store *lp.SQLiteStore
	directory := filepath.Join(t.TempDir(), "sqlite")
	h := newHTTPFixture(t, func(f *fixture, _ *HTTPConfig) {
		var err error
		store, err = lp.CreateSQLiteStore(t.Context(), directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		f.service.store = store
		f.op.ID = store.Namespace() + "/operation"
		f.op.MandateID = store.Namespace() + "/mandate"
		f.record.Mandate.ID = f.op.MandateID
		if err = f.policies.Put(f.record); err != nil {
			t.Fatal(err)
		}
		if err = store.SyncMandates(t.Context(), []lp.Mandate{f.record.Mandate}); err != nil {
			t.Fatal(err)
		}
	})
	cap := h.authorize(t)
	c := h.challenge(t, h.client, "execute")
	status, raw, _ := h.post(t, h.client, "/execute", HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: cap})
	var result HTTPResponse
	if err := json.Unmarshal(raw, &result); err != nil || status != http.StatusOK || result.Execution == nil || result.Execution.State != lp.ExecutionSucceeded || h.f.calls.Load() != 1 {
		t.Fatalf("SQLite TLS execution: %d %s", status, raw)
	}
	reopened, err := lp.OpenSQLiteStore(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.Lookup(t.Context(), result.Execution.OperationID, result.Execution.RequestDigest)
	if err != nil || record != *result.Execution {
		t.Fatalf("durable readback: %+v %v", record, err)
	}
	c = h.challenge(t, h.client, "execute")
	status, _, _ = h.post(t, h.client, "/execute", HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.f.op, Proof: h.proof(t, c, nil), Capability: cap})
	if status != http.StatusOK || h.f.calls.Load() != 1 {
		t.Fatal("fresh proof redispatched the completed task")
	}
}
