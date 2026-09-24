// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package sqlitestore

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/actionbinding"
)

func TestFirstAcceptanceRaceKeepsOneCanonicalCommitTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coord.db")
	seed := openTest(t, path, base.Add(2*time.Second))
	assignment, request := uncommittedAcceptanceFixture(t, seed)
	const contenders = 4
	stores := make([]*Store, contenders)
	for index := range stores {
		// All proofs are identical, but the winner alone chooses accepted_at.
		stores[index] = openTest(t, path, base.Add(time.Duration(index+2)*time.Second))
	}
	type result struct {
		view actionbinding.View
		err  error
	}
	results := make(chan result, contenders)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(contenders)
	for _, store := range stores {
		go func() {
			ready.Done()
			<-start
			view, err := store.CommitAcceptance(ctx, assignment.Revision, assignment, request)
			results <- result{view: view, err: err}
		}()
	}
	ready.Wait()
	close(start)
	first := <-results
	if first.err != nil {
		t.Fatal(first.err)
	}
	for index := 1; index < contenders; index++ {
		got := <-results
		if got.err != nil || !reflect.DeepEqual(got.view, first.view) {
			t.Fatalf("first-write race returned competing commit provenance: %+v, %v", got.view, got.err)
		}
	}
	if first.view.Action.CreatedAt.Before(base.Add(2*time.Second)) || first.view.Action.CreatedAt.After(base.Add(5*time.Second)) {
		t.Fatalf("acceptance clock is not one of the transaction clocks: %s", first.view.Action.CreatedAt)
	}
	var raw []byte
	if err := seed.db.QueryRowContext(ctx, "SELECT actions FROM state WHERE id=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		Actions            map[string]json.RawMessage `json:"actions"`
		Bindings           map[string]json.RawMessage `json:"bindings"`
		ActionByAssignment map[string]string          `json:"action_by_assignment"`
		Events             map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Actions) != 1 || len(persisted.Bindings) != 1 || len(persisted.Events) != 1 ||
		len(persisted.ActionByAssignment) != 1 || persisted.ActionByAssignment[assignment.AssignmentID] != request.ActionID {
		t.Fatalf("first-write race created duplicate acceptance state: %+v", persisted)
	}
}
