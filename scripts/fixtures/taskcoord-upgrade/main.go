// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// This test-only probe is compiled unchanged against each source checkout.
// It uses synthetic authorization fixtures and does not contact any provider.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/sqlitestore"
)

const seedMode = "seed"

type state struct {
	Schema    int    `json:"schema"`
	Tasks     string `json:"tasks_sha256"`
	Actions   string `json:"actions_sha256"`
	NewTables int    `json:"reachability_quarantine_tables"`
	Integrity string `json:"integrity"`
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func inspect(ctx context.Context, path string) (state, error) {
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return state{}, err
	}
	defer func() { _ = db.Close() }()
	var result state
	var tasks, actions []byte
	var application int
	for query, target := range map[string]any{
		"PRAGMA user_version": &result.Schema, "PRAGMA application_id": &application,
		"PRAGMA integrity_check": &result.Integrity,
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('reachability','outbox_quarantine')": &result.NewTables,
	} {
		if err := db.QueryRowContext(ctx, query).Scan(target); err != nil {
			return state{}, err
		}
	}
	if application != 0x41534243 || result.Integrity != "ok" {
		return state{}, errors.New("unexpected TaskCoord database identity or integrity")
	}
	if err := db.QueryRowContext(ctx, "SELECT tasks, actions FROM state WHERE id=1").Scan(&tasks, &actions); err != nil {
		return state{}, err
	}
	result.Tasks, result.Actions = digest(tasks), digest(actions)
	return result, nil
}

func fixture() (taskcoord.Participant, taskcoord.Transition, error) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	participant := taskcoord.Participant{
		Schema: taskcoord.ParticipantSchemaV1, ParticipantID: "agent:upgrade-fixture",
		Kind: taskcoord.ParticipantAgent, IdentityRef: "urn:identity:upgrade-fixture", Status: taskcoord.ParticipantActive, RegisteredAt: at.Add(-time.Hour),
	}
	auth := taskcoord.AuthenticatedOperation{
		ActorID: participant.ParticipantID, ParticipantID: participant.ParticipantID,
		AuthorizationID: "authorization:upgrade-fixture", ProofID: "proof:upgrade-fixture", Operation: taskcoord.OperationOffer,
		TaskID: "task:upgrade-fixture", AssignmentID: "assignment:upgrade-fixture", TargetParticipantID: participant.ParticipantID,
		VerifierNonce: "nonce:upgrade-fixture", IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute),
	}
	transition, err := taskcoord.Offer(taskcoord.AssignmentDefinition{
		EventID: "event:upgrade-fixture", AssignmentID: auth.AssignmentID,
		TaskID: auth.TaskID, ParticipantID: participant.ParticipantID, Role: taskcoord.RoleAssignee,
		AuthorityDigest: strings.Repeat("a", 64), OfferedAt: at,
	}, participant, auth)
	return participant, transition, err
}

func exercise(ctx context.Context, mode, path string) (map[string]any, error) {
	var before state
	if mode == seedMode {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("seed requires a new database")
		}
	} else if mode == "verify" {
		var err error
		before, err = inspect(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("inspect historical database: %w", err)
		}
		if before.Schema != 1 || before.NewTables != 0 {
			return nil, errors.New("expected actual old schema 1 before migration")
		}
	} else {
		return nil, errors.New("mode must be seed or verify")
	}
	//nolint:contextcheck // Both reviewed Open APIs own a bounded initialization context and accept no caller context.
	store, err := sqlitestore.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = store.Close() }()
	participant, transition, err := fixture()
	if err != nil {
		return nil, err
	}
	if mode == seedMode {
		if err := store.RegisterParticipant(ctx, participant); err != nil {
			return nil, err
		}
		if err := store.CommitAssignment(ctx, 0, transition.Assignment, transition.Record); err != nil {
			return nil, err
		}
	}
	loadedParticipant, err := store.LoadParticipant(ctx, participant.ParticipantID)
	if err != nil || !reflect.DeepEqual(loadedParticipant, participant) {
		return nil, errors.New("Participant changed across storage transition")
	}
	loaded, err := store.LoadAssignment(ctx, transition.Assignment.AssignmentID)
	if err != nil || !reflect.DeepEqual(loaded, transition.Assignment) {
		return nil, errors.New("Assignment changed across storage transition")
	}
	// The original EventID must retain its immutable retry history. Losing that
	// history would make this initial-creation retry conflict with the row.
	if err := store.CommitAssignment(ctx, 0, transition.Assignment, transition.Record); err != nil {
		return nil, fmt.Errorf("immutable retry was not preserved: %w", err)
	}
	if err := store.Close(); err != nil {
		return nil, err
	}
	after, err := inspect(ctx, path)
	if err != nil {
		return nil, err
	}
	if mode == seedMode && (after.Schema != 1 || after.NewTables != 0) {
		return nil, errors.New("initial probe did not create the historical schema")
	}
	if mode == "verify" && (after.Schema != 2 || after.NewTables != 2 || before.Tasks != after.Tasks || before.Actions != after.Actions) {
		return nil, errors.New("expected schema 1 to 2 migration preserving state bytes")
	}
	return map[string]any{
		"schema": "asb.taskcoord-upgrade-probe/v1", "passed": true, "mode": mode,
		"before": before, "after": after, "participant_preserved": true, "assignment_preserved": true, "immutable_retry_preserved": true,
	}, nil
}

func run() int {
	mode := flag.String("mode", "", "seed or verify")
	path := flag.String("database", "", "private disposable database path")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if !filepath.IsAbs(*path) {
		fmt.Fprintln(os.Stderr, "probe requires an absolute database path")
		return 2
	}
	result, err := exercise(ctx, *mode, *path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TaskCoord upgrade probe failed:", err)
		return 1
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "probe evidence failed:", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run())
}
