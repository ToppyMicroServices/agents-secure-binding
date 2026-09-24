// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTaskRequiresIndependentAuthorization(t *testing.T) {
	configs, err := bootstrapDemo(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stop, err := startTaskServer(context.Background(), configs[roleAgentB])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), taskTimeout)
		defer cancel()
		if err := stop(ctx); err != nil {
			t.Error(err)
		}
	})
	config := configs[roleAgentA]
	request := taskRequest{TaskID: taskID, Values: []int64{7, 11, 13}}
	withoutTaskGrant := config
	withoutTaskGrant.TaskGrant = ""
	result, status, err := sendTask(context.Background(), withoutTaskGrant, config.Target.Endpoint, request, false)
	if err != nil || status != http.StatusUnauthorized || result != (taskResult{}) {
		t.Fatalf("task without authorization = %+v, status %d, error %v", result, status, err)
	}
	replayPath := filepath.Join(configs[roleAgentB].StateDir, "task-replay.json")
	if _, err := os.Stat(replayPath); !os.IsNotExist(err) {
		t.Fatalf("unaccepted task wrote replay state: %v", err)
	}
	result, status, err = sendTask(context.Background(), config, config.Target.Endpoint, request, true)
	if err != nil || status != http.StatusOK {
		t.Fatalf("authorized task = %+v, status %d, error %v", result, status, err)
	}
	if result.TaskID != taskID || result.AgentID != roleAgentB || result.Caller != roleAgentA || result.Sum != 31 || result.Executions != 1 || result.PID != os.Getpid() {
		t.Fatalf("authorized task result = %+v", result)
	}
	info, err := os.Stat(replayPath)
	if err != nil || info.Size() == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("durable task replay file = %v, error %v", info, err)
	}
}

func TestTaskInputBounds(t *testing.T) {
	tests := []struct {
		name    string
		request taskRequest
		valid   bool
	}{
		{name: "sum", request: taskRequest{TaskID: taskID, Values: []int64{7, 11, 13}}, valid: true},
		{name: "limits", request: taskRequest{TaskID: taskID, Values: []int64{-1_000_000, 1_000_000}}, valid: true},
		{name: "sixteen-values", request: taskRequest{TaskID: taskID, Values: make([]int64, 16)}, valid: true},
		{name: "seventeen-values", request: taskRequest{TaskID: taskID, Values: make([]int64, 17)}},
		{name: "no-values", request: taskRequest{TaskID: taskID}},
		{name: "other-task", request: taskRequest{TaskID: "another-task", Values: []int64{1}}},
		{name: "above-limit", request: taskRequest{TaskID: taskID, Values: []int64{1_000_001}}},
		{name: "below-limit", request: taskRequest{TaskID: taskID, Values: []int64{-1_000_001}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateTask(test.request); (err == nil) != test.valid {
				t.Fatalf("validateTask = %v, want valid=%v", err, test.valid)
			}
		})
	}
	for _, body := range []string{
		`{"task_id":"sum-demo-1","values":[1.5]}`,
		`{"task_id":"sum-demo-1","values":[9223372036854775808]}`,
		`{"task_id":"sum-demo-1","values":[1],"extra":true}`,
		`{"task_id":"sum-demo-1","values":[1]} {}`,
	} {
		var request taskRequest
		if err := decodeTaskJSON([]byte(body), &request); err == nil {
			t.Fatalf("decoded unsupported task JSON: %s", body)
		}
	}
}

func TestTaskActionBindsFullBodyAndRoles(t *testing.T) {
	body := []byte(`{"task_id":"sum-demo-1","values":[7,11,13]}`)
	action, err := taskActionContext(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(action, &fields); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if fields["method"] != http.MethodPost || fields["path"] != taskPath || fields["sender"] != roleAgentA || fields["receiver"] != roleAgentB || fields["body_sha256"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("task action context = %s", action)
	}
	changed, err := taskActionContext([]byte(`{"task_id":"sum-demo-1","values":[7,11,14]}`))
	if err != nil || bytes.Equal(action, changed) {
		t.Fatalf("changed values did not change task binding: %v", err)
	}
}

func TestTaskClientRejectsEndpointBeforeConnection(t *testing.T) {
	config := processConfig{
		Self:   trustedIdentity{Role: roleAgentA},
		Target: targetConfig{AgentID: roleAgentB, Endpoint: "https://127.0.0.1:9443"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, status, err := sendTask(ctx, config, "https://127.0.0.1:9444", taskRequest{TaskID: taskID, Values: []int64{1}}, false)
	if err == nil || status != 0 || result != (taskResult{}) {
		t.Fatalf("unconfigured endpoint = %+v, status %d, error %v", result, status, err)
	}
}
