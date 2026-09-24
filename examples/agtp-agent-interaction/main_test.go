// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"
)

func TestAgentInteractionProcesses(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	evidence, err := runDemo(ctx, childCommand{
		executable: executable, prefix: []string{"-test.run=^TestInteractionChild$", "--"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Passed || !evidence.DistinctProcesses || !evidence.DistinctTLSKeys || evidence.LLMUsed {
		t.Fatalf("unexpected run identity: %+v", evidence)
	}
	if evidence.Discovery.InitialMatches != 0 || evidence.Discovery.InitialPeers != 1 || !evidence.Discovery.DHTFound || evidence.Discovery.PeerCount != 2 {
		t.Fatalf("discovery did not learn the task destination: %+v", evidence.Discovery)
	}
	if evidence.WithoutProofStatus != http.StatusUnauthorized || evidence.AuthorizedStatus != http.StatusOK || evidence.Result.Sum != 31 || evidence.Result.Executions != 1 {
		t.Fatalf("interaction decisions = %+v", evidence)
	}
	if evidence.Result.AgentID != roleAgentB || evidence.Result.Caller != roleAgentA || evidence.Result.PID != evidence.Processes[roleAgentB] {
		t.Fatalf("task identities = %+v", evidence.Result)
	}
	for _, role := range []string{roleAgentA, roleRelay, roleAgentB} {
		if evidence.Processes[role] <= 0 || evidence.Processes[role] == os.Getpid() {
			t.Fatalf("%s was not a child", role)
		}
	}
}

// The test binary uses the same role entry point as the standalone command.
// Each invocation is a real OS process with its own generated role credentials.
func TestInteractionChild(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	if err := runCommand(os.Args[separator+1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestChildEnvironmentOmitsProviderSecrets(t *testing.T) {
	t.Setenv("ASB_AGENT_A_LLM_API_KEY", "dummy-not-a-real-key")
	t.Setenv("ASB_AGENT_B_LLM_API_KEY", "dummy-not-a-real-key")
	for _, entry := range childEnvironment() {
		if entry == "ASB_AGENT_A_LLM_API_KEY=dummy-not-a-real-key" || entry == "ASB_AGENT_B_LLM_API_KEY=dummy-not-a-real-key" {
			t.Fatal("provider key was passed to the local reference agent")
		}
	}
}
