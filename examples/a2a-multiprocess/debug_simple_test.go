// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestPrepareDebugSimpleEnablesOnlySimulation(t *testing.T) {
	opts, err := prepareDebugSimple(debugSimpleTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !opts.allowSimulation || opts.allowInsecureLLMLoopback {
		t.Fatalf("debug opt-ins = simulation:%v insecure-loopback:%v, want only simulation", opts.allowSimulation, opts.allowInsecureLLMLoopback)
	}
}

func TestPrepareDebugSimpleRejectsNonlocalOrProductionOptions(t *testing.T) {
	tests := []struct {
		name      string
		want      string
		configure func(*options)
	}{
		{name: "role", want: "--role=orchestrator", configure: func(opts *options) { opts.role = demoAgentIssuer }},
		{name: "deployment", want: "--deployment-config", configure: func(opts *options) { opts.deploymentConfig = "deployment.json" }},
		{name: "hardware mode", want: "--attestation-mode=simulation", configure: func(opts *options) { opts.attestationMode = modeHardware }},
		{name: "SNP platform", want: "--attestation-platform=auto", configure: func(opts *options) { opts.attestationPlatform = platformSNP }},
		{name: "TDX platform", want: "--attestation-platform=auto", configure: func(opts *options) { opts.attestationPlatform = strings.ToLower(platformTDX) }},
		{name: "measurement", want: "--expected-measurement-hex", configure: func(opts *options) { opts.expectedMeasurementHex = "01" }},
		{name: "Redis store", want: "--acceptance-store=file", configure: func(opts *options) { opts.acceptanceStore = acceptanceStoreRedis }},
		{name: "manager URL", want: "--manager-url", configure: func(opts *options) { opts.managerURL = "https://127.0.0.1:1" }},
		{name: "attester URL", want: "--attester-url", configure: func(opts *options) { opts.attesterURL = "https://127.0.0.1:2" }},
		{name: "verifier URL", want: "--verifier-url", configure: func(opts *options) { opts.verifierURL = "https://127.0.0.1:3" }},
		{name: "replay URL", want: "--replay-url", configure: func(opts *options) { opts.replayURL = "https://127.0.0.1:4" }},
		{name: "Agent B URL", want: "--agent-b-url", configure: func(opts *options) { opts.agentBURL = "https://127.0.0.1:5" }},
		{name: "public URL", want: "--public-url", configure: func(opts *options) { opts.publicURL = "https://127.0.0.1:6" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := debugSimpleTestOptions()
			test.configure(&opts)
			if _, err := prepareDebugSimple(opts); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepareDebugSimple() error = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestPrepareDebugSimpleDoesNotEnableLegacyLLMTransport(t *testing.T) {
	opts := debugSimpleTestOptions()
	opts.workflow = workflowLLMConversation
	prepared, err := prepareDebugSimple(opts)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.allowInsecureLLMLoopback {
		t.Fatal("debug-simple enabled the legacy HTTP LLM transport")
	}
}

func debugSimpleTestOptions() options {
	return options{
		role:                "orchestrator",
		workflow:            workflowSecurityTest,
		attestationMode:     modeSimulation,
		attestationPlatform: platformAuto,
		acceptanceStore:     acceptanceStoreFile,
	}
}
