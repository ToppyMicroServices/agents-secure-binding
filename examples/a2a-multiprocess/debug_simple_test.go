// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestPrepareDebugSimpleEnablesOnlyLocalSimulationOptIns(t *testing.T) {
	opts, err := prepareDebugSimple(debugSimpleTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !opts.allowSimulation || !opts.allowInsecureLLMLoopback {
		t.Fatalf("debug opt-ins = simulation:%v insecure-loopback:%v, want both true", opts.allowSimulation, opts.allowInsecureLLMLoopback)
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

func TestPrepareDebugSimpleRequiresLoopbackConversationLLMs(t *testing.T) {
	base := debugSimpleTestOptions()
	base.workflow = workflowLLMConversation
	base.agentALLMURL = "http://localhost:11434/v1"
	base.agentBLLMURL = "http://[::1]:11435/v1"
	if _, err := prepareDebugSimple(base); err != nil {
		t.Fatalf("loopback LLM URLs rejected: %v", err)
	}

	tests := []struct {
		name      string
		configure func(*options)
		want      string
	}{
		{name: "Agent A remote", want: "Agent A LLM URL", configure: func(opts *options) { opts.agentALLMURL = "http://llm-a.example" }},
		{name: "Agent B remote", want: "Agent B LLM URL", configure: func(opts *options) { opts.agentBLLMURL = "http://llm-b.example" }},
		{name: "Agent A missing", want: "Agent A LLM URL", configure: func(opts *options) { opts.agentALLMURL = "" }},
		{name: "Agent B missing", want: "Agent B LLM URL", configure: func(opts *options) { opts.agentBLLMURL = "" }},
		{name: "HTTPS", want: "use HTTP", configure: func(opts *options) { opts.agentALLMURL = "https://localhost:11434" }},
		{name: "non HTTP scheme", want: "use HTTP", configure: func(opts *options) { opts.agentALLMURL = "file://localhost/tmp/model" }},
		{name: "malformed URL", want: "absolute HTTP URL", configure: func(opts *options) { opts.agentALLMURL = "http://[::1" }},
		{name: "relative URL", want: "absolute HTTP URL", configure: func(opts *options) { opts.agentALLMURL = "//localhost:11434" }},
		{name: "user information", want: "user information", configure: func(opts *options) { opts.agentALLMURL = "http://user@localhost:11434" }},
		{name: "query", want: "a query", configure: func(opts *options) { opts.agentALLMURL = "http://localhost:11434?debug=1" }},
		{name: "fragment", want: "a fragment", configure: func(opts *options) { opts.agentALLMURL = "http://localhost:11434#debug" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := base
			test.configure(&opts)
			if _, err := prepareDebugSimple(opts); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepareDebugSimple() error = %v, want error containing %q", err, test.want)
			}
		})
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
