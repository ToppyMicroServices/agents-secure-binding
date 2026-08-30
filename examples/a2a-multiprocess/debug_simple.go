// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/runtime/netguard"
)

const debugSimpleWarning = "WARNING: --debug-simple is for LOCAL DEBUGGING ONLY. It uses signed SIMULATED attestation evidence; no SNP, TDX, TPM, or vTPM evidence is collected or verified. ASB role endpoints remain loopback-only, and plaintext HTTP is permitted only for loopback LLM endpoints. This run is not evidence of confidential execution or production readiness."

func prepareDebugSimple(opts options) (options, error) {
	if opts.role != "orchestrator" {
		return opts, fmt.Errorf("--debug-simple requires --role=orchestrator")
	}
	if opts.deploymentConfig != "" {
		return opts, fmt.Errorf("--debug-simple cannot be combined with --deployment-config")
	}
	if !strings.EqualFold(opts.attestationMode, modeSimulation) {
		return opts, fmt.Errorf("--debug-simple requires --attestation-mode=simulation")
	}
	if opts.attestationPlatform != "" && !strings.EqualFold(opts.attestationPlatform, platformAuto) {
		return opts, fmt.Errorf("--debug-simple requires --attestation-platform=auto")
	}
	if opts.expectedMeasurementHex != "" {
		return opts, fmt.Errorf("--debug-simple cannot be combined with --expected-measurement-hex")
	}
	if effectiveAcceptanceStore(opts.acceptanceStore) != acceptanceStoreFile {
		return opts, fmt.Errorf("--debug-simple requires --acceptance-store=file")
	}
	for _, endpoint := range []struct {
		flag  string
		value string
	}{
		{flag: "--manager-url", value: opts.managerURL},
		{flag: "--attester-url", value: opts.attesterURL},
		{flag: "--verifier-url", value: opts.verifierURL},
		{flag: "--replay-url", value: opts.replayURL},
		{flag: "--agent-b-url", value: opts.agentBURL},
		{flag: "--public-url", value: opts.publicURL},
	} {
		if endpoint.value != "" {
			return opts, fmt.Errorf("--debug-simple cannot be combined with %s", endpoint.flag)
		}
	}
	if effectiveWorkflow(opts.workflow) == workflowLLMConversation {
		for _, endpoint := range []struct {
			name  string
			value string
		}{
			{name: "Agent A", value: opts.agentALLMURL},
			{name: "Agent B", value: opts.agentBLLMURL},
		} {
			if err := validateDebugSimpleLLMURL(endpoint.name, endpoint.value); err != nil {
				return opts, err
			}
		}
	}

	opts.allowSimulation = true
	opts.allowInsecureLLMLoopback = true
	return opts, nil
}

func validateDebugSimpleLLMURL(name, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return fmt.Errorf("--debug-simple requires the %s LLM URL to be an absolute HTTP URL", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("--debug-simple does not allow user information, a query, or a fragment in the %s LLM URL", name)
	}
	if !strings.EqualFold(parsed.Scheme, "http") {
		return fmt.Errorf("--debug-simple requires the %s LLM URL to use HTTP", name)
	}
	if !netguard.IsLoopbackHost(parsed.Hostname()) {
		return fmt.Errorf("--debug-simple requires the %s LLM URL to use a loopback hostname", name)
	}
	return nil
}
