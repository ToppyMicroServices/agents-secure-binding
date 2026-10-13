// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
)

const debugSimpleWarning = "WARNING: --debug-simple is for LOCAL DEBUGGING ONLY. It uses signed SIMULATED attestation evidence; no SNP, TDX, TPM, or vTPM evidence is collected or verified. ASB role endpoints remain loopback-only. This run is not evidence of confidential execution or production readiness."

func prepareDebugSimple(opts options) (options, error) {
	if opts.role != roleOrchestrator {
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
	opts.allowSimulation = true
	return opts, nil
}
