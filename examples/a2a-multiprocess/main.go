// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

type options struct {
	role                   string
	stateDir               string
	listen                 string
	readyFile              string
	managerURL             string
	attesterURL            string
	verifierURL            string
	replayURL              string
	agentBURL              string
	publicURL              string
	attestationMode        string
	attestationPlatform    string
	expectedMeasurementHex string
	allowSimulation        bool
}

func main() {
	os.Exit(runMain())
}

func runMain() int {
	opts := parseFlags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runRole(ctx, opts, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "a2a multiprocess demo (%s) failed: %v\n", opts.role, err)
		return 1
	}
	return 0
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.role, "role", "orchestrator", "role: orchestrator, bootstrap, manager, attester, verifier, replay, agent-b, or agent-a")
	flag.StringVar(&opts.stateDir, "state-dir", "", "state directory containing role-specific credentials and replay state")
	flag.StringVar(&opts.listen, "listen", "127.0.0.1:0", "server listen address")
	flag.StringVar(&opts.readyFile, "ready-file", "", "optional file receiving the server address after startup")
	flag.StringVar(&opts.managerURL, "manager-url", "", "Manager base URL")
	flag.StringVar(&opts.attesterURL, "attester-url", "", "attester base URL")
	flag.StringVar(&opts.verifierURL, "verifier-url", "", "attestation verifier base URL")
	flag.StringVar(&opts.replayURL, "replay-url", "", "replay store base URL")
	flag.StringVar(&opts.agentBURL, "agent-b-url", "", "Agent B base URL")
	flag.StringVar(&opts.publicURL, "public-url", "", "public URL advertised by Agent B")
	flag.StringVar(&opts.attestationMode, "attestation-mode", modeSimulation, "attestation mode: simulation or hardware")
	flag.StringVar(&opts.attestationPlatform, "attestation-platform", platformAuto, "hardware platform: auto, snp, or tdx")
	flag.StringVar(&opts.expectedMeasurementHex, "expected-measurement-hex", "", "required hardware measurement (SNP MEASUREMENT or TDX MRTD), hex encoded")
	flag.BoolVar(&opts.allowSimulation, "allow-simulation", false, "allow explicitly marked simulation attestation results")
	flag.Parse()
	return opts
}

func runRole(ctx context.Context, opts options, out outputWriter) error {
	switch opts.role {
	case "orchestrator":
		return runOrchestrator(ctx, opts, out)
	case "bootstrap":
		return bootstrapState(opts.stateDir)
	case "manager":
		return runManager(ctx, opts, out)
	case "attester":
		return runAttester(ctx, opts, out)
	case "verifier":
		return runVerifier(ctx, opts, out)
	case "replay":
		return runReplayStore(ctx, opts, out)
	case "agent-b":
		return runAgentB(ctx, opts, out)
	case "agent-a":
		return runAgentA(ctx, opts, out)
	default:
		return fmt.Errorf("unsupported role %q", opts.role)
	}
}

type outputWriter interface {
	Write([]byte) (int, error)
}
