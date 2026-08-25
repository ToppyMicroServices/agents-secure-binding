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
	"time"
)

var (
	version = "dev"
	commit  = "unknown"
)

type options struct {
	role                     string
	workflow                 string
	stateDir                 string
	listen                   string
	readyFile                string
	managerURL               string
	attesterURL              string
	verifierURL              string
	replayURL                string
	agentBURL                string
	publicURL                string
	attestationMode          string
	attestationPlatform      string
	expectedMeasurementHex   string
	allowSimulation          bool
	bindingProfile           string
	reportFormat             string
	reportFile               string
	deploymentConfig         string
	trustManifest            string
	deploymentEvidence       string
	promptFile               string
	agentALLMURL             string
	agentALLMModel           string
	agentAAPIKeyEnv          string
	agentBLLMURL             string
	agentBLLMModel           string
	agentBAPIKeyEnv          string
	allowInsecureLLMLoopback bool
	acceptanceStore          string
	redisAddress             string
	redisServerName          string
	redisCAFile              string
	redisUsername            string
	redisPasswordEnv         string
	redisKeyPrefix           string
	redisOperationTimeout    time.Duration
	redisMaxReplayTTL        time.Duration
	redisReplicaAcks         int
	redisReplicationTimeout  time.Duration
	showVersion              bool
}

func main() {
	os.Exit(runMain())
}

func runMain() int {
	opts := parseFlags()
	if opts.showVersion {
		fmt.Printf("asb-a2a-test %s (%s)\n", version, commit)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runRole(ctx, opts, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "asb-a2a-test (%s) failed: %v\n", opts.role, err)
		return 1
	}
	return 0
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.role, "role", "orchestrator", "role: orchestrator, bootstrap, manager, attester, verifier, replay, agent-b, agent-a, or verify-evidence")
	flag.StringVar(&opts.workflow, "workflow", workflowSecurityTest, "workflow: security-test or llm-conversation")
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
	flag.StringVar(&opts.bindingProfile, "binding-profile", bindingProfileV1, "binding profile: v1 or draft06-v2")
	flag.StringVar(&opts.reportFormat, "format", reportFormatText, "result format: text or json")
	flag.StringVar(&opts.reportFile, "report", "", "optional path for an atomic JSON report")
	flag.StringVar(&opts.deploymentConfig, "deployment-config", "", "multi-host deployment JSON; supplies HTTPS endpoints, listen addresses, and the binding profile")
	flag.StringVar(&opts.trustManifest, "trust-manifest", "", "multi-host non-secret trust manifest (defaults to <state-dir>/multihost-trust.json)")
	flag.StringVar(&opts.deploymentEvidence, "deployment-evidence", "", "optional atomic multi-host evidence file written by Agent A")
	flag.StringVar(&opts.promptFile, "prompt-file", "", "input file for llm-conversation (maximum 64 KiB)")
	flag.StringVar(&opts.agentALLMURL, "agent-a-llm-url", "", "Agent A OpenAI-compatible API base URL")
	flag.StringVar(&opts.agentALLMModel, "agent-a-llm-model", "", "Agent A model ID")
	flag.StringVar(&opts.agentAAPIKeyEnv, "agent-a-api-key-env", "ASB_AGENT_A_LLM_API_KEY", "ASB_-prefixed environment variable containing Agent A's API key")
	flag.StringVar(&opts.agentBLLMURL, "agent-b-llm-url", "", "Agent B OpenAI-compatible API base URL")
	flag.StringVar(&opts.agentBLLMModel, "agent-b-llm-model", "", "Agent B model ID")
	flag.StringVar(&opts.agentBAPIKeyEnv, "agent-b-api-key-env", "ASB_AGENT_B_LLM_API_KEY", "ASB_-prefixed environment variable containing Agent B's API key")
	flag.BoolVar(&opts.allowInsecureLLMLoopback, "allow-insecure-llm-loopback", false, "allow HTTP only for loopback LLM endpoints")
	flag.StringVar(&opts.acceptanceStore, "acceptance-store", "file", "v2 acceptance store: file or redis")
	flag.StringVar(&opts.redisAddress, "redis-address", "", "Redis/Valkey TLS host:port for the redis acceptance store")
	flag.StringVar(&opts.redisServerName, "redis-server-name", "", "Redis/Valkey TLS server name")
	flag.StringVar(&opts.redisCAFile, "redis-ca-file", "", "PEM CA file for Redis/Valkey TLS")
	flag.StringVar(&opts.redisUsername, "redis-username", "", "Redis/Valkey ACL username")
	flag.StringVar(&opts.redisPasswordEnv, "redis-password-env", "ASB_REDIS_PASSWORD", "ASB_-prefixed environment variable containing the Redis/Valkey password")
	flag.StringVar(&opts.redisKeyPrefix, "redis-key-prefix", "asb:a2a:acceptance:v1:", "Redis/Valkey key namespace ending in colon")
	flag.DurationVar(&opts.redisOperationTimeout, "redis-operation-timeout", 5*time.Second, "maximum time for one Redis/Valkey transaction")
	flag.DurationVar(&opts.redisMaxReplayTTL, "redis-max-replay-ttl", 10*time.Minute, "maximum accepted replay retention")
	flag.IntVar(&opts.redisReplicaAcks, "redis-replica-acks", 0, "replica acknowledgements required after each Redis/Valkey write")
	flag.DurationVar(&opts.redisReplicationTimeout, "redis-replication-timeout", 0, "WAIT timeout when replica acknowledgements are required")
	flag.BoolVar(&opts.showVersion, "version", false, "print version and exit")
	flag.Parse()
	return opts
}

func runRole(ctx context.Context, opts options, out outputWriter) error {
	var deployment *multiHostDeploymentV1
	if opts.deploymentConfig != "" {
		loaded, err := loadMultiHostDeployment(opts.deploymentConfig)
		if err != nil {
			return err
		}
		deployment = &loaded
		opts = applyMultiHostDeployment(opts, loaded)
		if opts.role == "orchestrator" {
			return fmt.Errorf("multi-host deployment config is used with explicit roles, not the loopback orchestrator")
		}
	}
	if opts.deploymentEvidence != "" && (deployment == nil || (opts.role != demoAgentIssuer && opts.role != roleVerifyEvidence)) {
		return fmt.Errorf("deployment evidence requires --deployment-config and Agent A or verify-evidence role")
	}
	if opts.trustManifest != "" && (deployment == nil || (opts.role != "bootstrap" && !((opts.role == demoAgentIssuer || opts.role == roleVerifyEvidence) && opts.deploymentEvidence != ""))) {
		return fmt.Errorf("trust manifest is used only by multi-host bootstrap, Agent A evidence, or evidence verification")
	}
	opts.workflow = effectiveWorkflow(opts.workflow)
	if opts.workflow != workflowSecurityTest && opts.workflow != workflowLLMConversation {
		return fmt.Errorf("unsupported workflow %q", opts.workflow)
	}
	if opts.reportFormat != reportFormatText && opts.reportFormat != reportFormatJSON {
		return fmt.Errorf("unsupported result format %q", opts.reportFormat)
	}
	switch opts.role {
	case "orchestrator":
		return runOrchestrator(ctx, opts, out)
	case "bootstrap":
		if deployment != nil {
			return bootstrapMultiHostState(opts.stateDir, *deployment, effectiveTrustManifestPath(opts))
		}
		return bootstrapState(opts.stateDir)
	case "manager":
		return runManager(ctx, opts, out)
	case "attester":
		return runAttester(ctx, opts, out)
	case "verifier":
		return runVerifier(ctx, opts, out)
	case "replay":
		return runReplayStore(ctx, opts, out)
	case demoAudience:
		return runAgentB(ctx, opts, out)
	case demoAgentIssuer:
		return runAgentA(ctx, opts, out)
	case roleVerifyEvidence:
		return verifyMultiHostRunEvidence(opts, out)
	default:
		return fmt.Errorf("unsupported role %q", opts.role)
	}
}

func effectiveWorkflow(value string) string {
	if value == "" {
		return workflowSecurityTest
	}
	return value
}

type outputWriter interface {
	Write([]byte) (int, error)
}
