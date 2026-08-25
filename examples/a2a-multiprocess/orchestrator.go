// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type childProcess struct {
	name   string
	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan error
	stderr bytes.Buffer
}

func runOrchestrator(ctx context.Context, opts options, out outputWriter) (runErr error) {
	opts.workflow = effectiveWorkflow(opts.workflow)
	if opts.workflow == workflowLLMConversation {
		if err := validateConversationOptions(opts); err != nil {
			return err
		}
	}
	agentStarted := false
	defer func() {
		if runErr == nil || agentStarted || (opts.reportFormat != reportFormatJSON && opts.reportFile == "") {
			return
		}
		reporter, err := newTestRunReporter(opts, out)
		if err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("create infrastructure report: %w", err))
			return
		}
		reporter.recordInfrastructureError()
		if err := reporter.finish(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write infrastructure report: %w", err))
		}
	}()
	stateDir := opts.stateDir
	removeState := false
	if stateDir == "" {
		var err error
		stateDir, err = os.MkdirTemp("", "asb-a2a-multiprocess-")
		if err != nil {
			return fmt.Errorf("create demonstration state directory: %w", err)
		}
		removeState = true
	}
	if removeState {
		defer os.RemoveAll(stateDir)
	}
	if err := bootstrapState(stateDir); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate demonstration binary: %w", err)
	}

	processes := make([]*childProcess, 0, 5)
	defer func() {
		for i := len(processes) - 1; i >= 0; i-- {
			processes[i].cancel()
		}
		for i := len(processes) - 1; i >= 0; i-- {
			select {
			case <-processes[i].done:
			case <-time.After(2 * time.Second):
				_ = processes[i].cmd.Process.Kill()
				<-processes[i].done
			}
		}
	}()

	start := func(name string, extra ...string) (string, error) {
		childEnv, err := orchestratorChildEnvironment(opts, name)
		if err != nil {
			return "", err
		}
		process, rawURL, err := startServerProcess(ctx, executable, stateDir, name, childEnv, extra...)
		if err != nil {
			return "", err
		}
		processes = append(processes, process)
		if opts.reportFormat == reportFormatText {
			fmt.Fprintf(out, "started %-8s pid=%d endpoint=%s\n", name, process.cmd.Process.Pid, rawURL)
		}
		return rawURL, nil
	}

	replayURL, err := start("replay", replayProcessArgs(opts)...)
	if err != nil {
		return err
	}
	managerURL, err := start("manager", "--binding-profile", opts.bindingProfile)
	if err != nil {
		return err
	}
	attesterURL, err := start("attester", "--attestation-mode", opts.attestationMode, "--attestation-platform", opts.attestationPlatform)
	if err != nil {
		return err
	}
	verifierURL, err := start("verifier", "--expected-measurement-hex", opts.expectedMeasurementHex, "--binding-profile", opts.bindingProfile)
	if err != nil {
		return err
	}
	agentBArgs := []string{"--replay-url", replayURL, "--expected-measurement-hex", opts.expectedMeasurementHex, "--binding-profile", opts.bindingProfile}
	if opts.workflow == workflowLLMConversation {
		agentBArgs = append(agentBArgs,
			"--workflow", opts.workflow,
			"--agent-b-llm-url", opts.agentBLLMURL,
			"--agent-b-llm-model", opts.agentBLLMModel,
			"--agent-b-api-key-env", opts.agentBAPIKeyEnv,
		)
		if opts.allowInsecureLLMLoopback {
			agentBArgs = append(agentBArgs, "--allow-insecure-llm-loopback")
		}
	}
	if strings.EqualFold(opts.attestationMode, modeSimulation) {
		agentBArgs = append(agentBArgs, "--allow-simulation")
	} else if opts.allowSimulation {
		agentBArgs = append(agentBArgs, "--allow-simulation")
	}
	agentBURL, err := start("agent-b", agentBArgs...)
	if err != nil {
		return err
	}

	agentArgs := agentAProcessArgs(opts, stateDir, managerURL, attesterURL, verifierURL, agentBURL)
	agent := exec.CommandContext(ctx, executable, agentArgs...)
	agent.Env, err = orchestratorChildEnvironment(opts, "agent-a")
	if err != nil {
		return err
	}
	agent.Stdout = writerAdapter{out}
	var agentErrors bytes.Buffer
	agent.Stderr = &agentErrors
	if err := agent.Start(); err != nil {
		return fmt.Errorf("start Agent A test process: %w", err)
	}
	agentStarted = true
	if err := agent.Wait(); err != nil {
		return fmt.Errorf("Agent A test failed: %w: %s", err, strings.TrimSpace(agentErrors.String()))
	}
	return nil
}

func replayProcessArgs(opts options) []string {
	backend := effectiveAcceptanceStore(opts.acceptanceStore)
	arguments := []string{"--acceptance-store", backend}
	if backend != acceptanceStoreRedis {
		return arguments
	}
	return append(arguments,
		"--redis-address", opts.redisAddress,
		"--redis-server-name", opts.redisServerName,
		"--redis-ca-file", opts.redisCAFile,
		"--redis-username", opts.redisUsername,
		"--redis-password-env", effectiveRedisPasswordEnv(opts.redisPasswordEnv),
		"--redis-key-prefix", opts.redisKeyPrefix,
		"--redis-operation-timeout", opts.redisOperationTimeout.String(),
		"--redis-max-replay-ttl", opts.redisMaxReplayTTL.String(),
		"--redis-replica-acks", fmt.Sprintf("%d", opts.redisReplicaAcks),
		"--redis-replication-timeout", opts.redisReplicationTimeout.String(),
	)
}

func agentAProcessArgs(opts options, stateDir, managerURL, attesterURL, verifierURL, agentBURL string) []string {
	args := []string{
		"--role", "agent-a", "--state-dir", stateDir,
		"--manager-url", managerURL, "--attester-url", attesterURL,
		"--verifier-url", verifierURL, "--agent-b-url", agentBURL,
		"--attestation-mode", opts.attestationMode,
		"--attestation-platform", opts.attestationPlatform,
		"--binding-profile", opts.bindingProfile,
		"--workflow", opts.workflow,
		"--format", opts.reportFormat,
	}
	if opts.workflow == workflowLLMConversation {
		args = append(args,
			"--prompt-file", opts.promptFile,
			"--agent-a-llm-url", opts.agentALLMURL,
			"--agent-a-llm-model", opts.agentALLMModel,
			"--agent-a-api-key-env", opts.agentAAPIKeyEnv,
		)
		if opts.allowInsecureLLMLoopback {
			args = append(args, "--allow-insecure-llm-loopback")
		}
	}
	if opts.reportFile != "" {
		args = append(args, "--report", opts.reportFile)
	}
	return args
}

func startServerProcess(parent context.Context, executable, stateDir, role string, environment []string, extra ...string) (*childProcess, string, error) {
	readyFile := filepath.Join(stateDir, ".ready-"+role)
	_ = os.Remove(readyFile)
	ctx, cancel := context.WithCancel(parent)
	args := []string{"--role", role, "--state-dir", stateDir, "--listen", "127.0.0.1:0", "--ready-file", readyFile}
	args = append(args, extra...)
	process := &childProcess{name: role, cancel: cancel, done: make(chan error, 1)}
	process.cmd = exec.CommandContext(ctx, executable, args...)
	if environment != nil {
		process.cmd.Env = environment
	}
	process.cmd.Stdout = io.Discard
	process.cmd.Stderr = &process.stderr
	if err := process.cmd.Start(); err != nil {
		cancel()
		return nil, "", fmt.Errorf("start %s: %w", role, err)
	}
	go func() {
		process.done <- process.cmd.Wait()
	}()

	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-process.done:
			cancel()
			return nil, "", fmt.Errorf("%s exited before ready: %v: %s", role, err, strings.TrimSpace(process.stderr.String()))
		case <-ticker.C:
			raw, err := os.ReadFile(readyFile)
			if err == nil && strings.TrimSpace(string(raw)) != "" {
				return process, "https://" + strings.TrimSpace(string(raw)), nil
			}
		case <-timer.C:
			cancel()
			<-process.done
			return nil, "", fmt.Errorf("%s did not become ready: %s", role, strings.TrimSpace(process.stderr.String()))
		case <-parent.Done():
			cancel()
			<-process.done
			return nil, "", parent.Err()
		}
	}
}

type writerAdapter struct {
	outputWriter
}
