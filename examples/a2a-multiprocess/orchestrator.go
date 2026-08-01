// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
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

func runOrchestrator(ctx context.Context, opts options, out outputWriter) error {
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
		process, rawURL, err := startServerProcess(ctx, executable, stateDir, name, extra...)
		if err != nil {
			return "", err
		}
		processes = append(processes, process)
		fmt.Fprintf(out, "started %-8s pid=%d endpoint=%s\n", name, process.cmd.Process.Pid, rawURL)
		return rawURL, nil
	}

	replayURL, err := start("replay")
	if err != nil {
		return err
	}
	managerURL, err := start("manager")
	if err != nil {
		return err
	}
	attesterURL, err := start("attester", "--attestation-mode", opts.attestationMode, "--attestation-platform", opts.attestationPlatform)
	if err != nil {
		return err
	}
	verifierURL, err := start("verifier", "--expected-measurement-hex", opts.expectedMeasurementHex)
	if err != nil {
		return err
	}
	agentBArgs := []string{"--replay-url", replayURL, "--expected-measurement-hex", opts.expectedMeasurementHex}
	if strings.EqualFold(opts.attestationMode, modeSimulation) {
		agentBArgs = append(agentBArgs, "--allow-simulation")
	} else if opts.allowSimulation {
		agentBArgs = append(agentBArgs, "--allow-simulation")
	}
	agentBURL, err := start("agent-b", agentBArgs...)
	if err != nil {
		return err
	}

	agentArgs := []string{
		"--role", "agent-a", "--state-dir", stateDir,
		"--manager-url", managerURL, "--attester-url", attesterURL,
		"--verifier-url", verifierURL, "--agent-b-url", agentBURL,
		"--attestation-mode", opts.attestationMode,
	}
	agent := exec.CommandContext(ctx, executable, agentArgs...)
	agent.Stdout = writerAdapter{out}
	var agentErrors bytes.Buffer
	agent.Stderr = &agentErrors
	if err := agent.Run(); err != nil {
		return fmt.Errorf("Agent A demonstration failed: %w: %s", err, strings.TrimSpace(agentErrors.String()))
	}
	return nil
}

func startServerProcess(parent context.Context, executable, stateDir, role string, extra ...string) (*childProcess, string, error) {
	readyFile := filepath.Join(stateDir, ".ready-"+role)
	_ = os.Remove(readyFile)
	ctx, cancel := context.WithCancel(parent)
	args := []string{"--role", role, "--state-dir", stateDir, "--listen", "127.0.0.1:0", "--ready-file", readyFile}
	args = append(args, extra...)
	process := &childProcess{name: role, cancel: cancel, done: make(chan error, 1)}
	process.cmd = exec.CommandContext(ctx, executable, args...)
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
