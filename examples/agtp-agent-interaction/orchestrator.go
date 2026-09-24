// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type childCommand struct {
	executable string
	prefix     []string          // used by the multiprocess test helper
	namespaces map[string]string // Linux integration harness only
}

type runningProcess struct {
	role   string
	cmd    *exec.Cmd
	cancel context.CancelFunc
	done   chan struct{}
	err    error // read only after done is closed
	stderr bytes.Buffer
}

func runDemo(ctx context.Context, command childCommand) (_ interactionEvidence, runErr error) {
	var evidence interactionEvidence
	root, err := os.MkdirTemp("", "asb-agent-interaction-")
	if err != nil {
		return evidence, err
	}
	defer func() {
		runErr = errors.Join(runErr, os.RemoveAll(root))
	}()
	configs, err := bootstrapDemo(root)
	if err != nil {
		return evidence, err
	}
	return runPreparedDemo(ctx, command, root, configs)
}

func runPreparedDemo(ctx context.Context, command childCommand, root string, configs map[string]processConfig) (_ interactionEvidence, runErr error) {
	var evidence interactionEvidence
	processes := make([]*runningProcess, 0, 3)
	defer func() {
		for i := len(processes) - 1; i >= 0; i-- {
			runErr = errors.Join(runErr, processes[i].stop())
		}
	}()
	resultPath := filepath.Join(root, "result.json")
	for _, role := range []string{roleRelay, roleAgentB, roleAgentA} {
		config := configs[role]
		configPath := filepath.Join(config.StateDir, "config.json")
		if err := writeJSONFile(configPath, config); err != nil {
			return evidence, err
		}
		readyPath := filepath.Join(config.StateDir, "ready.json")
		args := append([]string(nil), command.prefix...)
		args = append(args, "--role", role, "--config", configPath, "--ready", readyPath)
		if role == roleAgentA {
			args = append(args, "--result", resultPath)
		}
		childCtx, cancel := context.WithCancel(ctx)
		process := &runningProcess{role: role, cancel: cancel, done: make(chan struct{})}
		executable := command.executable
		if namespace := command.namespaces[role]; namespace != "" {
			ip, err := exec.LookPath("ip")
			if err != nil {
				cancel()
				return evidence, err
			}
			args = append([]string{"netns", "exec", namespace, executable}, args...)
			executable = ip
		}
		process.cmd = exec.CommandContext(childCtx, executable, args...)
		process.cmd.Env = childEnvironment()
		process.cmd.Stderr = &process.stderr
		if err := process.cmd.Start(); err != nil {
			cancel()
			return evidence, err
		}
		processes = append(processes, process)
		go func() { process.err = process.cmd.Wait(); close(process.done) }()
		if err := process.waitReady(ctx, readyPath); err != nil {
			return evidence, err
		}
	}
	agentA := processes[2]
	select {
	case <-ctx.Done():
		return evidence, ctx.Err()
	case <-agentA.done:
		if agentA.err != nil {
			return evidence, agentA.failure()
		}
	}
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		return evidence, err
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return evidence, err
	}
	if !evidence.Passed || evidence.Processes[roleAgentA] != agentA.cmd.Process.Pid || evidence.Result.PID != processes[1].cmd.Process.Pid {
		return evidence, errors.New("interaction evidence does not match launched agents")
	}
	evidence.Processes[roleRelay] = processes[0].cmd.Process.Pid
	evidence.DistinctProcesses = evidence.Processes[roleAgentA] != evidence.Processes[roleAgentB] && evidence.Processes[roleAgentA] != evidence.Processes[roleRelay] && evidence.Processes[roleAgentB] != evidence.Processes[roleRelay]
	certificateA, err := certificateFromPEM(configs[roleAgentA].Self.Certificate)
	if err != nil {
		return evidence, err
	}
	certificateB, err := certificateFromPEM(configs[roleAgentB].Self.Certificate)
	if err != nil {
		return evidence, err
	}
	evidence.DistinctTLSKeys = publicKeyPin(certificateA) != publicKeyPin(certificateB)
	if !evidence.DistinctProcesses || !evidence.DistinctTLSKeys {
		return evidence, errors.New("agents were not distinct")
	}
	return evidence, nil
}

func (p *runningProcess) waitReady(ctx context.Context, path string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			var ready processReady
			if err := json.Unmarshal(raw, &ready); err != nil {
				return err
			}
			if ready.Role != p.role || ready.PID != p.cmd.Process.Pid {
				return errors.New("invalid readiness identity")
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("%s readiness timeout", p.role)
		case <-p.done:
			return p.failure()
		case <-ticker.C:
		}
	}
}

func (p *runningProcess) failure() error {
	return fmt.Errorf("%s exited: %v: %s", p.role, p.err, strings.TrimSpace(p.stderr.String()))
}

func (p *runningProcess) stop() error {
	defer p.cancel()
	select {
	case <-p.done:
		if p.err != nil {
			return p.failure()
		}
		return nil
	default:
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		p.cancel()
	}
	select {
	case <-p.done:
		if p.err != nil {
			return p.failure()
		}
		return nil
	case <-time.After(5 * time.Second):
		p.cancel()
		<-p.done
		return fmt.Errorf("%s required forced shutdown", p.role)
	}
}

// The reference agents do not need provider credentials from the parent shell.
func childEnvironment() []string {
	var environment []string
	for _, name := range []string{"PATH", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "GORACE"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}
