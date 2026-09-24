// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// This command runs two deterministic agents and a discovery relay as separate
// processes. It uses local test identities, not production credentials or LLMs.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

type commandOptions struct {
	role   string
	config string
	ready  string
	result string
	report string
}

type interactionEvidence struct {
	SchemaVersion          int               `json:"schema_version"`
	Passed                 bool              `json:"passed"`
	NetworkScope           string            `json:"network_scope"`
	Profile                string            `json:"profile"`
	LLMUsed                bool              `json:"llm_used"`
	Processes              map[string]int    `json:"processes"`
	DistinctProcesses      bool              `json:"distinct_processes"`
	DistinctTLSKeys        bool              `json:"distinct_tls_keys"`
	Discovery              discoveryEvidence `json:"discovery"`
	Request                taskRequest       `json:"request"`
	Result                 taskResult        `json:"result"`
	WithoutProofStatus     int               `json:"without_task_proof_status"`
	AuthorizedStatus       int               `json:"authorized_status"`
	ResponseAuthentication string            `json:"response_authentication"`
	CreatedAt              time.Time         `json:"created_at"`
}

type processReady struct {
	Role string `json:"role"`
	PID  int    `json:"pid"`
}

func main() {
	if err := runCommand(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "agent interaction:", err)
		os.Exit(1)
	}
}

func runCommand(args []string, out io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if opts.role != "" {
		return runProcessRole(ctx, opts)
	}
	ctx, deadlineCancel := context.WithTimeout(ctx, 45*time.Second)
	defer deadlineCancel()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	evidence, err := runDemo(ctx, childCommand{executable: executable})
	if err != nil {
		return err
	}
	if opts.report != "" {
		if err := writeJSONFile(opts.report, evidence); err != nil {
			return err
		}
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(evidence)
}

func parseOptions(args []string) (commandOptions, error) {
	var opts commandOptions
	flags := flag.NewFlagSet("agtp-agent-interaction", flag.ContinueOnError)
	flags.StringVar(&opts.report, "report", "", "write the non-secret interaction evidence as JSON")
	flags.StringVar(&opts.role, "role", "", "internal child role: agent-a, agent-b, or relay")
	flags.StringVar(&opts.config, "config", "", "internal generated role configuration")
	flags.StringVar(&opts.ready, "ready", "", "internal readiness file")
	flags.StringVar(&opts.result, "result", "", "internal Agent A result file")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}
	if flags.NArg() != 0 {
		return opts, errors.New("unexpected positional arguments")
	}
	if opts.role == "" && (opts.config != "" || opts.ready != "" || opts.result != "") {
		return opts, errors.New("child flags require a role")
	}
	if opts.role != "" && (opts.config == "" || opts.ready == "" || opts.report != "") {
		return opts, errors.New("child requires config and readiness paths, without report")
	}
	if opts.role == roleAgentA && opts.result == "" {
		return opts, errors.New("agent-a requires a result path")
	}
	return opts, nil
}

func runProcessRole(ctx context.Context, opts commandOptions) (runErr error) {
	config, err := readConfig(opts.config)
	if err != nil {
		return err
	}
	if config.Self.Role != opts.role {
		return errors.New("role does not match configured identity")
	}
	node, err := startDiscovery(ctx, config)
	if err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, node.Stop(stopCtx))
	}()
	if opts.role == roleAgentB {
		stop, err := startTaskServer(ctx, config)
		if err != nil {
			return err
		}
		defer func() {
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			runErr = errors.Join(runErr, stop(stopCtx))
		}()
	}
	if err := writeJSONFile(opts.ready, processReady{Role: opts.role, PID: os.Getpid()}); err != nil {
		return err
	}
	if opts.role != roleAgentA {
		select {
		case <-ctx.Done():
			return nil
		case err := <-node.Errors():
			return err
		}
	}
	discovered, err := discoverTaskTarget(ctx, node, config)
	if err != nil {
		return err
	}
	request := taskRequest{TaskID: taskID, Values: []int64{7, 11, 13}}
	_, withoutProof, err := sendTask(ctx, config, discovered.Endpoint, request, false)
	if err != nil {
		return err
	}
	if withoutProof != http.StatusUnauthorized {
		return fmt.Errorf("task without proof returned %d", withoutProof)
	}
	result, status, err := sendTask(ctx, config, discovered.Endpoint, request, true)
	if err != nil {
		return err
	}
	if status != http.StatusOK || result.Sum != 31 || result.Executions != 1 || result.PID == os.Getpid() {
		return errors.New("task result did not demonstrate one separate-process execution")
	}
	scope := "single-host loopback"
	if len(config.AllowedCIDRs) > 0 {
		scope = "configured private IPs; host topology must be verified by the harness"
	}
	return writeJSONFile(opts.result, interactionEvidence{
		SchemaVersion: 1, Passed: true, NetworkScope: scope, Profile: "ASB software-only Direct-Agent v1",
		Processes: map[string]int{roleAgentA: os.Getpid(), roleAgentB: result.PID},
		Discovery: discovered, Request: request, Result: result,
		WithoutProofStatus: withoutProof, AuthorizedStatus: status,
		ResponseAuthentication: "same pinned TLS connection; no separate reverse-direction ASB proof",
		CreatedAt:              time.Now().UTC(),
	})
}

func writeJSONFile(path string, value any) (result error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".asb-interaction-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, err)
		}
	}()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
