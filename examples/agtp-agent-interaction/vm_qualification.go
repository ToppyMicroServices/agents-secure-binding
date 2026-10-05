// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/agtp/discovery/peer"
)

const (
	vmLabTTL       = 25 * time.Minute
	vmOS           = "linux"
	vmTaskEndpoint = "https://10.203.0.13:9444"
	vmStopCommand  = "stop"
)

// This deliberately fixed lab configuration is not a deployment credential
// importer. Authority private keys remain in this short-lived preparation call;
// each VM receives only its own role credentials and the peer public identities.
func prepareVMConfigs(root string) error {
	if runtime.GOOS != vmOS || !filepath.IsAbs(root) {
		return errors.New("VM preparation requires Linux and a new absolute directory")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return err
	}
	configs, err := bootstrapDemoWithTTL(root, vmLabTTL)
	if err != nil {
		return err
	}
	addresses := map[string]string{roleAgentA: "10.203.0.11", roleRelay: "10.203.0.12", roleAgentB: "10.203.0.13"}
	for role, config := range configs {
		config.Self.Node.Endpoint = addresses[role] + ":9443"
		config.AllowedCIDRs = []string{"10.203.0.11/32", "10.203.0.12/32", "10.203.0.13/32"}
		config.Target.Endpoint = vmTaskEndpoint
		config.StateDir = "/var/lib/asb-vm"
		config.VMQualification = true
		configs[role] = config
	}
	for role, config := range configs {
		for index, remote := range config.Peers {
			config.Peers[index] = configs[remote.Role].Self
		}
		if err := writeJSONFile(filepath.Join(root, role, "config.json"), config); err != nil {
			return err
		}
	}
	return nil
}

type vmCommand struct {
	ID     uint64 `json:"id"`
	Action string `json:"action"`
}

type vmObservation struct {
	ID         uint64               `json:"id"`
	Action     string               `json:"action"`
	Passed     bool                 `json:"passed"`
	Role       string               `json:"role"`
	PID        int                  `json:"pid"`
	BootID     string               `json:"boot_id"`
	MachineID  string               `json:"machine_id_sha256"`
	Records    int                  `json:"records"`
	Tombstones int                  `json:"tombstones"`
	Peers      int                  `json:"peers"`
	StateHash  string               `json:"state_sha256"`
	Task       *interactionEvidence `json:"task,omitempty"`
}

// The harness controls this private local directory; no command endpoint is
// exposed over a network. Each allowed command is bounded and acknowledgements
// contain no role configuration, credentials or payload logs.
func runVMControl(ctx context.Context, node *peer.Node, config processConfig, directory string) error {
	if runtime.GOOS != vmOS || !filepath.IsAbs(directory) {
		return errors.New("VM control requires Linux and an absolute private control directory")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-node.Errors():
			return err
		case <-ticker.C:
		}
		command, err := readVMCommand(filepath.Join(directory, "request.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if command.ID <= last {
			continue
		}
		last = command.ID
		operationCtx, operationCancel := context.WithTimeout(ctx, 15*time.Second)
		observation, operationErr := executeVMCommand(operationCtx, node, config, command)
		operationCancel()
		if err := writeJSONFile(filepath.Join(directory, "response.json"), observation); err != nil {
			return err
		}
		if operationErr != nil {
			return errors.New("VM qualification command failed")
		}
		if command.Action == vmStopCommand {
			return nil
		}
	}
}

func readVMCommand(path string) (vmCommand, error) {
	var command vmCommand
	file, err := os.Open(path)
	if err != nil {
		return command, err
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || strictjson.ValidateDocument(raw, 4096) != nil {
		return command, errors.New("invalid VM command document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || command.ID == 0 || command.ID > 256 {
		return command, errors.New("invalid VM command identity")
	}
	switch command.Action {
	case "status", "task", "gossip", "withdraw", vmStopCommand:
		return command, nil
	default:
		return command, errors.New("unsupported VM command")
	}
}

func executeVMCommand(ctx context.Context, node *peer.Node, config processConfig, command vmCommand) (vmObservation, error) {
	observation := vmObservation{ID: command.ID, Action: command.Action, Role: config.Self.Role, PID: os.Getpid()}
	var err error
	switch command.Action {
	case "task":
		if config.Self.Role != roleAgentA {
			return observation, errors.New("task command requires Agent A")
		}
		observation.Task, err = vmTask(ctx, node, config)
	case "gossip":
		err = node.GossipOnce(ctx)
	case "withdraw":
		if config.Self.Role != roleAgentB {
			return observation, errors.New("withdraw command requires Agent B")
		}
		_, err = node.Deregister(config.Target.Name, 2)
	case "status", vmStopCommand:
	default:
		return observation, errors.New("unsupported VM command")
	}
	if err != nil {
		return observation, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return observation, err
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(bytes.TrimSpace(machine)) != 32 {
		return observation, errors.New("missing guest machine identity")
	}
	observation.BootID = strings.TrimSpace(string(boot))
	machineHash := sha256.Sum256(bytes.TrimSpace(machine))
	observation.MachineID = hex.EncodeToString(machineHash[:])
	state, err := os.ReadFile(discoveryStatePath(config))
	if err != nil {
		return observation, err
	}
	stateHash := sha256.Sum256(state)
	observation.StateHash = hex.EncodeToString(stateHash[:])
	observation.Records, observation.Tombstones, observation.Peers = node.Counts()
	observation.Passed = true
	return observation, nil
}

func vmTask(ctx context.Context, node *peer.Node, config processConfig) (*interactionEvidence, error) {
	discovered, err := discoverTaskTarget(ctx, node, config)
	if err != nil {
		return nil, err
	}
	request := taskRequest{TaskID: taskID, Values: []int64{7, 11, 13}}
	_, denied, err := sendTask(ctx, config, discovered.Endpoint, request, false)
	if err != nil || denied != http.StatusUnauthorized {
		return nil, errors.New("missing-proof task was not rejected")
	}
	result, status, err := sendTask(ctx, config, discovered.Endpoint, request, true)
	if err != nil || status != http.StatusOK || result.Sum != 31 || result.Executions != 1 || result.AgentID != roleAgentB || result.Caller != roleAgentA {
		return nil, errors.New("authenticated VM task failed")
	}
	// Numeric PIDs may coincide across separate kernels. The host harness checks
	// guest boot identities instead; the ordinary local demo keeps its PID check.
	return &interactionEvidence{
		SchemaVersion: 1, Passed: true, NetworkScope: "three Linux guests on one host; topology verified separately",
		Profile: "ASB software-only Direct-Agent v1", Discovery: discovered,
		Request: request, Result: result, WithoutProofStatus: denied, AuthorizedStatus: status,
		ResponseAuthentication: "same pinned TLS connection; no separate reverse-direction ASB proof", CreatedAt: time.Now().UTC(),
	}, nil
}
