// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/production"
)

const (
	vmStageConfig     = "config"
	vmStageDiscovery  = "discovery"
	vmStageTaskServer = "task-server"
	vmStageReady      = "ready"
	vmStageControl    = "control"
)

type vmStageDiagnostic struct {
	Role  string `json:"role"`
	PID   int    `json:"pid"`
	Stage string `json:"stage"`
}

type vmStopDiagnostic struct {
	vmStageDiagnostic
	Passed   bool   `json:"passed"`
	Category string `json:"category"`
}

func writeVMStage(directory, role, stage string) error {
	if directory == "" {
		return nil
	}
	return writeJSONFile(filepath.Join(directory, "stage.json"), vmStageDiagnostic{Role: role, PID: os.Getpid(), Stage: stage})
}

func vmStopped(role, stage string, err error) vmStopDiagnostic {
	return vmStopDiagnostic{
		vmStageDiagnostic: vmStageDiagnostic{Role: role, PID: os.Getpid(), Stage: stage},
		Passed:            err == nil, Category: vmErrorCategory(err),
	}
}

// Emit only fixed categories. Error strings can contain paths, payloads or
// credentials and must never enter the uploaded lab diagnostics.
func vmErrorCategory(err error) string {
	if err == nil {
		return "none"
	}
	for _, category := range []struct {
		err  error
		name string
	}{
		{syscall.EADDRNOTAVAIL, "address-not-available"},
		{syscall.EADDRINUSE, "address-in-use"},
		{os.ErrPermission, "permission"},
		{os.ErrNotExist, "not-found"},
		{context.DeadlineExceeded, "deadline"},
		{context.Canceled, "cancelled"},
		{production.ErrMissingTrustSource, "missing-trust-source"},
		{production.ErrTrustSourceUnavailable, "trust-source-unavailable"},
		{production.ErrMissingReplayCache, "missing-replay-cache"},
		{production.ErrMissingPolicy, "missing-policy"},
		{production.ErrInvalidAuthority, "invalid-authority"},
		{production.ErrInvalidTokenLifetime, "invalid-token-lifetime"},
		{production.ErrMissingContext, "missing-context"},
		{production.ErrInvalidCurrentTime, "invalid-current-time"},
	} {
		if errors.Is(err, category.err) {
			return category.name
		}
	}
	return "other"
}
