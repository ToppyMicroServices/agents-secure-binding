// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIProcessHelper(t *testing.T) {
	if os.Getenv("ASB_CLI_PROCESS_TEST") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing subprocess arguments")
}

func TestCLIExitStatus(t *testing.T) {
	directory := t.TempDir()
	fixture := filepath.Join(directory, "input.txt")
	if err := os.WriteFile(fixture, []byte("test input"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
		env  []string
		code int
		text string
	}{
		{"local checksum without agent", []string{"checksum", fixture}, []string{"AGENT_GRPC_URL=remote.invalid:9999"}, 0, "Hash of file:"},
		{"missing local file", []string{"checksum", fixture + ".absent"}, nil, 1, "Error computing hash:"},
		{"invalid command", []string{"invalid-command"}, nil, 1, "unknown command"},
		{"invalid environment", []string{"--help"}, []string{"AGENT_GRPC_TIMEOUT=invalid"}, 1, "failed to load"},
		{"agent setup failure", []string{"algo", fixture, fixture}, []string{"AGENT_GRPC_URL=remote.invalid:9999"}, 1, "Failed to connect to agent:"},
		{"help without agent", []string{"--help"}, []string{"AGENT_GRPC_URL=remote.invalid:9999"}, 0, "Usage:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIProcessHelper$", "--"}, test.args...)
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			for _, entry := range os.Environ() {
				if strings.HasPrefix(entry, "AGENT_") || strings.HasPrefix(entry, "MANAGER_") || strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "ASB_CLI_PROCESS_TEST=") {
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "HOME="+directory, "ASB_CLI_PROCESS_TEST=1", "NO_COLOR=1")
			cmd.Env = append(cmd.Env, test.env...)
			output, err := cmd.CombinedOutput()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil || code != test.code || !bytes.Contains(output, []byte(test.text)) {
				t.Fatalf("exit=%d, error=%v, context=%v, output=%s", code, err, ctx.Err(), output)
			}
		})
	}
}
