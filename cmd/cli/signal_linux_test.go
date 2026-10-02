// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLIInterruptsStalledConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connected := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			connected <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcessHelper$", "--", "algo", "unused", "unused")
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "AGENT_") || strings.HasPrefix(entry, "MANAGER_") || strings.HasPrefix(entry, "HOME=") || strings.HasPrefix(entry, "ASB_CLI_PROCESS_TEST=") {
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "HOME="+t.TempDir(), "ASB_CLI_PROCESS_TEST=1", "AGENT_GRPC_URL="+listener.Addr().String(), "AGENT_GRPC_TIMEOUT=60s")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	select {
	case conn := <-connected:
		defer conn.Close()
	case <-ctx.Done():
		t.Fatal("CLI did not attempt the health connection")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	select {
	case err := <-finished:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Fatalf("interrupted CLI error = %v, want exit 2", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI waited for the health timeout after SIGTERM")
	}
}
