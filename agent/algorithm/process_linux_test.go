//go:build linux

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package algorithm

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	nestedDescendantMode          = "nested"
	nestedNamespaceDeniedExitCode = 99
)

func TestConfigureCommandRequiresAtomicNamespaces(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	ConfigureCommand(cmd)
	attr := cmd.SysProcAttr
	if attr.Cloneflags != syscall.CLONE_NEWUSER|syscall.CLONE_NEWPID {
		t.Fatalf("clone flags = %#x", attr.Cloneflags)
	}
	if len(attr.UidMappings) != 1 || attr.UidMappings[0] != (syscall.SysProcIDMap{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}) {
		t.Fatalf("UID mappings = %#v", attr.UidMappings)
	}
	if len(attr.GidMappings) != 1 || attr.GidMappings[0] != (syscall.SysProcIDMap{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}) || attr.GidMappingsEnableSetgroups {
		t.Fatalf("GID mappings = %#v, setgroups = %v", attr.GidMappings, attr.GidMappingsEnableSetgroups)
	}
}

func TestContainedCommandSuccessAndLaunchFailure(t *testing.T) {
	cmd := processHelperCommand("control")
	var output bytes.Buffer
	cmd.Stdout = &output
	// StartCommand enforces the boundary even without ConfigureCommand.
	if err := StartCommand(cmd); err != nil {
		t.Fatalf("Linux runtime must allow computation namespaces: %v", err)
	}
	if err := WaitCommand(cmd); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != fmt.Sprintf("1 %d %d", os.Geteuid(), os.Getegid()) {
		t.Fatalf("command identity = %q", output.String())
	}
	if err := StopCommand(cmd); err != nil {
		t.Fatalf("Stop after Wait: %v", err)
	}
	missing := exec.Command(filepath.Join(t.TempDir(), "missing"))
	if err := StartCommand(missing); err == nil {
		t.Fatal("missing executable was accepted")
	}
	if missing.Process != nil {
		t.Fatal("failed launch retained a process")
	}
	if err := StopCommand(missing); err != nil {
		t.Fatal(err)
	}
}

func TestContainedCommandDescendantLifetime(t *testing.T) {
	requireNested := os.Getenv("ASB_REQUIRE_NESTED_PID_NAMESPACE") == "1"
	if requireNested && os.Geteuid() != 0 {
		t.Fatal("required nested PID-namespace qualification must run as root")
	}
	for _, descendant := range []string{"ordinary", "detached", nestedDescendantMode} {
		for _, outcome := range []string{"success", "error", "stop"} {
			t.Run(descendant+"/"+outcome, func(t *testing.T) {
				dir := t.TempDir()
				cmd := processHelperCommand("parent", dir, descendant, outcome)
				cmd.Stderr = os.Stderr
				if err := StartCommand(cmd); err != nil {
					t.Fatalf("Linux runtime must allow computation namespaces: %v", err)
				}
				done := make(chan error, 1)
				go func() { done <- WaitCommand(cmd) }()
				t.Cleanup(func() {
					_ = StopCommand(cmd)
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("namespace teardown did not complete")
					}
				})
				waitForProcessFile(t, filepath.Join(dir, "ready"))
				if denial, err := os.ReadFile(filepath.Join(dir, "nested-denied")); err == nil {
					if descendant != nestedDescendantMode || string(denial) != "EPERM" {
						t.Fatalf("unexpected namespace denial marker: %q", denial)
					}
					select {
					case err := <-done:
						done <- err
						var exitErr *exec.ExitError
						if !errors.As(err, &exitErr) || exitErr.ExitCode() != nestedNamespaceDeniedExitCode {
							t.Fatalf("denied nested launch = %v, want exit status %d", err, nestedNamespaceDeniedExitCode)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("denied nested launch did not exit")
					}
					if _, err := os.Stat(filepath.Join(dir, "descendant")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("descendant executed after denied nested launch: %v", err)
					}
					if requireNested {
						t.Fatal("required nested PID-namespace creation was denied")
					}
					t.Log("nested namespace creation denied with EPERM before descendant execution; cleanup coverage requires the privileged qualification gate")
					return
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				record, err := os.ReadFile(filepath.Join(dir, "descendant"))
				if err != nil {
					t.Fatal(err)
				}
				pid, err := strconv.Atoi(string(record))
				if err != nil || pid <= 1 {
					t.Fatalf("invalid host PID %q: %v", record, err)
				}
				if err := syscall.Kill(pid, 0); err != nil {
					t.Fatalf("descendant was not alive before teardown: %v", err)
				}
				if outcome == "stop" {
					if err := StopCommand(cmd); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				select {
				case err := <-done:
					// Keep the cleanup receiver ready after inspecting the result.
					done <- err
					if (err == nil) != (outcome == "success") {
						t.Fatalf("WaitCommand = %v for %s", err, outcome)
					}
					if outcome == "error" {
						var exitErr *exec.ExitError
						if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
							t.Fatalf("WaitCommand = %v, want exit status 23", err)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("WaitCommand did not complete descendant teardown")
				}
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatalf("descendant %d survived completed WaitCommand: %v", pid, err)
				}
			})
		}
	}
}

func processHelperCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestContainedProcessHelper$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "ASB_PROCESS_HELPER=1")
	return cmd
}

func waitForProcessFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not create %s", filepath.Base(path))
}

// TestContainedProcessHelper runs only in a bounded child process. It uses no
// external runtimes, so these regressions can run on a clean Linux runner.
func TestContainedProcessHelper(t *testing.T) {
	if os.Getenv("ASB_PROCESS_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(90)
	}
	args = args[1:]
	if args[0] == "control" {
		fmt.Printf("%d %d %d\n", os.Getpid(), os.Geteuid(), os.Getegid())
		os.Exit(0)
	}
	if args[0] == "leaf" {
		pid, err := os.Readlink("/proc/self")
		if err != nil || os.WriteFile(filepath.Join(args[1], "descendant"), []byte(pid), 0o600) != nil {
			os.Exit(91)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if args[0] == nestedDescendantMode {
		if os.Getpid() != 1 {
			os.Exit(98)
		}
		leaf := processHelperCommand("leaf", args[1])
		leaf.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := leaf.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(92)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if args[0] != "parent" || os.Getpid() != 1 {
		os.Exit(93)
	}
	dir, descendant, outcome := args[1], args[2], args[3]
	child := processHelperCommand("leaf", dir)
	if descendant == "detached" {
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
	if descendant == nestedDescendantMode {
		child = processHelperCommand(nestedDescendantMode, dir)
		// Create both namespaces atomically without new ID mappings. Go's
		// mapping writer uses the clone-returned PID, which is relative to
		// this namespace and cannot address the inherited host /proc mount.
		// The child retains its kernel credentials for ordinary file access.
		child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID}
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		if descendant == nestedDescendantMode && errors.Is(err, syscall.EPERM) {
			if err := os.WriteFile(filepath.Join(dir, "nested-denied"), []byte("EPERM"), 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(94)
			}
			if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(94)
			}
			os.Exit(nestedNamespaceDeniedExitCode)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(94)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "descendant")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(95)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0o600); err != nil {
		os.Exit(96)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			if outcome == "error" {
				os.Exit(23)
			}
			os.Exit(0)
		}
		if time.Now().After(deadline) {
			os.Exit(97)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
