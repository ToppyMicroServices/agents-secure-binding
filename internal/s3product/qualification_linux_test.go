//go:build linux && awsiam_live

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package s3product

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/asbbinding"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/awsiam"
)

// This lab uses fabricated identity and a local CLI stub that never calls AWS.
// Real OIDC/S3 acceptance remains the separate explicit live gate.
func offlineProduct(t *testing.T) (*liveProduct, lp.Solution) {
	t.Helper()
	binary := os.Getenv("ASB_QA_BINARY")
	if binary == "" {
		t.Skip("requires explicitly built Linux product")
	}
	h := newLiveProduct(t, t.Context(), binary)
	resource := "arn:aws:s3:::asb-test-bucket/read.txt"
	spec := awsiam.Specification{Schema: awsiam.Schema, RoleARN: "arn:aws:iam::111122223333:role/asb-reader", Region: "eu-west-1", CredentialProfile: "oidc", Objects: []awsiam.Object{{ARN: resource, Cost: 1, OwnerAccount: "111122223333"}}, Grants: []awsiam.GrantPolicy{{ID: "read", Policy: json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":["arn:aws:s3:::asb-test-bucket/read.txt"]}]}`)}}, Required: []string{resource}, Allowed: []string{resource}, MaxResponseBytes: 1024}
	raw := liveJSON(t, spec)
	profile, err := awsiam.Compile(raw)
	if err != nil {
		t.Fatal(err)
	}
	solution, err := lp.Solve(t.Context(), profile.Problem(), 2)
	if err != nil {
		t.Fatal(err)
	}
	action := lp.Action{Operation: awsiam.Operation, Resource: resource, Arguments: liveJSON(t, awsiam.Arguments{ProfileDigest: profile.Digest(), ExpectedBucketOwner: "111122223333", IfMatch: `"0123456789abcdef0123456789abcdef"`, RangeStart: 0, RangeEnd: 3})}
	h.config.ProfileFile = h.write(t, "profile.json", raw)
	h.config.WebIdentityTokenFile = h.write(t, "token", []byte("header.initial.signature"))
	h.config.AWSCLI = h.write(t, "fake-aws", []byte("#!/bin/sh\numask 077\necho call >> \"$0.calls\"\npwd > \"$0.session\"\n/bin/sleep 2\nprintf '%s' '{\"Code\":\"AccessDenied\",\"Message\":\"private-fixture-do-not-log\"}' >&2\nexit 1\n"))
	if err = os.Chmod(h.config.AWSCLI, 0o700); err != nil {
		t.Fatal(err)
	}
	var initial lp.SQLiteStatus
	h.admin(t, &initial, "init-store", "--directory", h.config.StoreDirectory)
	h.configure(t, initial.Namespace, action, solution.ProblemDigest)
	return h, solution
}

func executeAsync(t *testing.T, h *liveProduct, capability lp.Capability) <-chan int {
	t.Helper()
	c := h.challenge(t, "execute", h.operation)
	input := asbbinding.HTTPExecuteRequest{ChallengeID: c.ChallengeID, Operation: h.operation, Proof: h.proof(t, c, h.operation), Capability: capability}
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, "https://"+h.config.Listen+"/execute", bytes.NewReader(liveJSON(t, input)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	done := make(chan int, 1)
	go func() {
		response, err := h.client.Do(req)
		if err != nil {
			done <- 0
			return
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		done <- response.StatusCode
	}()
	return done
}

func awaitCLI(t *testing.T, h *liveProduct) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if _, err := os.Stat(h.config.AWSCLI + ".calls"); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("authorized fixture never reached STS boundary")
}

func TestOfflineProductActiveStopAndCrash(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("kill=%t", force), func(t *testing.T) {
			h, solution := offlineProduct(t)
			stop := h.start(t)
			capability := h.authorize(t, solution)
			done := executeAsync(t, h, capability)
			awaitCLI(t, h)
			start := time.Now()
			if force {
				h.kill()
			} else {
				stop()
			}
			status := <-done
			elapsed := time.Since(start)
			if !force && (status != http.StatusConflict || elapsed < time.Second || elapsed > 6*time.Second) {
				t.Fatalf("maintenance canceled instead of draining: status=%d duration=%s", status, elapsed)
			}
			var state lp.SQLiteStatus
			h.admin(t, &state, "status", "--directory", h.config.StoreDirectory)
			if state.Uncertain != 1 {
				t.Fatal("lost uncertain execution")
			}
			// The original exact authority remains consumed across restart.
			stop = h.start(t)
			if status = <-executeAsync(t, h, capability); status != http.StatusConflict {
				t.Fatal("uncertain operation was retried")
			}
			stop()
			calls, err := os.ReadFile(h.config.AWSCLI + ".calls")
			if err != nil || bytes.Count(calls, []byte("call\n")) != 1 {
				t.Fatal("unexpected external invocation count")
			}
			// A bare SIGKILL can retain private temporary identity material. The
			// supported systemd run below supplies PrivateTmp lifecycle cleanup.
			if raw, err := os.ReadFile(h.config.AWSCLI + ".session"); err == nil {
				directory := strings.TrimSpace(string(raw))
				_, retained := os.Stat(directory)
				t.Logf("kill=%t stopped_ms=%d temporary_retained=%t calls=1 uncertain=1", force, elapsed.Milliseconds(), retained == nil)
				if filepath.Dir(directory) == os.TempDir() && strings.HasPrefix(filepath.Base(directory), "asb-aws-session-") {
					_ = os.RemoveAll(directory)
				}
			}
		})
	}
}

func processResources(t *testing.T, pid int) (rssKB int64, fds int) {
	t.Helper()
	directory := filepath.Join("/proc", strconv.Itoa(pid))
	raw, err := os.ReadFile(filepath.Join(directory, "status"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" {
			rssKB, err = strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(directory, "fd"))
	if err != nil {
		t.Fatal(err)
	}
	return rssKB, len(entries)
}

func systemctl(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl %v: %s %v", args, out, err)
	}
	return strings.TrimSpace(string(out))
}

func cleanupSystemdUnit(t *testing.T, unit string) {
	t.Helper()
	t.Cleanup(func() {
		// testing cancels t.Context before running cleanup functions.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 70*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "systemctl", "disable", "--now", unit).CombinedOutput()
		if err != nil {
			t.Errorf("cleanup systemd %s: %s %v", unit, out, err)
		}
	})
}

func prepareSystemdProduct(t *testing.T, h *liveProduct) {
	t.Helper()
	if os.Geteuid() != 0 || !strings.HasPrefix(h.directory, "/var/lib/asb-s3/") {
		t.Fatal("systemd gate requires disposable root runner and state-directory fixtures")
	}
	h.write(t, "config.json", liveJSON(t, h.config))
	if err := os.MkdirAll("/etc/asb-s3", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/asb-s3/config.json", liveJSON(t, h.config), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "chown", "-R", "asb-s3:asb-s3", filepath.Dir(h.directory), "/etc/asb-s3").CombinedOutput(); err != nil {
		t.Fatalf("fixture ownership: %s %v", out, err)
	}
	source := h.write(t, "token-source", []byte("header.projected.signature"))
	projector := "[Unit]\nDescription=Disposable ASB QA token projector\n[Service]\nType=oneshot\nUser=asb-s3\nGroup=asb-s3\nRemainAfterExit=yes\nExecStart=/bin/sh -c 'umask 077; cp " + source + " " + h.config.WebIdentityTokenFile + ".next && mv " + h.config.WebIdentityTokenFile + ".next " + h.config.WebIdentityTokenFile + "'\n[Install]\nWantedBy=multi-user.target\n"
	if err := os.WriteFile("/etc/systemd/system/asb-s3-qa-projector.service", []byte(projector), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/etc/systemd/system/asb-s3.service.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/systemd/system/asb-s3.service.d/qa-projector.conf", []byte("[Unit]\nRequires=asb-s3-qa-projector.service\nAfter=asb-s3-qa-projector.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "chown", "asb-s3:asb-s3", source).CombinedOutput(); err != nil {
		t.Fatalf("source ownership: %s %v", out, err)
	}
	h.transport = &http.Transport{TLSClientConfig: h.clientTLS.Clone(), MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, ForceAttemptHTTP2: false}
	h.client = &http.Client{Transport: h.transport, Timeout: 40 * time.Second}
	t.Cleanup(h.transport.CloseIdleConnections)
}

func TestOfflineSystemdLifecycle(t *testing.T) {
	if os.Getenv("ASB_QA_SYSTEMD") != "1" {
		t.Skip("disposable systemd runner required")
	}
	h, solution := offlineProduct(t)
	original := h.mandate
	emergency, renewed := original, original
	emergency.ID += "-emergency"
	renewed.ID += "-renewed"
	h.config.MandatesFile = h.write(t, "mandates.json", liveJSON(t, []lp.Mandate{original, emergency, renewed}))
	prepareSystemdProduct(t, h)
	systemctl(t, "daemon-reload")
	cleanupSystemdUnit(t, "asb-s3-qa-projector.service")
	systemctl(t, "enable", "asb-s3-qa-projector.service")
	cleanupSystemdUnit(t, "asb-s3.service")
	systemctl(t, "enable", "--now", "asb-s3.service")
	if systemctl(t, "is-enabled", "asb-s3.service") != "enabled" {
		t.Fatal("unit not enabled")
	}
	// Wait for real authenticated readiness, not just Type=simple activation.
	waitProduct(t, h)
	capability := h.authorize(t, solution)
	done := executeAsync(t, h, capability)
	awaitCLI(t, h)
	start := time.Now()
	systemctl(t, "stop", "asb-s3.service")
	drain := time.Since(start)
	if status := <-done; status != http.StatusConflict || time.Since(start) < time.Second {
		t.Fatal("systemd interrupted STS rather than draining")
	}
	awaitSystemdSTSDiagnostic(t, t.Context(), h.operation.ID, stsDeniedCode)
	if systemctl(t, "show", "asb-s3", "--property=MainPID", "--value") != "0" {
		t.Fatal("main process retained after stop")
	}
	systemctl(t, "start", "asb-s3.service")
	waitProduct(t, h)
	if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
		t.Fatal("unit restart replayed unknown operation")
	}
	// Issue a distinct approved operation for immediate emergency fencing.
	h.mandate, h.operation.MandateID, h.operation.ID = emergency, emergency.ID, h.config.Namespace+"/emergency"
	capability = h.authorize(t, solution)
	if err := os.Remove(h.config.AWSCLI + ".calls"); err != nil {
		t.Fatal(err)
	}
	done = executeAsync(t, h, capability)
	awaitCLI(t, h)
	before, err := filepath.Glob("/tmp/systemd-private-*-asb-s3.service-*/tmp/asb-aws-session-*")
	if err != nil || len(before) == 0 {
		t.Fatal("PrivateTmp fixture was not observed")
	}
	systemctl(t, "stop", "--no-block", "asb-s3.service")
	systemctl(t, "kill", "--kill-whom=all", "--signal=SIGKILL", "asb-s3.service")
	<-done
	// Wait through RestartSec=5 to detect accidental automatic reactivation.
	time.Sleep(6 * time.Second)
	if systemctl(t, "show", "asb-s3", "--property=MainPID", "--value") != "0" {
		t.Fatal("emergency stop restarted the authority")
	}
	for _, path := range before {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("PrivateTmp retained identity after stop")
		}
	}
	if raw, err := os.ReadFile("/sys/fs/cgroup/system.slice/asb-s3.service/cgroup.procs"); err == nil && len(bytes.TrimSpace(raw)) != 0 {
		t.Fatal("unit retained descendants")
	}
	// A trusted projector atomically renews identity; the old operation stays
	// uncertain, while a new mandate can progress to the adapter again.
	if err = os.WriteFile(filepath.Join(h.directory, "token-source"), []byte("header.renewed.signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	systemctl(t, "restart", "asb-s3-qa-projector.service")
	if raw, err := os.ReadFile(h.config.WebIdentityTokenFile); err != nil || string(raw) != "header.renewed.signature" {
		t.Fatal("projector did not renew identity")
	}
	systemctl(t, "reset-failed", "asb-s3.service")
	systemctl(t, "start", "asb-s3.service")
	waitProduct(t, h)
	if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
		t.Fatal("emergency record was redispatched")
	}
	h.mandate, h.operation.MandateID, h.operation.ID = renewed, renewed.ID, h.config.Namespace+"/renewed"
	capability = h.authorize(t, solution)
	if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
		t.Fatal("new authority failed to reach fixture adapter")
	}
	systemctl(t, "stop", "asb-s3.service")
	var state lp.SQLiteStatus
	h.admin(t, &state, "status", "--directory", h.config.StoreDirectory)
	if state.Uncertain != 3 {
		t.Fatal("identity renewal lost uncertain history")
	}
	t.Logf("systemd_drain_ms=%d enabled=true authenticated_asb=true emergency_fenced=true private_tmp_cleaned=true projector_renewed=true uncertain_records=3", drain.Milliseconds())
}

func waitProduct(t *testing.T, h *liveProduct) {
	t.Helper()
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, "https://"+h.config.Listen+"/", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		response, err := h.client.Do(req)
		if err == nil {
			_ = response.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("authenticated TLS service did not become ready")
}

func TestOfflineProductResourceQualification(t *testing.T) {
	h, _ := offlineProduct(t)
	stop := h.start(t)
	defer stop()
	baselineRSS, baselineFD := processResources(t, h.pid)
	maxRSS, maxFD := baselineRSS, baselineFD
	started := time.Now()
	for round := range 3 {
		connections := make([]net.Conn, 0, 128)
		for range 128 {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", h.config.Listen)
			if err != nil {
				break
			} // A full kernel backlog may reject/delay a client.
			connections = append(connections, c)
		}
		rss, fd := processResources(t, h.pid)
		maxRSS, maxFD = max(maxRSS, rss), max(maxFD, fd)
		for _, c := range connections {
			_ = c.Close()
		}
		until := time.Now().Add(8 * time.Second)
		for time.Now().Before(until) {
			_, fd = processResources(t, h.pid)
			if fd <= baselineFD+2 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if fd > baselineFD+2 {
			t.Fatal("descriptors did not recover within 8s")
		}
		t.Logf("connection_cycle=%d clients=%d recovered_fd=%d", round, len(connections), fd)
	}
	finalRSS, finalFD := processResources(t, h.pid)
	if maxFD > baselineFD+66 || maxRSS > baselineRSS+128*1024 || finalRSS > baselineRSS+64*1024 {
		t.Fatal("bounded resource lab threshold exceeded")
	}
	t.Logf("rss_baseline_kb=%d rss_sampled_max_kb=%d rss_final_kb=%d fd_baseline=%d fd_peak=%d fd_final=%d duration_ms=%d", baselineRSS, maxRSS, finalRSS, baselineFD, maxFD, finalFD, time.Since(started).Milliseconds())
}

func TestOfflineProductMaximumConfiguration(t *testing.T) {
	if os.Getenv("ASB_QA_CAPACITY") != "1" {
		t.Skip("opt-in maximum configuration qualification")
	}
	h, _ := offlineProduct(t)
	var spec awsiam.Specification
	raw, err := os.ReadFile(h.config.ProfileFile)
	if err != nil || json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid fixture")
	}
	spec.Objects, spec.Grants, spec.Allowed = nil, nil, nil
	for i := range lp.MaxPermissions {
		arn := fmt.Sprintf("arn:aws:s3:::asb-test-bucket/k%03d", i)
		spec.Objects = append(spec.Objects, awsiam.Object{ARN: arn, Cost: 1, OwnerAccount: "111122223333"})
		spec.Allowed = append(spec.Allowed, arn)
	}
	spec.Required = spec.Allowed[:1]
	for i := range lp.MaxGrants {
		policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Action": awsiam.Operation, "Resource": spec.Allowed}}}
		spec.Grants = append(spec.Grants, awsiam.GrantPolicy{ID: fmt.Sprintf("grant-%d", i), Policy: liveJSON(t, policy)})
	}
	raw = liveJSON(t, spec)
	profile, err := awsiam.Compile(raw)
	if err != nil {
		t.Fatal("maximum valid profile rejected", err)
	}
	h.config.ProfileFile = h.write(t, "maximum-profile.json", raw)
	problem, err := lp.DigestProblem(profile.Problem())
	if err != nil {
		t.Fatal(err)
	}
	action := lp.Action{Operation: awsiam.Operation, Resource: spec.Required[0], Arguments: liveJSON(t, awsiam.Arguments{ProfileDigest: profile.Digest(), ExpectedBucketOwner: "111122223333", IfMatch: `"0123456789abcdef0123456789abcdef"`, RangeStart: 0, RangeEnd: 3})}
	h.configure(t, h.config.Namespace, action, problem)
	mandates := make([]lp.Mandate, 4096)
	for i := range mandates {
		mandates[i] = h.mandate
		mandates[i].ID = fmt.Sprintf("%s/maximum-%d", h.config.Namespace, i)
		mandates[i].ProblemDigest = problem
	}
	h.config.MandatesFile = h.write(t, "maximum-mandates.json", liveJSON(t, mandates))
	started := time.Now()
	stop := h.startWithin(t, 120*time.Second)
	defer stop()
	rss, fd := processResources(t, h.pid)
	if rss > 3*1024*1024 || fd > 64 {
		t.Fatal("maximum configuration exceeds lab 3GiB/64 idle-fd budget")
	}
	t.Logf("mandates=4096 permissions=256 grants=20 startup_ms=%d rss_kb=%d fd=%d profile_bytes=%d", time.Since(started).Milliseconds(), rss, fd, len(raw))
}

func TestOfflineProductRestoreSignal(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			h, _ := offlineProduct(t)
			source := filepath.Join(t.TempDir(), "large-sparse-fixture")
			file, err := os.OpenFile(source, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err = file.Truncate(1 << 30); err != nil {
				t.Fatal(err)
			}
			_ = file.Close()
			directory := filepath.Join(t.TempDir(), "interrupted")
			cmd := h.command("restore", "--input", source, "--directory", directory, "--sha256", strings.Repeat("0", 64))
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			until := time.Now().Add(5 * time.Second)
			observed := false
			for time.Now().Before(until) {
				if info, err := os.Stat(filepath.Join(directory, "journal.sqlite")); err == nil && info.Size() > 0 && info.Size() < 1<<30 {
					observed = true
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !observed {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("copy window not observed")
			}
			start := time.Now()
			if err = cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			if err = cmd.Wait(); err == nil || time.Since(start) > 3*time.Second {
				t.Fatal("cancel did not stop copy within 3s")
			}
			info, err := os.Stat(filepath.Join(directory, "journal.sqlite"))
			if err != nil || info.Size() >= 1<<30 {
				t.Fatal("copy completed despite cancellation")
			}
			if store, err := lp.OpenSQLiteStore(t.Context(), directory); err == nil {
				_ = store.Close()
				t.Fatal("partial restore executable")
			}
			t.Logf("signal=%s stop_ms=%d copied_bytes=%d source_bytes=1073741824 pending_rejected=true", sig, time.Since(start).Milliseconds(), info.Size())
		})
	}
}

func TestOfflineSystemdBoot(t *testing.T) {
	root := os.Getenv("ASB_QA_ROOTFS")
	if root == "" {
		t.Skip("requires disposable systemd-nspawn rootfs")
	}
	h, solution := offlineProduct(t)
	prepareSystemdProduct(t, h)
	for _, relative := range []string{"etc/systemd/system/asb-s3-qa-projector.service", "etc/systemd/system/asb-s3.service.d/qa-projector.conf"} {
		raw, err := os.ReadFile("/" + relative)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(filepath.Dir(filepath.Join(root, relative)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, relative), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.CommandContext(t.Context(), "systemctl", "--root="+root, "enable", "asb-s3-qa-projector.service").CombinedOutput(); err != nil {
		t.Fatalf("enable projector: %s %v", out, err)
	}
	var capability lp.Capability
	for boot := range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		cmd := exec.CommandContext(ctx, "systemd-nspawn", "--quiet", "--directory="+root, "--boot", "--machine=asb-s3-qa", "--register=yes", "--console=pipe", "--resolv-conf=off", "--bind=/var/lib/asb-s3", "--bind-ro=/etc/asb-s3")
		var diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr = &diagnostics, &diagnostics
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		// A failing test must still reap the disposable container supervisor.
		finished := false
		t.Cleanup(func() {
			if !finished {
				cleanup, stopCleanup := context.WithTimeout(context.WithoutCancel(t.Context()), 15*time.Second)
				_ = exec.CommandContext(cleanup, "machinectl", "terminate", "asb-s3-qa").Run()
				stopCleanup()
				cancel()
				_ = cmd.Wait()
				t.Logf("disposable container diagnostics: %s", diagnostics.String())
			}
		})
		waitProduct(t, h)
		if boot == 0 {
			capability = h.authorize(t, solution)
		}
		if status := <-executeAsync(t, h, capability); status != http.StatusConflict {
			t.Fatal("booted service did not preserve ASB/uncertainty contract")
		}
		if out, err := exec.CommandContext(ctx, "machinectl", "poweroff", "asb-s3-qa").CombinedOutput(); err != nil {
			t.Fatalf("container shutdown: %s %v", out, err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("container exited unexpectedly: %v %s", err, diagnostics.String())
		}
		finished = true
		cancel()
		h.transport.CloseIdleConnections()
		t.Logf("container_boot=%d real_systemd=true authenticated_asb=true", boot+1)
	}
	calls, err := os.ReadFile(h.config.AWSCLI + ".calls")
	if err != nil || bytes.Count(calls, []byte("call\n")) != 1 {
		t.Fatal("container reboot redispatched consumed authority")
	}
	t.Log("container_boots=2 physical_host_reboot=not_tested real_aws=false repeat_dispatches=0")
}

func TestOfflineProductIdentityRotation(t *testing.T) {
	old, solution := offlineProduct(t)
	stop := old.start(t)
	capability := old.authorize(t, solution)
	if status := <-executeAsync(t, old, capability); status != http.StatusConflict {
		t.Fatal("expected fixture STS denial")
	}
	stop()
	current, _ := offlineProduct(t)
	current.config.StoreDirectory = old.config.StoreDirectory
	current.config.MandatesFile = old.config.MandatesFile
	current.config.Namespace = old.config.Namespace
	current.mandate, current.operation = old.mandate, old.operation
	stop = current.start(t)
	defer stop()
	// Trust the replacement server, but present the retired client identity.
	oldTLS := old.clientTLS.Clone()
	oldTLS.RootCAs = current.clientTLS.RootCAs
	transport := &http.Transport{TLSClientConfig: oldTLS}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+current.config.Listen+"/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := client.Do(req); err == nil {
		_ = response.Body.Close()
		t.Fatal("retired client CA remained trusted")
	}
	c := current.challenge(t, "authorize", current.operation)
	grant, actor := current.grantKey, current.actorKey
	current.grantKey, current.actorKey = old.grantKey, old.actorKey
	status, _, _ := current.post(t, "/authorize", asbbinding.HTTPAuthorizeRequest{ChallengeID: c.ChallengeID, Operation: current.operation, Proof: current.proof(t, c, current.operation), Candidate: solution})
	if status != http.StatusForbidden {
		t.Fatal("retired signing identities remained trusted")
	}
	current.grantKey, current.actorKey = grant, actor
	capability = current.authorize(t, solution)
	if status = <-executeAsync(t, current, capability); status != http.StatusConflict {
		t.Fatal("rotation forgot consumed authority")
	}
	if _, err = os.Stat(current.config.AWSCLI + ".calls"); !os.IsNotExist(err) {
		t.Fatal("rotation replayed an uncertain operation")
	}
	t.Log("tls_rotation=true retired_client_rejected=true retired_proof_keys_rejected=true new_proof_accepted=true redispatches=0")
}
