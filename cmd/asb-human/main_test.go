// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/humanapp"
)

func proposalForTest(id string, revision uint64) humanapp.Command {
	return humanapp.Command{CommandID: "cmd-" + id, Kind: humanapp.KindPropose, OperationID: id, ExpectedRevision: revision,
		Change: &protectedchange.ChangeRequest{ChangeID: id, Tenant: humanapp.Tenant, Setting: humanapp.SettingName, Enabled: true}}
}

func responseForTest(t *testing.T, command humanapp.Command, digest, state string) []byte {
	t.Helper()
	response := humanapp.Response{CommandID: command.CommandID}
	if command.Kind == humanapp.KindInbox {
		response.Setting = &humanapp.Setting{Tenant: humanapp.Tenant, Name: humanapp.SettingName, Revision: 7}
	} else {
		response.Operation = &humanapp.Operation{OperationID: command.OperationID, ProposalDigest: digest, State: state}
	}
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLoopbackLiteralsOnly(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8091", "127.0.0.2:0", "[::1]:8090"} {
		if err := validateLoopback(address); err != nil {
			t.Errorf("%s: %v", address, err)
		}
	}
	for _, address := range []string{":8091", "0.0.0.0:8091", "[::]:8091", "localhost:8091", "192.0.2.1:8091", "127.0.0.1", "127.0.0.1:65536", "127.0.0.1:-1", "[::1%lo0]:8091"} {
		if validateLoopback(address) == nil {
			t.Errorf("accepted %q", address)
		}
	}
}

func TestListenerConflictNamesThePortAndRecoveryFlag(t *testing.T) {
	for _, listener := range []string{"core", "web"} {
		t.Run(listener, func(t *testing.T) {
			busy, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = busy.Close() }()
			cfg := serveOptions{dir: filepath.Join(t.TempDir(), "private"), coreAddress: "127.0.0.1:0", webAddress: "127.0.0.1:0"}
			if listener == "core" {
				cfg.coreAddress = busy.Addr().String()
			} else {
				cfg.webAddress = busy.Addr().String()
			}
			running, err := startServers(cfg)
			if running != nil {
				running.close()
				t.Fatal("listener conflict unexpectedly started the service")
			}
			if err == nil || !strings.Contains(err.Error(), busy.Addr().String()) || !strings.Contains(err.Error(), "--"+listener+"-listen=127.0.0.1:0") {
				t.Fatalf("missing targeted recovery guidance: %v", err)
			}
		})
	}
}

func TestReceiptPreservesProposalAcrossLostResponse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proposal.json")
	cfg := agentOptions{dir: dir, receipt: path, operationID: "restart-case", enabled: true, poll: 50 * time.Millisecond}
	var initial []byte
	var firstCalls []string
	first := func(_ context.Context, command humanapp.Command) ([]byte, error) {
		firstCalls = append(firstCalls, command.Kind)
		if command.Kind == humanapp.KindInbox {
			return responseForTest(t, command, "", ""), nil
		}
		receipt, saved, err := readReceipt(path)
		if err != nil {
			t.Fatalf("request sent before its receipt was saved: %v", err)
		}
		initial = append([]byte(nil), receipt.Command...)
		got, _ := json.Marshal(command)
		if !bytes.Equal(got, initial) || saved.ExpectedRevision != 7 {
			t.Fatal("sent a different command from the receipt")
		}
		return nil, errors.New("response connection lost")
	}
	err := runAgent(context.Background(), cfg, first, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") || !strings.Contains(err.Error(), path) {
		t.Fatalf("missing recovery direction: %v", err)
	}
	if strings.Join(firstCalls, ",") != "INBOX,PROPOSE" {
		t.Fatalf("calls: %v", firstCalls)
	}
	var resumed []humanapp.Command
	retry := func(_ context.Context, command humanapp.Command) ([]byte, error) {
		resumed = append(resumed, command)
		if command.Kind == humanapp.KindInbox {
			t.Fatal("restart fetched a new revision")
		}
		if command.Kind == humanapp.KindPropose {
			raw, _ := json.Marshal(command)
			if !bytes.Equal(raw, initial) {
				t.Fatal("restart changed proposal bytes")
			}
		}
		digest := command.ProposalDigest
		state := humanapp.StateApplied
		if command.Kind == humanapp.KindPropose {
			digest, _ = humanapp.CommandDigest(command)
			// Immutable original proposal responses may still say pending after
			// a decision; the following live STATUS must see the terminal state.
			state = humanapp.StatePending
		}
		return responseForTest(t, command, digest, state), nil
	}
	cfg.operationID, cfg.wait = "", true
	if err := runAgent(context.Background(), cfg, retry, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(resumed) != 2 || resumed[0].Kind != humanapp.KindPropose || resumed[1].Kind != humanapp.KindStatus || resumed[0].CommandID == resumed[1].CommandID {
		t.Fatalf("unexpected recovery requests: %+v", resumed)
	}
	after, _, err := readReceipt(path)
	if err != nil || !bytes.Equal(initial, after.Command) {
		t.Fatal("recovery modified the receipt")
	}
}

func TestRejectedProposalPreservesReceiptWithoutRebasing(t *testing.T) {
	for _, rejection := range []error{humanapp.ErrConflict, humanapp.ErrInvalid, humanapp.ErrUnauthorized, humanapp.ErrNotFound} {
		t.Run(rejection.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt.json")
			original := proposalForTest("unadmitted", 7)
			if err := saveReceipt(path, original); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			execute := func(_ context.Context, command humanapp.Command) ([]byte, error) {
				calls++
				if command.Kind != humanapp.KindPropose || command.CommandID != original.CommandID || command.OperationID != original.OperationID || command.ExpectedRevision != 7 || command.Change == nil || *command.Change != *original.Change {
					t.Fatalf("rejection recovery changed the saved proposal or read a new revision: %+v", command)
				}
				return nil, fmt.Errorf("core response: %w", rejection)
			}
			err = runAgent(context.Background(), agentOptions{receipt: path, wait: true, poll: 50 * time.Millisecond}, execute, io.Discard)
			if !errors.Is(err, rejection) || !strings.Contains(err.Error(), "submission rejected") || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "outcome unknown") || calls != 1 {
				t.Fatalf("incorrect rejection guidance or automatic retry: calls=%d, error=%v", calls, err)
			}
			if errors.Is(rejection, humanapp.ErrConflict) {
				for _, want := range []string{"inspect --receipt", "review the current setting", "new --operation-id", "new receipt", "will not refresh its revision"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("conflict guidance missing %q: %v", want, err)
					}
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected proposal changed the saved receipt")
			}
		})
	}
}

type failOnWriteNumber struct {
	writes, failAt int
	err            error
}

func (w *failOnWriteNumber) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestAgentOutputFailureRetainsUnknownOutcomeGuidance(t *testing.T) {
	for _, wait := range []bool{false, true} {
		t.Run(fmt.Sprintf("wait=%t", wait), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt.json")
			original := proposalForTest("output-failure", 7)
			if err := saveReceipt(path, original); err != nil {
				t.Fatal(err)
			}
			digest, err := humanapp.CommandDigest(original)
			if err != nil {
				t.Fatal(err)
			}
			failure := errors.New("synthetic output failure")
			output := &failOnWriteNumber{failAt: 2, err: failure}
			if wait {
				output.failAt = 3
			}
			execute := func(_ context.Context, command humanapp.Command) ([]byte, error) {
				state := humanapp.StatePending
				if command.Kind == humanapp.KindStatus {
					state = humanapp.StateApplied
				}
				return responseForTest(t, command, digest, state), nil
			}
			err = runAgent(context.Background(), agentOptions{receipt: path, wait: wait, poll: 50 * time.Millisecond}, execute, output)
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), "outcome unknown") || !strings.Contains(err.Error(), path) {
				t.Fatalf("lost output must retain receipt recovery guidance: %v", err)
			}
			if _, _, err := readReceipt(path); err != nil {
				t.Fatalf("receipt unavailable after output failure: %v", err)
			}
		})
	}
}

func TestInspectionDistinguishesMissingOperationFromUnavailableStatus(t *testing.T) {
	command, err := statusCommand("unadmitted", "sha256:"+strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []error{humanapp.ErrNotFound, humanapp.ErrConflict, humanapp.ErrUnavailable} {
		t.Run(failure.Error(), func(t *testing.T) {
			var output bytes.Buffer
			err := runInspection(context.Background(), command, func(_ context.Context, got humanapp.Command) ([]byte, error) {
				if got != command {
					t.Fatal("inspection changed the requested operation")
				}
				return nil, fmt.Errorf("core response: %w", failure)
			}, &output)
			if !errors.Is(err, failure) || output.Len() != 0 {
				t.Fatalf("inspection error or output = %v, %q", err, output.String())
			}
			if errors.Is(failure, humanapp.ErrNotFound) {
				for _, want := range []string{"no matching operation", "Keep any saved receipt", "submission was rejected with a conflict", "new --operation-id", "new receipt"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("missing-operation guidance missing %q: %v", want, err)
					}
				}
				if strings.Contains(err.Error(), "status unavailable") {
					t.Fatal("a definitive not-found response was described as unavailable")
				}
			} else if errors.Is(failure, humanapp.ErrConflict) {
				for _, want := range []string{"operation ID belongs to a different proposal", "Keep any saved receipt", "existing operation and current setting", "new --operation-id", "new receipt", "will not resolve this conflict"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("conflicting-operation guidance missing %q: %v", want, err)
					}
				}
				if strings.Contains(err.Error(), "status unavailable") || strings.Contains(err.Error(), "retry inspect") {
					t.Fatal("a definitive conflict was described as unavailable or retryable")
				}
			} else if !strings.Contains(err.Error(), "status unavailable; retry inspect") {
				t.Fatalf("temporary status failure lost retry guidance: %v", err)
			}
		})
	}
}

func TestReceiptNeverOverwritesAndRejectsConflictingFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	command := proposalForTest("exclusive", 4)
	if err := saveReceipt(path, command); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveReceipt(path, proposalForTest("other", 9)); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second save: %v", err)
	}
	for _, cfg := range []agentOptions{
		{receipt: path, operationID: "other"},
		{receipt: path, enabledSet: true, enabled: false},
	} {
		_, _, _, err := prepareProposal(context.Background(), cfg, func(context.Context, humanapp.Command) ([]byte, error) {
			t.Fatal("conflicting receipt made a network request")
			return nil, nil
		})
		if err == nil {
			t.Fatal("conflicting flags accepted")
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing receipt changed")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("receipt permission: %v %v", info, err)
		}
	}
	for _, id := range []string{"../escape", "a/b", `a\b`, ".", ""} {
		if _, err := derivedReceipt(t.TempDir(), id); err == nil {
			t.Fatalf("accepted receipt identifier %q", id)
		}
	}
	deviceNamed, err := derivedReceipt(t.TempDir(), "CON")
	if err != nil || filepath.Base(deviceNamed) != "proposal-CON.json" {
		t.Fatalf("unsafe Windows receipt filename: %q %v", deviceNamed, err)
	}
}

func TestInspectUsesReceiptAndFreshCommandIDs(t *testing.T) {
	dir := t.TempDir()
	path, err := derivedReceipt(dir, "inspection")
	if err != nil {
		t.Fatal(err)
	}
	command := proposalForTest("inspection", 3)
	if err := saveReceipt(path, command); err != nil {
		t.Fatal(err)
	}
	one, err := inspectionCommand(dir, path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	two, err := inspectionCommand(dir, "", "inspection", "")
	if err != nil {
		t.Fatal(err)
	}
	if one.CommandID == two.CommandID || one.ExpectedRevision != 0 || one.OperationID != command.OperationID || one.ProposalDigest != two.ProposalDigest {
		t.Fatal("invalid live status requests")
	}
	if _, err := inspectionCommand(dir, path, "inspection", one.ProposalDigest); err == nil {
		t.Fatal("mixed receipt and explicit identity accepted")
	}
}

func TestCanceledWaitLeavesRecoverableReceipt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	execute := func(_ context.Context, command humanapp.Command) ([]byte, error) {
		if command.Kind == humanapp.KindInbox {
			return responseForTest(t, command, "", ""), nil
		}
		digest, _ := humanapp.CommandDigest(command)
		cancel()
		return responseForTest(t, command, digest, humanapp.StatePending), nil
	}
	err := runAgent(ctx, agentOptions{dir: dir, receipt: path, enabled: true, wait: true, poll: 50 * time.Millisecond}, execute, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("wait error: %v", err)
	}
	if _, _, err := readReceipt(path); err != nil {
		t.Fatalf("receipt unavailable for recovery: %v", err)
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buffer.String() }

type commandProcess struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	lines    chan []byte
	finished chan struct{}
	err      error
	stderr   lockedBuffer
}

func startCommand(t *testing.T, executable string, args ...string) *commandProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &commandProcess{cancel: cancel, lines: make(chan []byte, 64), finished: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, executable, args...)
	p.cmd.Stderr = &p.stderr
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := p.cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			p.lines <- append([]byte(nil), scanner.Bytes()...)
		}
		p.err = p.cmd.Wait()
		close(p.lines)
		close(p.finished)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-p.finished:
		case <-time.After(15 * time.Second):
			t.Errorf("subprocess did not stop: %s", p.stderr.String())
		}
	})
	return p
}

func (p *commandProcess) next(t *testing.T, wanted string) map[string]json.RawMessage {
	t.Helper()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case raw, ok := <-p.lines:
			if !ok {
				t.Fatalf("subprocess ended before %s: %s", wanted, p.stderr.String())
			}
			var event map[string]json.RawMessage
			if err := json.Unmarshal(raw, &event); err != nil {
				t.Fatalf("non-JSON stdout: %q", raw)
			}
			var name string
			_ = json.Unmarshal(event["event"], &name)
			if name == wanted || (wanted == "operation" && event["operation"] != nil) {
				return event
			}
		case <-deadline.C:
			t.Fatalf("timed out awaiting %s: %s", wanted, p.stderr.String())
		}
	}
}

func (p *commandProcess) wait(t *testing.T, wantSuccess bool) {
	t.Helper()
	select {
	case <-p.finished:
		if wantSuccess && p.err != nil {
			t.Fatalf("subprocess failed: %v: %s", p.err, p.stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("subprocess did not finish: %s", p.stderr.String())
	}
}

func fieldString(t *testing.T, event map[string]json.RawMessage, name string) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(event[name], &value); err != nil {
		t.Fatalf("missing %s: %v", name, err)
	}
	return value
}

func buildCommand(t *testing.T) string {
	t.Helper()
	name := "asb-human"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-mod=readonly", "-o", path, ".")
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable: %v\n%s", err, output)
	}
	return path
}

func TestCommandProcessesRecoverApprovalAfterRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs real CLI processes")
	}
	executable := buildCommand(t)
	dir := filepath.Join(t.TempDir(), "private-state")
	init := startCommand(t, executable, "init", "--data-dir", dir)
	init.wait(t, true)
	startServer := func() (*commandProcess, string) {
		p := startCommand(t, executable, "serve", "--data-dir", dir, "--core-listen", "127.0.0.1:0", "--web-listen", "127.0.0.1:0")
		event := p.next(t, "ready")
		login, err := url.Parse(fieldString(t, event, "login_url"))
		if err != nil || login.RawQuery != "" || !strings.HasPrefix(login.Fragment, "login=") {
			t.Fatal("login token must appear only in the fragment")
		}
		response, err := http.Get(fieldString(t, event, "web_origin"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("browser status: %d", response.StatusCode)
		}
		return p, fieldString(t, event, "core_address")
	}
	server, address := startServer()
	path := filepath.Join(dir, "test-receipt.json")
	agent := startCommand(t, executable, "agent", "--data-dir", dir, "--core-address", address, "--operation-id", "process-recovery", "--receipt", path, "--wait", "--poll-interval", "50ms")
	agent.next(t, "proposal_saved")
	agent.next(t, "operation")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Abrupt process death leaves the committed proposal and its pre-send
	// receipt intact. Both application and agent are then new processes.
	agent.cancel()
	agent.wait(t, false)
	server.cancel()
	server.wait(t, false)
	_, address = startServer()
	resumed := startCommand(t, executable, "agent", "--data-dir", dir, "--core-address", address, "--receipt", path, "--wait", "--poll-interval", "50ms")
	resumed.next(t, "proposal_saved")
	resumed.next(t, "operation")
	receipt, original, err := readReceipt(path)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := newClient(dir, humanapp.ActorGateway, address)
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := newID("approve-")
	if err != nil {
		t.Fatal(err)
	}
	approval := humanapp.Command{CommandID: commandID, Kind: humanapp.KindApprove, OperationID: original.OperationID, ExpectedRevision: original.ExpectedRevision, ProposalDigest: receipt.ProposalDigest}
	if _, err := gateway.Execute(context.Background(), approval); err != nil {
		t.Fatal(err)
	}
	result := resumed.next(t, "operation")
	var operation humanapp.Operation
	if json.Unmarshal(result["operation"], &operation) != nil || operation.State != humanapp.StateApplied {
		t.Fatalf("operation did not apply: %s", result["operation"])
	}
	resumed.wait(t, true)
	inspect := startCommand(t, executable, "inspect", "--data-dir", dir, "--core-address", address, "--receipt", path)
	live := inspect.next(t, "operation")
	if json.Unmarshal(live["operation"], &operation) != nil || operation.After == nil || !operation.After.Enabled || operation.After.Revision != original.ExpectedRevision+1 {
		t.Fatal("live inspection did not show exactly one setting revision")
	}
	inspect.wait(t, true)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("restart changed original receipt bytes")
	}
	// Reinitializing an existing directory must preserve the committed result.
	initAgain := startCommand(t, executable, "init", "--data-dir", dir)
	initAgain.wait(t, true)
	inspectAgain := startCommand(t, executable, "inspect", "--data-dir", dir, "--core-address", address, "--operation-id", original.OperationID, "--digest", receipt.ProposalDigest)
	inspectAgain.next(t, "operation")
	inspectAgain.wait(t, true)

	t.Run("demo launches a separate waiting agent", func(t *testing.T) {
		demoDir := filepath.Join(t.TempDir(), "demo")
		demo := startCommand(t, executable, "demo", "--data-dir", demoDir, "--enabled=false")
		ready := demo.next(t, "ready")
		saved := demo.next(t, "proposal_saved")
		demo.next(t, "operation")
		demoReceipt := fieldString(t, saved, "receipt")
		r, proposed, err := readReceipt(demoReceipt)
		if err != nil {
			t.Fatal(err)
		}
		if proposed.Change.Enabled {
			t.Fatal("demo ignored --enabled=false")
		}
		client, err := newClient(demoDir, humanapp.ActorGateway, fieldString(t, ready, "core_address"))
		if err != nil {
			t.Fatal(err)
		}
		commandID, _ := newID("deny-")
		_, err = client.Execute(context.Background(), humanapp.Command{CommandID: commandID, Kind: humanapp.KindDecline, OperationID: proposed.OperationID, ExpectedRevision: proposed.ExpectedRevision, ProposalDigest: r.ProposalDigest})
		if err != nil {
			t.Fatal(err)
		}
		terminal := demo.next(t, "operation")
		for _, want := range []string{"Open this private link", fieldString(t, ready, "login_url"), demoDir, "no system setting is modified", "Press Ctrl+C"} {
			if !strings.Contains(demo.stderr.String(), want) {
				t.Errorf("missing startup guidance %q in %s", want, demo.stderr.String())
			}
		}
		if json.Unmarshal(terminal["operation"], &operation) != nil || operation.State != humanapp.StateDenied {
			t.Fatalf("demo result: %s", terminal["operation"])
		}
		resp, err := http.Get(fieldString(t, ready, "web_origin"))
		if err != nil {
			t.Fatal(fmt.Errorf("demo should stay available after agent completion: %w", err))
		}
		_ = resp.Body.Close()
	})
}
