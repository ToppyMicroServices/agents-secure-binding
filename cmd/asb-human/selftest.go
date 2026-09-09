// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/humanapp"
)

func selfTestCommand(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("self-test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	timeout := flags.Duration("timeout", 30*time.Second, "workflow timeout, greater than zero and at most 5m")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: asb-human self-test [--timeout 30s]\nAutomatically checks local approval with a simulated Human gateway.\nUses fresh temporary credentials and SQLite; never opens existing application data.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 || *timeout > 5*time.Minute {
		return errors.New("self-test accepts only --timeout, greater than zero and at most 5m")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if _, err := fmt.Fprintln(stdout, "ASB local approval self-test\nSimulated Human gateway; software-only TLS 1.3/mTLS. No browser or TEE required."); err != nil {
		return err
	}
	if err := runSelfTest(ctx, stdout, ""); err != nil {
		return fmt.Errorf("self-test failed: %w", err)
	}
	_, err := fmt.Fprintln(stdout, "PASS: local approval self-test completed.\nTemporary credentials and database removed. This is not real-Human or hardware qualification.")
	return err
}

// The temporary parent is a test seam, not a CLI option. The harness never
// accepts an existing application directory, address, or user credentials.
func runSelfTest(ctx context.Context, stdout io.Writer, temporaryParent string) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(temporaryParent, "asb-human-self-test-")
	if err != nil {
		return fmt.Errorf("create isolated temporary directory: %w", err)
	}
	defer func() {
		// dir is the exact, private directory created by this invocation.
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("remove self-test data at %q: %w", dir, cleanupErr))
		}
	}()
	if err := humanapp.Initialize(dir); err != nil {
		return fmt.Errorf("initialize temporary credentials: %w", err)
	}
	core, err := startSelfTestCore(ctx, dir)
	if err != nil {
		return err
	}
	defer func() {
		if core != nil {
			err = errors.Join(err, core.close())
		}
	}()
	if err := selfTestSetting(ctx, core.agent, false, 0); err != nil {
		return fmt.Errorf("initial authenticated read: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, "  OK  Fresh database and authenticated loopback connection"); err != nil {
		return err
	}

	type recordedCommand struct {
		actor   string
		command humanapp.Command
		result  []byte
	}
	var original []recordedCommand
	for _, scenario := range []struct {
		id, decision, state string
		value               bool
		revision            uint64
	}{
		{"approval", humanapp.KindApprove, humanapp.StateApplied, true, 0},
		{"denial", humanapp.KindDecline, humanapp.StateDenied, false, 1},
	} {
		proposal := humanapp.Command{CommandID: "self-test-propose-" + scenario.id, Kind: humanapp.KindPropose,
			OperationID: "self-test-" + scenario.id, ExpectedRevision: scenario.revision,
			Change: &protectedchange.ChangeRequest{ChangeID: "self-test-" + scenario.id, Tenant: humanapp.Tenant, Setting: humanapp.SettingName, Enabled: scenario.value}}
		digest, err := humanapp.CommandDigest(proposal)
		if err != nil {
			return err
		}
		raw, proposed, err := selfTestOperation(ctx, core.agent, proposal, digest, humanapp.StatePending)
		if err != nil {
			return fmt.Errorf("%s proposal: %w", scenario.id, err)
		}
		if proposed.Operation.Before.Revision != scenario.revision || proposed.Operation.Proposer != humanapp.ActorAgent || proposed.Operation.Change != *proposal.Change {
			return errors.New("pending proposal does not preserve the agent's requested change")
		}
		original = append(original, recordedCommand{humanapp.ActorAgent, proposal, raw})
		decision := humanapp.Command{CommandID: "self-test-decide-" + scenario.id, Kind: scenario.decision,
			OperationID: proposal.OperationID, ExpectedRevision: scenario.revision, ProposalDigest: digest}
		raw, decided, err := selfTestOperation(ctx, core.gateway, decision, digest, scenario.state)
		if err != nil {
			return fmt.Errorf("simulated %s: %w", scenario.id, err)
		}
		operation := decided.Operation
		if operation.Reviewer != humanapp.ActorGateway || operation.HumanParticipant != humanapp.HumanParticipant || operation.Assurance != humanapp.Assurance || operation.DecidedAt == nil {
			return errors.New("decision is missing its gateway-asserted identity")
		}
		if scenario.state == humanapp.StateApplied {
			if operation.After == nil || !operation.After.Enabled || operation.After.Revision != 1 {
				return errors.New("approved change was not applied exactly once")
			}
		} else if operation.After != nil {
			return errors.New("denied change unexpectedly reports an effect")
		}
		original = append(original, recordedCommand{humanapp.ActorGateway, decision, raw})
		if err := selfTestSetting(ctx, core.agent, true, 1); err != nil {
			return fmt.Errorf("setting after %s: %w", scenario.id, err)
		}
		if _, err := fmt.Fprintf(stdout, "  OK  Simulated %s: %s; maintenance_mode=true, revision=1\n", scenario.id, scenario.state); err != nil {
			return err
		}
	}
	if err := core.close(); err != nil {
		core = nil
		return fmt.Errorf("close before restart: %w", err)
	}
	core = nil
	core, err = startSelfTestCore(ctx, dir)
	if err != nil {
		return fmt.Errorf("reopen database and service: %w", err)
	}
	for _, saved := range original {
		client := core.agent
		if saved.actor == humanapp.ActorGateway {
			client = core.gateway
		}
		retried, err := client.Execute(ctx, saved.command)
		if err != nil {
			return fmt.Errorf("recover %s with fresh authentication: %w", saved.command.CommandID, err)
		}
		if !bytes.Equal(saved.result, retried) {
			return errors.New("restart retry changed the original outcome bytes")
		}
	}
	for _, saved := range original {
		if saved.actor != humanapp.ActorGateway {
			continue
		}
		status, err := statusCommand(saved.command.OperationID, saved.command.ProposalDigest)
		if err != nil {
			return err
		}
		state := humanapp.StateApplied
		if saved.command.Kind == humanapp.KindDecline {
			state = humanapp.StateDenied
		}
		if _, _, err := selfTestOperation(ctx, core.agent, status, saved.command.ProposalDigest, state); err != nil {
			return fmt.Errorf("live status after restart: %w", err)
		}
	}
	if err := selfTestSetting(ctx, core.agent, true, 1); err != nil {
		return fmt.Errorf("restart introduced another effect: %w", err)
	}
	_, err = fmt.Fprintln(stdout, "  OK  SQLite reopen: original outcomes recovered; no repeated effect")
	return err
}

func selfTestOperation(ctx context.Context, client *humanapp.Client, command humanapp.Command, digest, state string) ([]byte, humanapp.Response, error) {
	raw, err := client.Execute(ctx, command)
	if err != nil {
		return nil, humanapp.Response{}, err
	}
	result, err := checkedResponse(raw, command.CommandID, command.OperationID, digest)
	if err == nil && result.Operation.State != state {
		err = fmt.Errorf("expected %s, got %s", state, result.Operation.State)
	}
	return raw, result, err
}

func selfTestSetting(ctx context.Context, client *humanapp.Client, enabled bool, revision uint64) error {
	command, err := inboxCommand()
	if err != nil {
		return err
	}
	raw, err := client.Execute(ctx, command)
	if err != nil {
		return err
	}
	var result humanapp.Response
	if err := json.Unmarshal(raw, &result); err != nil {
		return err
	}
	want := humanapp.Setting{Tenant: humanapp.Tenant, Name: humanapp.SettingName, Enabled: enabled, Revision: revision}
	if result.CommandID != command.CommandID || result.Setting == nil || *result.Setting != want {
		return fmt.Errorf("expected maintenance_mode=%t, revision=%d", enabled, revision)
	}
	return nil
}

type selfTestCore struct {
	server         *http.Server
	store          *humanapp.Store
	agent, gateway *humanapp.Client
	done           chan error
}

func startSelfTestCore(ctx context.Context, dir string) (_ *selfTestCore, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := humanapp.OpenStore(filepath.Join(dir, "self-test.sqlite"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, store.Close())
		}
	}()
	core, err := humanapp.NewCoreServer(dir, store)
	if err != nil {
		return nil, err
	}
	tlsConfig := core.TLSConfig()
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.MaxVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("self-test requires TLS 1.3 and verified client certificates")
	}
	var listen net.ListenConfig
	listener, err := listen.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on an available loopback port: %w", err)
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()
	agent, err := humanapp.NewClient(dir, humanapp.ActorAgent, listener.Addr().String())
	if err != nil {
		return nil, err
	}
	gateway, err := humanapp.NewClient(dir, humanapp.ActorGateway, listener.Addr().String())
	if err != nil {
		return nil, err
	}
	running := &selfTestCore{store: store, agent: agent, gateway: gateway, done: make(chan error, 1),
		server: &http.Server{Handler: core.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10}}
	go func() { running.done <- running.server.Serve(tls.NewListener(listener, tlsConfig)) }()
	return running, nil
}

func (s *selfTestCore) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, s.server.Close())
	}
	if serveErr := <-s.done; !errors.Is(serveErr, http.ErrServerClosed) {
		err = errors.Join(err, serveErr)
	}
	return errors.Join(err, s.store.Close())
}
