// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// asb-human runs the experimental approval application on one trusted host.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	protectedchange "github.com/ToppyMicroServices/agents-secure-binding/v2/examples/protected-change-consumer"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/humanapp"
)

const (
	defaultCoreAddress = "127.0.0.1:8091"
	defaultWebAddress  = "127.0.0.1:8090"
	receiptVersion     = 1
)

type executeCommand func(context.Context, humanapp.Command) ([]byte, error)

// The original proposal is immutable. In particular, its expected revision
// must never be refreshed when an earlier response may have been lost.
type proposalReceipt struct {
	Version        int             `json:"version"`
	Command        json.RawMessage `json:"command"`
	ProposalDigest string          `json:"proposal_digest"`
}

type agentOptions struct {
	dir, address, operationID, receipt string
	enabled, enabledSet, wait          bool
	poll, timeout                      time.Duration
}

type serveOptions struct {
	dir, coreAddress, webAddress string
	demo, enabled                bool
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_ = writeJSON(os.Stderr, map[string]string{"error": err.Error()})
		os.Exit(1)
	}
}

func defaultDataDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("choose --data-dir: %w", err)
	}
	return filepath.Join(dir, "asb-human"), nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: asb-human <self-test|demo|init|serve|agent|inspect> [flags]")
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(stdout, "usage: asb-human <self-test|demo|init|serve|agent|inspect> [flags]\nTry self-test for an automatic local check, or demo for a browser review.\nUse a command with --help for its options.")
		return err
	}
	if args[0] == "self-test" {
		return selfTestCommand(ctx, args[1:], stdout, stderr)
	}
	dir, err := defaultDataDir()
	if err != nil {
		// An explicit directory still works when the OS profile is unavailable.
		dir = ""
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&dir, "data-dir", dir, "private local application directory")
	var serveCfg serveOptions
	var agentCfg agentOptions
	var operationID, receiptPath, digest string
	switch args[0] {
	case "init":
	case "serve", "demo":
		serveCfg.demo = args[0] == "demo"
		coreAddress, webAddress := defaultCoreAddress, defaultWebAddress
		if serveCfg.demo {
			coreAddress, webAddress = "127.0.0.1:0", "127.0.0.1:0"
		}
		flags.StringVar(&serveCfg.coreAddress, "core-listen", coreAddress, "core listener: explicit loopback IP and port; zero chooses an available port")
		flags.StringVar(&serveCfg.webAddress, "web-listen", webAddress, "browser listener: explicit loopback IP and port; zero chooses an available port")
		if serveCfg.demo {
			flags.BoolVar(&serveCfg.enabled, "enabled", true, "propose the local maintenance_mode value")
		}
	case "agent":
		flags.StringVar(&agentCfg.address, "core-address", defaultCoreAddress, "core address: explicit loopback IP and port")
		flags.StringVar(&agentCfg.operationID, "operation-id", "", "proposal identifier; generated when omitted")
		flags.StringVar(&agentCfg.receipt, "receipt", "", "save or resume an immutable proposal receipt")
		flags.BoolVar(&agentCfg.enabled, "enabled", true, "requested local maintenance_mode value (use --enabled=false to disable)")
		flags.BoolVar(&agentCfg.wait, "wait", false, "poll until the proposal is applied, denied, or stale")
		flags.DurationVar(&agentCfg.poll, "poll-interval", time.Second, "interval between freshly authenticated status requests")
		flags.DurationVar(&agentCfg.timeout, "timeout", 0, "stop waiting after this duration; zero waits until interrupted")
	case "inspect":
		flags.StringVar(&agentCfg.address, "core-address", defaultCoreAddress, "core address: explicit loopback IP and port")
		flags.StringVar(&operationID, "operation-id", "", "proposal identifier")
		flags.StringVar(&receiptPath, "receipt", "", "read a saved proposal receipt")
		flags.StringVar(&digest, "digest", "", "proposal digest, required with --operation-id unless its derived receipt exists")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || dir == "" {
		return errors.New("provide --data-dir and use named flags only")
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	switch args[0] {
	case "init":
		if err := humanapp.Initialize(dir); err != nil {
			return err
		}
		return writeJSON(stdout, map[string]string{"event": "initialized", "data_dir": dir})
	case "serve", "demo":
		serveCfg.dir = dir
		return serve(ctx, serveCfg, stdout, stderr)
	case "agent":
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "enabled" {
				agentCfg.enabledSet = true
			}
		})
		agentCfg.dir = dir
		if agentCfg.poll < 50*time.Millisecond || agentCfg.timeout < 0 {
			return errors.New("poll interval must be at least 50ms and timeout cannot be negative")
		}
		client, err := newClient(dir, humanapp.ActorAgent, agentCfg.address)
		if err != nil {
			return err
		}
		return runAgent(ctx, agentCfg, client.Execute, stdout)
	case "inspect":
		command, err := inspectionCommand(dir, receiptPath, operationID, digest)
		if err != nil {
			return err
		}
		client, err := newClient(dir, humanapp.ActorAgent, agentCfg.address)
		if err != nil {
			return err
		}
		return runInspection(ctx, command, client.Execute, stdout)
	}
	return nil
}

func validateLoopback(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("address must contain an explicit loopback IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return errors.New("only explicit loopback IP literals are allowed")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return errors.New("port must be an integer from 0 to 65535")
	}
	return nil
}

func newClient(dir, actor, address string) (*humanapp.Client, error) {
	if err := validateLoopback(address); err != nil {
		return nil, err
	}
	return humanapp.NewClient(dir, actor, address)
}

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func inboxCommand() (humanapp.Command, error) {
	id, err := newID("cmd-")
	return humanapp.Command{CommandID: id, Kind: humanapp.KindInbox}, err
}

func statusCommand(operationID, digest string) (humanapp.Command, error) {
	id, err := newID("cmd-")
	if err != nil {
		return humanapp.Command{}, err
	}
	command := humanapp.Command{CommandID: id, Kind: humanapp.KindStatus, OperationID: operationID, ProposalDigest: digest}
	return command, command.Validate()
}

func derivedReceipt(dir, operationID string) (string, error) {
	// Validate with the protocol's own identifier rules before using an ID in
	// a path. STATUS also gives the ID exactly the same validation as PROPOSE.
	check := humanapp.Command{CommandID: "receipt-path-check", Kind: humanapp.KindStatus, OperationID: operationID, ProposalDigest: "sha256:" + strings.Repeat("0", 64)}
	if err := check.Validate(); err != nil {
		return "", errors.New("invalid operation ID")
	}
	// A fixed prefix also keeps valid IDs such as CON away from Windows
	// device filenames. The protocol's length limit keeps filenames bounded.
	return filepath.Join(dir, "receipts", "proposal-"+operationID+".json"), nil
}

func readReceipt(path string) (proposalReceipt, humanapp.Command, error) {
	var receipt proposalReceipt
	var command humanapp.Command
	info, err := os.Lstat(path)
	if err != nil {
		return receipt, command, err
	}
	if !info.Mode().IsRegular() || info.Size() > humanapp.MaxRequestBytes+1024 {
		return receipt, command, errors.New("receipt must be a small regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return receipt, command, errors.New("receipt permissions must restrict access to its owner")
	}
	file, err := os.Open(path)
	if err != nil {
		return receipt, command, err
	}
	defer file.Close()
	d := json.NewDecoder(io.LimitReader(file, humanapp.MaxRequestBytes+1025))
	d.DisallowUnknownFields()
	if err := d.Decode(&receipt); err != nil {
		return receipt, command, fmt.Errorf("invalid receipt: %w", err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF || receipt.Version != receiptVersion {
		return receipt, command, errors.New("invalid receipt format or version")
	}
	if err := json.Unmarshal(receipt.Command, &command); err != nil || command.Kind != humanapp.KindPropose || command.Validate() != nil {
		return receipt, command, errors.New("receipt does not contain a valid original PROPOSE command")
	}
	canonical, err := json.Marshal(command)
	if err != nil || !bytes.Equal(canonical, receipt.Command) {
		return receipt, command, errors.New("receipt command bytes are not canonical; refusing to reconstruct them")
	}
	digest, err := humanapp.CommandDigest(command)
	if err != nil || digest != receipt.ProposalDigest {
		return receipt, command, errors.New("receipt proposal digest does not match its original command")
	}
	return receipt, command, nil
}

func saveReceipt(path string, command humanapp.Command) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	digest, err := humanapp.CommandDigest(command)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(proposalReceipt{Version: receiptVersion, Command: raw, ProposalDigest: digest})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return errors.New("receipt destination must be a regular file")
	}
	// Keep a failed/partial receipt in place. No request has been submitted,
	// and an automatic retry must never replace a possibly existing record.
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	return nil
}

func prepareProposal(ctx context.Context, cfg agentOptions, execute executeCommand) (string, proposalReceipt, humanapp.Command, error) {
	path := cfg.receipt
	var err error
	if path == "" {
		if cfg.operationID == "" {
			cfg.operationID, err = newID("op-")
			if err != nil {
				return "", proposalReceipt{}, humanapp.Command{}, err
			}
		}
		path, err = derivedReceipt(cfg.dir, cfg.operationID)
		if err != nil {
			return "", proposalReceipt{}, humanapp.Command{}, err
		}
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", proposalReceipt{}, humanapp.Command{}, err
	}
	load := func() (string, proposalReceipt, humanapp.Command, error) {
		receipt, command, err := readReceipt(path)
		if err == nil && ((cfg.operationID != "" && cfg.operationID != command.OperationID) || (cfg.enabledSet && cfg.enabled != command.Change.Enabled)) {
			err = errors.New("requested operation ID or value conflicts with the saved receipt")
		}
		return path, receipt, command, err
	}
	if path, receipt, command, err := load(); !errors.Is(err, os.ErrNotExist) {
		return path, receipt, command, err
	}
	if cfg.operationID == "" {
		cfg.operationID, err = newID("op-")
		if err != nil {
			return "", proposalReceipt{}, humanapp.Command{}, err
		}
	}
	inbox, err := inboxCommand()
	if err != nil {
		return "", proposalReceipt{}, humanapp.Command{}, err
	}
	raw, err := execute(ctx, inbox)
	if err != nil {
		return "", proposalReceipt{}, humanapp.Command{}, fmt.Errorf("could not read the initial revision; no proposal submitted: %w", err)
	}
	var response humanapp.Response
	if json.Unmarshal(raw, &response) != nil || response.CommandID != inbox.CommandID || response.Setting == nil || response.Setting.Tenant != humanapp.Tenant || response.Setting.Name != humanapp.SettingName {
		return "", proposalReceipt{}, humanapp.Command{}, errors.New("invalid initial setting response; no proposal submitted")
	}
	id, err := newID("cmd-")
	if err != nil {
		return "", proposalReceipt{}, humanapp.Command{}, err
	}
	command := humanapp.Command{
		CommandID: id, Kind: humanapp.KindPropose, OperationID: cfg.operationID,
		ExpectedRevision: response.Setting.Revision,
		Change:           &protectedchange.ChangeRequest{ChangeID: cfg.operationID, Tenant: humanapp.Tenant, Setting: humanapp.SettingName, Enabled: cfg.enabled},
	}
	if err := command.Validate(); err != nil {
		return "", proposalReceipt{}, humanapp.Command{}, err
	}
	if err := saveReceipt(path, command); err != nil && !errors.Is(err, os.ErrExist) {
		return "", proposalReceipt{}, humanapp.Command{}, fmt.Errorf("could not save receipt; no proposal submitted: %w", err)
	}
	return load()
}

func runAgent(ctx context.Context, cfg agentOptions, execute executeCommand, stdout io.Writer) error {
	if cfg.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
		defer cancel()
	}
	path, receipt, command, err := prepareProposal(ctx, cfg, execute)
	if err != nil {
		return err
	}
	if err := writeJSON(stdout, struct {
		Event          string `json:"event"`
		Receipt        string `json:"receipt"`
		OperationID    string `json:"operation_id"`
		ProposalDigest string `json:"proposal_digest"`
	}{"proposal_saved", path, command.OperationID, receipt.ProposalDigest}); err != nil {
		return err
	}
	unknown := func(err error) error {
		return fmt.Errorf("outcome unknown; run inspect --receipt %q, or resume agent --receipt %q --wait with the same --data-dir and --core-address: %w", path, path, err)
	}
	raw, err := execute(ctx, command)
	if err != nil {
		if errors.Is(err, humanapp.ErrConflict) {
			return fmt.Errorf("proposal submission rejected (conflict); saved receipt preserved at %q. Run inspect --receipt %q with the same --data-dir and --core-address. If no matching operation is found, review the current setting in the browser before intentionally creating a new proposal with a new --operation-id and a new receipt; resuming this receipt will not refresh its revision: %w", path, path, err)
		}
		if errors.Is(err, humanapp.ErrInvalid) || errors.Is(err, humanapp.ErrUnauthorized) || errors.Is(err, humanapp.ErrNotFound) {
			return fmt.Errorf("proposal submission rejected; saved receipt preserved at %q. Resolve the reported error, then inspect the saved operation before deciding whether to resume or create a new proposal: %w", path, err)
		}
		return unknown(err)
	}
	response, err := checkedResponse(raw, command.CommandID, command.OperationID, receipt.ProposalDigest)
	if err != nil {
		return unknown(err)
	}
	if err := writeJSON(stdout, json.RawMessage(raw)); err != nil {
		return unknown(err)
	}
	if !cfg.wait || terminal(response.Operation.State) {
		return nil
	}
	ticker := time.NewTicker(cfg.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return unknown(ctx.Err())
		case <-ticker.C:
		}
		status, err := statusCommand(command.OperationID, receipt.ProposalDigest)
		if err != nil {
			return unknown(err)
		}
		raw, err := execute(ctx, status)
		if err != nil {
			return unknown(err)
		}
		response, err := checkedResponse(raw, status.CommandID, command.OperationID, receipt.ProposalDigest)
		if err != nil {
			return unknown(err)
		}
		if terminal(response.Operation.State) {
			if err := writeJSON(stdout, json.RawMessage(raw)); err != nil {
				return unknown(err)
			}
			return nil
		}
	}
}

func runInspection(ctx context.Context, command humanapp.Command, execute executeCommand, stdout io.Writer) error {
	raw, err := execute(ctx, command)
	if err != nil {
		if errors.Is(err, humanapp.ErrNotFound) {
			return fmt.Errorf("no matching operation was found in this service. Keep any saved receipt. If submission was interrupted, resume that receipt unchanged. If submission was rejected with a conflict, review the current setting in the browser before intentionally creating a new proposal with a new --operation-id and a new receipt: %w", err)
		}
		if errors.Is(err, humanapp.ErrConflict) {
			return fmt.Errorf("the operation ID belongs to a different proposal. Keep any saved receipt. Review the existing operation and current setting in the browser before intentionally creating a new proposal with a new --operation-id and a new receipt; repeating inspect with the same ID and digest will not resolve this conflict: %w", err)
		}
		return fmt.Errorf("status unavailable; retry inspect with the same receipt or operation ID and digest: %w", err)
	}
	if _, err := checkedResponse(raw, command.CommandID, command.OperationID, command.ProposalDigest); err != nil {
		return err
	}
	return writeJSON(stdout, json.RawMessage(raw))
}

func terminal(state string) bool {
	return state == humanapp.StateApplied || state == humanapp.StateDenied || state == humanapp.StateStale
}

func checkedResponse(raw []byte, commandID, operationID, digest string) (humanapp.Response, error) {
	var response humanapp.Response
	if json.Unmarshal(raw, &response) != nil || response.CommandID != commandID || response.Operation == nil || response.Operation.OperationID != operationID || response.Operation.ProposalDigest != digest {
		return response, errors.New("response does not match the saved operation")
	}
	if response.Operation.State != humanapp.StatePending && !terminal(response.Operation.State) {
		return response, errors.New("unrecognized operation state")
	}
	return response, nil
}

func inspectionCommand(dir, receiptPath, operationID, digest string) (humanapp.Command, error) {
	if receiptPath != "" && (operationID != "" || digest != "") {
		return humanapp.Command{}, errors.New("use either --receipt or --operation-id with --digest")
	}
	if receiptPath == "" && digest == "" {
		var err error
		receiptPath, err = derivedReceipt(dir, operationID)
		if err != nil {
			return humanapp.Command{}, errors.New("inspect requires --receipt or --operation-id and --digest")
		}
	}
	if receiptPath != "" {
		receipt, command, err := readReceipt(receiptPath)
		if err != nil {
			return humanapp.Command{}, err
		}
		operationID, digest = command.OperationID, receipt.ProposalDigest
	}
	return statusCommand(operationID, digest)
}

func writeJSON(w io.Writer, value any) error { return json.NewEncoder(w).Encode(value) }

type runningServers struct {
	coreAddress, webOrigin, loginURL string
	core, web                        *http.Server
	store                            *humanapp.Store
	errors                           chan error
}

func startServers(cfg serveOptions) (*runningServers, error) {
	if err := validateLoopback(cfg.coreAddress); err != nil {
		return nil, fmt.Errorf("core listener: %w", err)
	}
	if err := validateLoopback(cfg.webAddress); err != nil {
		return nil, fmt.Errorf("web listener: %w", err)
	}
	if err := humanapp.Initialize(cfg.dir); err != nil {
		return nil, err
	}
	store, err := humanapp.OpenStore(filepath.Join(cfg.dir, "human-approval.sqlite"))
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = store.Close()
		}
	}()
	core, err := humanapp.NewCoreServer(cfg.dir, store)
	if err != nil {
		return nil, err
	}
	coreListener, err := net.Listen("tcp", cfg.coreAddress)
	if err != nil {
		return nil, fmt.Errorf("core listener %q: %w; choose another port with --core-listen=127.0.0.1:0", cfg.coreAddress, err)
	}
	defer func() {
		if failed {
			_ = coreListener.Close()
		}
	}()
	webListener, err := net.Listen("tcp", cfg.webAddress)
	if err != nil {
		return nil, fmt.Errorf("browser listener %q: %w; choose another port with --web-listen=127.0.0.1:0", cfg.webAddress, err)
	}
	defer func() {
		if failed {
			_ = webListener.Close()
		}
	}()
	client, err := newClient(cfg.dir, humanapp.ActorGateway, coreListener.Addr().String())
	if err != nil {
		return nil, err
	}
	token, err := humanapp.LoginToken(cfg.dir)
	if err != nil {
		return nil, err
	}
	origin := "http://" + webListener.Addr().String()
	webHandler, err := humanapp.NewWebHandler(humanapp.WebConfig{Origin: origin, LoginToken: token, Execute: client.Execute})
	if err != nil {
		return nil, err
	}
	running := &runningServers{
		coreAddress: coreListener.Addr().String(), webOrigin: origin,
		loginURL: origin + "/#login=" + url.QueryEscape(token), store: store,
		core:   &http.Server{Handler: core.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10},
		web:    &http.Server{Handler: webHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10},
		errors: make(chan error, 2),
	}
	tlsConfig := core.TLSConfig().Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		return nil, errors.New("core transport must require verified client certificates")
	}
	go func() { running.errors <- running.core.Serve(tls.NewListener(coreListener, tlsConfig)) }()
	go func() { running.errors <- running.web.Serve(webListener) }()
	failed = false
	return running, nil
}

func (s *runningServers) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.web.Shutdown(ctx) != nil {
		_ = s.web.Close()
	}
	if s.core.Shutdown(ctx) != nil {
		_ = s.core.Close()
	}
	_ = s.store.Close()
}

func serve(ctx context.Context, cfg serveOptions, stdout, stderr io.Writer) error {
	running, err := startServers(cfg)
	if err != nil {
		return err
	}
	defer running.close()
	if err := writeJSON(stdout, struct {
		Event       string `json:"event"`
		CoreAddress string `json:"core_address"`
		WebOrigin   string `json:"web_origin"`
		LoginURL    string `json:"login_url"`
	}{"ready", running.coreAddress, running.webOrigin, running.loginURL}); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stderr, "\nASB local Human approval is ready.\nOpen this private link in a browser on this computer:\n\n  %s\n\nData directory: %s\nOnly this application's maintenance_mode setting can change; no system setting is modified.\nThe server stays open after a decision. Press Ctrl+C to stop it.\nDo not share the login link or the private data directory.\n\n", running.loginURL, cfg.dir); err != nil {
		return err
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var childDone <-chan error
	if cfg.demo {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		child := exec.CommandContext(childCtx, executable, "agent", "--data-dir", cfg.dir, "--core-address", running.coreAddress, "--enabled="+strconv.FormatBool(cfg.enabled), "--wait")
		child.Stdout, child.Stderr = stdout, stderr
		if err := child.Start(); err != nil {
			return err
		}
		done := make(chan error, 1)
		childDone = done
		go func() { done <- child.Wait() }()
		defer func() {
			cancel()
			if childDone != nil {
				<-childDone
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-running.errors:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case err := <-childDone:
			childDone = nil
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("demo agent stopped; recover using its saved receipt: %w", err)
			}
			// Keep the browser and live inspection available after the decision.
		}
	}
}
