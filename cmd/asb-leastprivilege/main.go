// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// asb-leastprivilege exposes the bounded optimizer and independent checker to
// agents as a JSON CLI. It never changes cloud IAM or sends prompts externally.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
)

const commandSolve = "solve"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: asb-leastprivilege demo|solve|verify [flags]")
	}
	if args[0] == "demo" {
		if len(args) != 1 {
			return errors.New("demo takes no arguments")
		}
		return demo(out)
	}
	if args[0] != commandSolve && args[0] != "verify" {
		return fmt.Errorf("unknown command %q", args[0])
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	problemPath := fs.String("problem", "", "trusted problem JSON file")
	solutionPath := fs.String("solution", "", "candidate solution JSON file (verify only)")
	budget := fs.Uint64("max-evaluations", 1<<lp.MaxGrants, "maximum evaluated subsets; exhaustion fails closed")
	timeout := fs.Duration("timeout", 5*time.Second, "positive search deadline")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *problemPath == "" || *timeout <= 0 {
		return errors.New("a problem file and positive timeout are required; no positional arguments")
	}
	if (args[0] == commandSolve && *solutionPath != "") || (args[0] == "verify" && *solutionPath == "") {
		return errors.New("--solution is required only for verify")
	}
	var problem lp.Problem
	if err := readJSON(*problemPath, &problem); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if args[0] == commandSolve {
		solution, err := lp.Solve(ctx, problem, *budget)
		if err != nil {
			return err
		}
		return writeJSON(out, solution)
	}
	var candidate lp.Solution
	if err := readJSON(*solutionPath, &candidate); err != nil {
		return err
	}
	if err := lp.Verify(ctx, problem, candidate, *budget); err != nil {
		return err
	}
	return writeJSON(out, struct {
		Verified      bool   `json:"verified"`
		ProblemDigest string `json:"problem_digest"`
		Cost          uint64 `json:"cost"`
	}{true, candidate.ProblemDigest, candidate.Cost})
}

// Strict JSON input avoids ambiguous model/proof interpretation at the CLI.
func readJSON(path string, target any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return err
	}
	if len(raw) > limit {
		return errors.New("JSON input exceeds 1 MiB")
	}
	if err := uniqueKeys(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON input must contain exactly one value")
	}
	return nil
}

func uniqueKeys(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds 32 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON object key")
			}
			seen[name] = true
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueKeys(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// demo performs one local read through the consumption boundary. No real IAM
// credentials, cloud effects, human identities, or remote AI calls are involved.
func demo(out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	problem := lp.Problem{
		Schema:      lp.ProblemSchemaV1,
		Permissions: []lp.Permission{{ID: "reports.read", Cost: 1}, {ID: "reports.write", Cost: 10}},
		Grants: []lp.Grant{
			{ID: "reader", Permissions: []string{"reports.read"}},
			{ID: "editor", Permissions: []string{"reports.read", "reports.write"}},
		},
		Required: []string{"reports.read"}, Allowed: []string{"reports.read", "reports.write"},
	}
	solution, err := lp.Solve(ctx, problem, 4)
	if err != nil {
		return err
	}
	if err := lp.Verify(ctx, problem, solution, 4); err != nil {
		return err
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	request := lp.Request{
		ActorID: "agent:demo", TaskID: "task:read-report",
		Action: lp.Action{Operation: "read", Resource: "report:demo", Arguments: []byte("version=1")},
	}
	ad, err := lp.DigestAction(request.Action)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	mandate := lp.Mandate{
		ID: "mandate:demo-once", PolicyRef: "policy:demo-v1", ActorID: request.ActorID,
		TaskID: request.TaskID, ActionDigest: ad, ProblemDigest: solution.ProblemDigest,
		NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute), MaxTTLSeconds: 30, AllowAutomatic: true,
	}
	newAuthorizer := func(m lp.Mandate) (*lp.Authorizer, error) {
		return lp.NewAuthorizer(lp.AuthorizerConfig{Problem: problem, Mandate: m, SigningKey: private, MaxEvaluations: 4})
	}
	issuer, err := newAuthorizer(mandate)
	if err != nil {
		return err
	}
	cap, err := issuer.Authorize(ctx, request, solution)
	if err != nil {
		return err
	}
	uses, err := lp.NewMemoryUseStore(8)
	if err != nil {
		return err
	}
	if err := lp.ConsumeCapability(ctx, cap, pub, mandate, request, time.Now(), uses); err != nil {
		return err
	}
	// This dispatch consumes only the exact verified request. A cloud adapter
	// must likewise restrict its credentials and enforce the permission model.
	if request.Action.Operation != "read" || request.Action.Resource != "report:demo" || string(request.Action.Arguments) != "version=1" {
		return errors.New("unsupported local demo effect")
	}
	localResult := "demo report: 42"
	replay := lp.ConsumeCapability(ctx, cap, pub, mandate, request, time.Now(), uses)
	if !errors.Is(replay, lp.ErrReplay) {
		return fmt.Errorf("expected replay rejection, got %v", replay)
	}
	humanMandate := mandate
	humanMandate.AllowAutomatic = false
	humanIssuer, err := newAuthorizer(humanMandate)
	if err != nil {
		return err
	}
	_, humanErr := humanIssuer.Authorize(ctx, request, solution)
	if !errors.Is(humanErr, lp.ErrHumanRequired) {
		return fmt.Errorf("expected human gate, got %v", humanErr)
	}
	tampered := request
	tampered.Action.Resource = "report:other"
	if err := lp.CheckCapability(cap, pub, mandate, tampered, time.Now()); !errors.Is(err, lp.ErrBinding) {
		return fmt.Errorf("expected action binding rejection, got %v", err)
	}
	return writeJSON(out, struct {
		Mode                       string        `json:"mode"`
		Solution                   lp.Solution   `json:"solution"`
		Capability                 lp.Capability `json:"capability"`
		PublicKey                  []byte        `json:"public_key"`
		Mandate                    lp.Mandate    `json:"mandate"`
		Result                     string        `json:"executed_result"`
		ReplayRejected             bool          `json:"replay_rejected"`
		HumanGatePreserved         bool          `json:"human_gate_preserved"`
		ActionSubstitutionRejected bool          `json:"action_substitution_rejected"`
	}{"local-reference-demo", solution, cap, pub, mandate, localResult, true, true, true})
}
