// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// asb-leastprivilege-proof creates or independently checks finite proof trees.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	lp "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/leastprivilege/certificate"
)

const commandGenerate = "generate"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != commandGenerate && args[0] != "check") {
		return errors.New("usage: asb-leastprivilege-proof generate|check --problem file --solution file [--proof file]")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	problemPath := flags.String("problem", "", "trusted finite problem JSON")
	solutionPath := flags.String("solution", "", "candidate solution JSON")
	proofPath := flags.String("proof", "", "certificate JSON (check only)")
	budget := flags.Uint64("max-nodes", certificate.MaxNodes, "positive proof-node work limit")
	timeout := flags.Duration("timeout", 5*time.Second, "positive evaluation deadline")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *problemPath == "" || *solutionPath == "" || *timeout <= 0 || *budget == 0 {
		return errors.New("problem, solution, positive timeout and positive node budget are required; no positional arguments")
	}
	if (args[0] == commandGenerate && *proofPath != "") || (args[0] == "check" && *proofPath == "") {
		return errors.New("--proof is required only for check")
	}
	var problem lp.Problem
	var solution lp.Solution
	if err := readJSON(*problemPath, &problem); err != nil {
		return err
	}
	if err := readJSON(*solutionPath, &solution); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if args[0] == commandGenerate {
		proof, _, err := certificate.Generate(ctx, problem, solution, *budget)
		if err != nil {
			return err
		}
		return encoder.Encode(proof)
	}
	var proof certificate.Proof
	if err := readJSON(*proofPath, &proof); err != nil {
		return err
	}
	stats, err := certificate.Check(ctx, problem, solution, proof, *budget)
	if err != nil {
		return err
	}
	return encoder.Encode(struct {
		Verified      bool              `json:"verified"`
		ProblemDigest string            `json:"problem_digest"`
		Cost          uint64            `json:"cost"`
		Stats         certificate.Stats `json:"stats"`
	}{true, solution.ProblemDigest, solution.Cost, stats})
}
