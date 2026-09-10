// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const debugUsage = "usage: human-coordination-e2e --debug-simple --report <path>"

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout io.Writer, stderr io.Writer) int {
	flags := flag.NewFlagSet("human-coordination-e2e", flag.ContinueOnError)
	flags.SetOutput(stderr)
	debugSimple := flags.Bool("debug-simple", false, "run the software-only non-production scenario")
	reportPath := flags.String("report", "", "write the deterministic JSON evidence report to this path")
	flags.Usage = func() {
		fmt.Fprintln(stderr, debugUsage)
		fmt.Fprintln(stderr, "This example is simulated, software-only, and makes no production claim.")
	}
	if err := flags.Parse(args); err != nil {
		flags.Usage()
		return 2
	}
	if flags.NArg() != 0 || !*debugSimple || strings.TrimSpace(*reportPath) == "" {
		flags.Usage()
		fmt.Fprintln(stderr, "refusing to run without the explicit debug flag and report path; this is a non-production example")
		return 2
	}

	report, err := runScenario(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "debug-simple scenario failed: %v\n", err)
		return 1
	}
	if err := writeEvidenceReport(*reportPath, report); err != nil {
		fmt.Fprintf(stderr, "write debug-simple report: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "debug-simple evidence report written")
	return 0
}

func writeEvidenceReport(path string, report evidenceReport) error {
	raw, err := marshalEvidenceReport(report)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, raw, 0o644)
}

func marshalEvidenceReport(report evidenceReport) ([]byte, error) {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
