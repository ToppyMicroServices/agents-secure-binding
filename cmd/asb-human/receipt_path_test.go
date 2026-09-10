// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestQuoteReceiptPath(t *testing.T) {
	for _, tc := range []struct{ goos, path, want string }{
		{goosWindows, `C:\Users\A B\receipt.json`, `'C:\Users\A B\receipt.json'`},
		{goosWindows, `C:\O'Brien\$value; & ` + "`" + `.json`, `'C:\O''Brien\$value; & ` + "`" + `.json'`},
		{goosWindows, `C:\‘review’\receipt.json`, `'C:\‘‘review’’\receipt.json'`},
		{"linux", `/tmp/O'Brien/$value; & ` + "`" + `.json`, `'/tmp/O'"'"'Brien/$value; & ` + "`" + `.json'`},
		{"darwin", `/tmp/日本語 folder/receipt.json`, `'/tmp/日本語 folder/receipt.json'`},
	} {
		if got := quoteReceiptPath(tc.path, tc.goos); got != tc.want {
			t.Errorf("quoteReceiptPath(%q, %q) = %q, want %q", tc.path, tc.goos, got, tc.want)
		}
	}
}

// Exercise the actual shell parser and a native child process, not a second
// implementation of the quoting function. CI runs this on each supported OS.
func TestReceiptPathShellRoundTrip(t *testing.T) {
	if os.Getenv("ASB_HUMAN_RECEIPT_PATH_CHILD") == "1" {
		if err := json.NewEncoder(os.Stdout).Encode(os.Args[len(os.Args)-1]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	shell := "sh"
	if runtime.GOOS == goosWindows {
		shell = "pwsh"
	}
	if _, err := exec.LookPath(shell); err != nil {
		t.Fatalf("documented shell %s is required for this test: %v", shell, err)
	}
	for _, path := range []string{
		`C:\Users\A B\receipt.json`,
		`C:\O'Brien\$value; & ` + "`" + `.json`,
		`C:\‘review’\receipt.json`,
		`C:\‚review‛\receipt.json`,
		`/tmp/日本語 folder/$(echo expanded)/receipt.json`,
	} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			script := quoteReceiptPath(executable, runtime.GOOS) + " " + quoteReceiptPath("-test.run=^TestReceiptPathShellRoundTrip$", runtime.GOOS) + " -- " + quoteReceiptPath(path, runtime.GOOS)
			args := []string{"-c", script}
			if runtime.GOOS == goosWindows {
				args = []string{"-NoProfile", "-NonInteractive", "-Command", "& " + script}
			}
			command := exec.CommandContext(ctx, shell, args...)
			command.Env = append(os.Environ(), "ASB_HUMAN_RECEIPT_PATH_CHILD=1")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("shell round trip: %v\n%s", err, output)
			}
			var got string
			if err := json.Unmarshal(output, &got); err != nil || got != path {
				t.Fatalf("argument changed: got %q, want %q; decode error: %v", output, path, err)
			}
		})
	}
}
