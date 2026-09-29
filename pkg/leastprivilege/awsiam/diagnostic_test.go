// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProviderDiagnosticStagesDiscardPrivateText(t *testing.T) {
	for _, stage := range []string{"identity", "sts", "s3"} {
		t.Run(stage, func(t *testing.T) {
			e, solution, request, cli := fakeExecutor(t)
			secret := "private-fixture-token-do-not-log"
			switch stage {
			case "identity":
				e.config.CredentialsFile = cli + ".missing"
			case "sts":
				if err := os.WriteFile(cli, []byte("#!/bin/sh\nprintf '%s' '{\"Code\":\"AccessDenied\",\"Message\":\""+secret+"\"}' >&2\nexit 1\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "s3":
				e.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(secret) })
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err := e.Execute(ctx, "operation:diagnostic", request, solution)
			got, code := Diagnostic(err)
			if err == nil || got != stage || code == "" || strings.Contains(code, secret) {
				t.Fatalf("stage %s got %s/%s", stage, got, code)
			}
		})
	}
}

func TestSTSDiagnosticParsingExplainsUnclassifiedFailures(t *testing.T) {
	for _, tc := range []struct {
		name, raw, format, parse, provider string
	}{
		{"empty", "\n", "empty", "unrecognized", ""},
		{"missing_code", `{"Message":"private-text"}`, "json", "missing_code", ""},
		{"unknown_code", `{"Code":"PrivateSecret"}`, "json", "unknown_code", ""},
		{"wrong_type", `{"Code":{"private":"secret"}}`, "json", "invalid_fields", ""},
		{"partial_json", `{"Code":"ExpiredToken"`, "invalid_json", "invalid_json", ""},
		{"trailing_json", `{"Code":"ExpiredToken"} private-text`, "invalid_json", "invalid_json", ""},
		{"json_with_legacy_line", "{\"Code\":\"PrivateSecret\"\nAn error occurred (ExpiredToken) when calling the AssumeRole operation: private-text", "invalid_json", "invalid_json", ""},
		{"json_array_with_legacy_line", "[\nAn error occurred (ExpiredToken) when calling the AssumeRole operation: private-text", "invalid_json", "invalid_json", ""},
		{"traceback", "Traceback (most recent call last):\nprivate-token", "traceback", "unrecognized", ""},
		{"cli_text", "aws: [ERROR]: private-token", "cli_text", "unrecognized", ""},
		{"plain_text", "private-token", "text", "unrecognized", ""},
		{"known_json", `{"Code":"ExpiredTokenException","Message":"private-token"}`, "json", "classified", "ExpiredTokenException"},
		{"legacy", "An error occurred (AccessDenied) when calling the AssumeRole operation: private-token", "legacy", "classified", "AccessDenied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, detail := stsErrorDiagnostic([]byte(tc.raw))
			if detail.Format != tc.format || detail.Parse != tc.parse || detail.ProviderCode != tc.provider || detail.StderrBytes != len(tc.raw) {
				t.Fatalf("incorrect diagnostic classification: %+v", detail)
			}
			if tc.provider == "" && code != "unclassified failure" {
				t.Fatal("unclassified error became a provider diagnosis")
			}
		})
	}
}
