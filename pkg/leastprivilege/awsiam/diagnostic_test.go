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
