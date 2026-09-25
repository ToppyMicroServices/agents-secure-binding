// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebIdentityIsExplicitRotatesAndDoesNotLeakIntoArguments(t *testing.T) {
	e, _, _, cli := fakeExecutor(t)
	script, err := os.ReadFile(cli)
	if err != nil {
		t.Fatal(err)
	}
	script = []byte(strings.Replace(string(script), "/bin/cat \"$AWS_SHARED_CREDENTIALS_FILE\" > \"$0.creds\"", "for arg in \"$@\"; do case \"$arg\" in file://*) /bin/cat \"${arg#file://}\" > \"$0.token\" ;; esac; done", 1))
	if err = os.WriteFile(cli, script, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(cli), "projected-token")
	e.config.CredentialsFile = ""
	e.config.WebIdentityTokenFile = path
	for _, token := range []string{"header.first.signature", "header.rotated.signature"} {
		if err = os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/untrusted/token")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		_, err = e.assume(ctx, "operation:test", []byte(`{"Version":"2012-10-17","Statement":[]}`))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		captured, err := os.ReadFile(cli + ".token")
		if err != nil || string(captured) != token {
			t.Fatal("did not read current explicit token")
		}
		args, err := os.ReadFile(cli + ".args")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(args), "assume-role-with-web-identity") || !strings.Contains(string(args), "--no-sign-request") || strings.Contains(string(args), token) {
			t.Fatal("wrong STS invocation or token in process arguments")
		}
		env, err := os.ReadFile(cli + ".env")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(env), "/untrusted/token") {
			t.Fatal("ambient token source inherited")
		}
		for _, arg := range strings.Split(string(args), "\n") {
			if private, ok := strings.CutPrefix(arg, "file://"); ok {
				if _, err = os.Stat(private); !os.IsNotExist(err) {
					t.Fatal("private token copy retained")
				}
			}
		}
	}
}

func TestWebIdentityRejectsAmbiguousSourcesAndPublicToken(t *testing.T) {
	e, _, _, cli := fakeExecutor(t)
	path := filepath.Join(filepath.Dir(cli), "token")
	config := e.config
	config.WebIdentityTokenFile = path
	if _, err := NewExecutor(e.profile, config); err == nil {
		t.Fatal("two credential sources accepted")
	}
	config.CredentialsFile = ""
	config.WebIdentityTokenFile = "relative"
	if _, err := NewExecutor(e.profile, config); err == nil {
		t.Fatal("relative token path accepted")
	}
	e.config.CredentialsFile = ""
	e.config.WebIdentityTokenFile = path
	if err := os.WriteFile(path, []byte("header.payload.signature"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := e.assume(ctx, "test", nil); err == nil {
		t.Fatal("public token accepted")
	}
	if _, err := os.Stat(cli + ".args"); !os.IsNotExist(err) {
		t.Fatal("CLI invoked before source validation")
	}
}
