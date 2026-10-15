// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedRequestTimeoutBounds(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		value   time.Duration
		want    time.Duration
		wantErr bool
	}{
		{name: "default", want: 20 * time.Second},
		{name: "positive", value: time.Nanosecond, want: time.Nanosecond},
		{name: "CPU duration", value: 2 * time.Minute, want: 2 * time.Minute},
		{name: "maximum", value: 10 * time.Minute, want: 10 * time.Minute},
		{name: "negative", value: -time.Nanosecond, wantErr: true},
		{name: "excessive", value: 10*time.Minute + time.Nanosecond, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveManagedRequestTimeout(test.value)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("timeout = %s, %v; want %s, error %v", got, err, test.want, test.wantErr)
			}
			if !test.wantErr {
				return
			}
			if _, err := NewManagedGGUF(context.Background(), ManagedGGUFConfig{RequestTimeout: test.value}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "request timeout") {
				t.Errorf("GGUF did not reject invalid timeout before copying model files: %v", err)
			}
			if _, err := NewManagedModel(context.Background(), ManagedModelConfig{RequestTimeout: test.value}); !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "request timeout") {
				t.Errorf("bundle did not reject invalid timeout before copying model files: %v", err)
			}
			if _, err := startManagedServer(context.Background(), "", nil, test.value); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("server did not reject invalid timeout before starting command: %v", err)
			}
		})
	}
}

func testSHA256(contents []byte) string {
	digest := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestManagedGGUFRequiresTrustedCanonicalDigests(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name   string
		model  string
		server string
	}{
		{name: "missing model", server: good},
		{name: "missing server", model: good},
		{name: "short model", model: "sha256:abc", server: good},
		{name: "uppercase model", model: "sha256:" + strings.Repeat("A", 64), server: good},
		{name: "raw server", model: good, server: strings.Repeat("b", 64)},
		{name: "uppercase server", model: good, server: "sha256:" + strings.Repeat("B", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			managed, err := NewManagedGGUF(context.Background(), ManagedGGUFConfig{
				ModelPath: "/unavailable/model.gguf", ModelSHA256: test.model,
				ServerPath: "/unavailable/llama-server", ServerSHA256: test.server,
			})
			if managed != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewManagedGGUF() = %v, %v; want ErrInvalidConfig", managed, err)
			}
		})
	}
}

func TestManagedGGUFRejectsTamperedBytesBeforeLaunch(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "model.gguf")
	modelContents := []byte("tampered GGUF bytes")
	if err := os.WriteFile(modelPath, modelContents, 0o600); err != nil {
		t.Fatal(err)
	}
	serverPath := filepath.Join(dir, "llama-server")
	serverContents := []byte("#!/bin/sh\n: > \"$ASB_TEST_LAUNCH_MARKER\"\nexit 1\n")
	if err := os.WriteFile(serverPath, serverContents, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "launched")
	t.Setenv("ASB_TEST_LAUNCH_MARKER", marker)
	for _, test := range []struct {
		name         string
		modelDigest  string
		modelSize    int64
		serverDigest string
	}{
		{name: "model bytes differ despite model label", modelDigest: testSHA256([]byte("expected GGUF bytes")), serverDigest: testSHA256(serverContents)},
		{name: "server bytes differ", modelDigest: testSHA256(modelContents), serverDigest: testSHA256([]byte("expected server bytes"))},
		{name: "manifest size differs", modelDigest: testSHA256(modelContents), modelSize: int64(len(modelContents) - 1), serverDigest: testSHA256(serverContents)},
	} {
		t.Run(test.name, func(t *testing.T) {
			managed, err := NewManagedGGUF(context.Background(), ManagedGGUFConfig{
				ModelPath: modelPath, ModelSHA256: test.modelDigest, ModelSize: test.modelSize,
				ServerPath: serverPath, ServerSHA256: test.serverDigest,
			})
			if managed != nil || !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("NewManagedGGUF() = %v, %v; want ErrDigestMismatch", managed, err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("server was launched before both digests matched: %v", err)
			}
		})
	}
}

func TestManagedGGUFRejectsSymlinkAndNonregularSources(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.gguf")
	if err := os.WriteFile(source, []byte("GGUF"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "linked.gguf")
	if err := os.Symlink(source, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{symlink, dir} {
		if err := copyVerifiedFile(path, filepath.Join(dir, "copy.gguf"), testSHA256([]byte("GGUF")), 0, false); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("copyVerifiedFile(%q) error = %v; want ErrInvalidConfig", path, err)
		}
	}
}
