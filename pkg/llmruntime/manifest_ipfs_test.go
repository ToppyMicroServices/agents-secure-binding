// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const testHFRevision = "0123456789abcdef0123456789abcdef01234567"

func testGGUFManifestBytes() []byte {
	return []byte(fmt.Sprintf(`{"schema":"asb.huggingface-gguf/v1","repo":"owner/model","revision":"%s","path":"weights/model.gguf","sha256":"sha256:%s","size":12345}`,
		testHFRevision, strings.Repeat("a", 64)))
}

func testPinnedManifestConfig(block []byte, apiURL string) PinnedGGUFManifestConfig {
	digest := sha256.Sum256(block)
	cidBytes := append([]byte{1, 0x55, 0x12, sha256.Size}, digest[:]...)
	return PinnedGGUFManifestConfig{
		CID:              "b" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cidBytes)),
		ManifestSHA256:   "sha256:" + hex.EncodeToString(digest[:]),
		KuboAPIURL:       apiURL,
		ExpectedRepo:     "owner/model",
		ExpectedRevision: testHFRevision,
		ExpectedPath:     "weights/model.gguf",
	}
}

func TestResolvePinnedGGUFManifest(t *testing.T) {
	block := testGGUFManifestBytes()
	config := testPinnedManifestConfig(block, "")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v0/block/get" || request.URL.Query().Get("arg") != config.CID {
			t.Errorf("unexpected Kubo request: %s %s", request.Method, request.URL)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/vnd.ipld.raw")
		_, _ = writer.Write(block)
	}))
	defer server.Close()
	config.KuboAPIURL = server.URL
	manifest, err := ResolvePinnedGGUFManifest(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Repo != config.ExpectedRepo || manifest.Revision != config.ExpectedRevision ||
		manifest.Path != config.ExpectedPath || manifest.ModelSHA256 != "sha256:"+strings.Repeat("a", 64) || manifest.Size != 12345 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
}

func TestResolvePinnedGGUFManifestRejectsTamperedBlock(t *testing.T) {
	block := testGGUFManifestBytes()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(append(block, ' '))
	}))
	defer server.Close()
	config := testPinnedManifestConfig(block, server.URL)
	_, err := ResolvePinnedGGUFManifest(context.Background(), config)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered block error = %v; want ErrDigestMismatch", err)
	}
}

func TestResolvePinnedGGUFManifestRejectsUnavailableBlock(t *testing.T) {
	block := testGGUFManifestBytes()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	_, err := ResolvePinnedGGUFManifest(context.Background(), testPinnedManifestConfig(block, server.URL))
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("unavailable block error = %v; want ErrProvider", err)
	}
}

func TestResolvePinnedGGUFManifestRejectsOversizedBlock(t *testing.T) {
	block := make([]byte, maxGGUFManifestBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(block)
	}))
	defer server.Close()
	_, err := ResolvePinnedGGUFManifest(context.Background(), testPinnedManifestConfig(block, server.URL))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("oversized block error = %v; want ErrInvalidManifest", err)
	}
}

func TestResolvePinnedGGUFManifestRejectsRedirect(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		http.Redirect(writer, request, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	_, err := ResolvePinnedGGUFManifest(context.Background(), testPinnedManifestConfig(testGGUFManifestBytes(), server.URL))
	if !errors.Is(err, ErrProvider) || calls.Load() != 1 {
		t.Fatalf("redirect error = %v, calls = %d; want ErrProvider and one call", err, calls.Load())
	}
}

func TestResolvePinnedGGUFManifestRejectsWrongSchema(t *testing.T) {
	good := string(testGGUFManifestBytes())
	for _, test := range []struct {
		name  string
		block string
	}{
		{name: "unknown member", block: strings.Replace(good, `"size":12345`, `"size":12345,"extra":true`, 1)},
		{name: "missing member", block: strings.Replace(good, `,"size":12345`, "", 1)},
		{name: "duplicate member", block: strings.Replace(good, `"size":12345`, `"size":12345,"size":12345`, 1)},
		{name: "wrong schema", block: strings.Replace(good, `asb.huggingface-gguf/v1`, `other`, 1)},
		{name: "not full commit", block: strings.Replace(good, testHFRevision, `main`, 1)},
		{name: "traversal path", block: strings.Replace(good, `weights/model.gguf`, `../model.gguf`, 1)},
		{name: "invalid size", block: strings.Replace(good, `"size":12345`, `"size":-1`, 1)},
		{name: "wrong size type", block: strings.Replace(good, `"size":12345`, `"size":"12345"`, 1)},
		{name: "trailing JSON", block: good + ` {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(test.block))
			}))
			defer server.Close()
			_, err := ResolvePinnedGGUFManifest(context.Background(), testPinnedManifestConfig([]byte(test.block), server.URL))
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("schema error = %v; want ErrInvalidManifest", err)
			}
		})
	}
}

func TestResolvePinnedGGUFManifestRejectsIdentityMismatch(t *testing.T) {
	block := testGGUFManifestBytes()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(block)
	}))
	defer server.Close()
	config := testPinnedManifestConfig(block, server.URL)
	config.ExpectedRepo = "another/model"
	_, err := ResolvePinnedGGUFManifest(context.Background(), config)
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("identity mismatch error = %v; want ErrInvalidManifest", err)
	}
}

func TestResolvePinnedGGUFManifestRejectsUnsafeConfig(t *testing.T) {
	block := testGGUFManifestBytes()
	for _, test := range []struct {
		name   string
		mutate func(*PinnedGGUFManifestConfig)
	}{
		{name: "missing digest", mutate: func(config *PinnedGGUFManifestConfig) { config.ManifestSHA256 = "" }},
		{name: "CID mismatch", mutate: func(config *PinnedGGUFManifestConfig) { config.ManifestSHA256 = "sha256:" + strings.Repeat("0", 64) }},
		{name: "invalid CID", mutate: func(config *PinnedGGUFManifestConfig) { config.CID = "../bad" }},
		{name: "nonloopback API", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL = "http://192.0.2.1:5001" }},
		{name: "DNS API", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL = "http://localhost:5001" }},
		{name: "API path", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL += "/api" }},
		{name: "API query", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL += "?arg=bad" }},
		{name: "empty API query", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL += "?" }},
		{name: "API fragment", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL += "#" }},
		{name: "API credentials", mutate: func(config *PinnedGGUFManifestConfig) { config.KuboAPIURL = "http://user:pass@127.0.0.1:5001" }},
		{name: "moving revision", mutate: func(config *PinnedGGUFManifestConfig) { config.ExpectedRevision = "main" }},
		{name: "unsafe path", mutate: func(config *PinnedGGUFManifestConfig) { config.ExpectedPath = "../model.gguf" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testPinnedManifestConfig(block, "http://127.0.0.1:5001")
			test.mutate(&config)
			_, err := ResolvePinnedGGUFManifest(context.Background(), config)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("unsafe config error = %v; want ErrInvalidConfig", err)
			}
		})
	}
}
