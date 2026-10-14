// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManagedModelDigestPolicies(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	validManifest := modelDigestPolicy{
		ManifestCID:    "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
		ManifestSHA256: digest,
		Repo:           "owner/model", Revision: strings.Repeat("b", 40), File: "weights/model.gguf",
	}
	for _, test := range []struct {
		name    string
		policy  modelDigestPolicy
		wantErr bool
	}{
		{name: "direct digest", policy: modelDigestPolicy{DirectSHA256: digest}},
		{name: "pinned manifest", policy: validManifest},
		{name: "missing direct digest", wantErr: true},
		{name: "partial manifest", policy: modelDigestPolicy{ManifestCID: validManifest.ManifestCID}, wantErr: true},
		{name: "conflicting sources", policy: modelDigestPolicy{
			DirectSHA256: digest, ManifestCID: validManifest.ManifestCID,
			ManifestSHA256: digest, Repo: validManifest.Repo,
			Revision: validManifest.Revision, File: validManifest.File,
		}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateManagedModelOptions("Agent A", "/tmp/model.gguf", test.policy)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateManagedModelOptions() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
	got, size, err := resolveModelDigest(context.Background(), modelDigestPolicy{DirectSHA256: digest}, "")
	if err != nil || got != digest || size != 0 {
		t.Fatalf("resolve direct digest = %q, size %d, %v", got, size, err)
	}
	if want := []string{
		"--agent-a-gguf-manifest-cid", validManifest.ManifestCID,
		"--agent-a-gguf-manifest-sha256", digest,
		"--agent-a-gguf-repo", validManifest.Repo,
		"--agent-a-gguf-revision", validManifest.Revision,
		"--agent-a-gguf-file", validManifest.File,
	}; !reflect.DeepEqual(modelPolicyArgs("agent-a-gguf", validManifest), want) {
		t.Fatalf("manifest child arguments = %v, want %v", modelPolicyArgs("agent-a-gguf", validManifest), want)
	}
}

func TestConversationWorkflowPinnedIPFSManifests(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	directory := t.TempDir()
	fixture := newManagedConversationFixture(t, directory, "agent-a-output", "agent-b-output")
	promptPath := filepath.Join(directory, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte("authorized prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	const revision = "0123456789abcdef0123456789abcdef01234567"
	aPolicy, aBlock := testPinnedGGUFPolicy(t, fixture.agentASHA256, fixture.agentAPath, "agent-a.gguf", revision)
	bPolicy, bBlock := testPinnedGGUFPolicy(t, fixture.agentBSHA256, fixture.agentBPath, "agent-b.gguf", revision)
	blocks := map[string][]byte{aPolicy.ManifestCID: aBlock, bPolicy.ManifestCID: bBlock}
	kubo := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v0/block/get" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		block, ok := blocks[request.URL.Query().Get("arg")]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = writer.Write(block)
	}))
	defer kubo.Close()
	binary := filepath.Join(directory, "asb-a2a")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build A2A conversation tool: %v\n%s", err, output)
	}
	arguments := []string{
		"--debug-simple", "--workflow", workflowLLMConversation,
		"--prompt-file", promptPath,
		"--llama-server-path", fixture.serverPath,
		"--llama-server-sha256", fixture.serverSHA256,
		"--agent-a-gguf-path", fixture.agentAPath,
		"--agent-b-gguf-path", fixture.agentBPath,
		"--kubo-api-url", kubo.URL,
	}
	arguments = append(arguments, modelPolicyArgs("agent-a-gguf", aPolicy)...)
	arguments = append(arguments, modelPolicyArgs("agent-b-gguf", bPolicy)...)
	run := exec.Command(binary, arguments...)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run A2A LLM conversation with pinned manifests: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("agent-b-output")) {
		t.Fatalf("conversation stdout did not contain Agent B output\n%s", output)
	}
	if got := len(readFakeLlamaTrace(t, fixture.agentATracePath)); got != 1 {
		t.Fatalf("Agent A model calls = %d, want 1", got)
	}
	if got := len(readFakeLlamaTrace(t, fixture.agentBTracePath)); got != 1 {
		t.Fatalf("Agent B model calls = %d, want 1", got)
	}
}

func testPinnedGGUFPolicy(t *testing.T, modelSHA256, modelPath, sourcePath, revision string) (modelDigestPolicy, []byte) {
	t.Helper()
	info, err := os.Stat(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	block, err := json.Marshal(struct {
		Schema   string `json:"schema"`
		Repo     string `json:"repo"`
		Revision string `json:"revision"`
		Path     string `json:"path"`
		SHA256   string `json:"sha256"`
		Size     int64  `json:"size"`
	}{"asb.huggingface-gguf/v1", "owner/model", revision, sourcePath, modelSHA256, info.Size()})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(block)
	cidBytes := append([]byte{1, 0x55, 0x12, sha256.Size}, digest[:]...)
	policy := modelDigestPolicy{
		ManifestCID:    "b" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cidBytes)),
		ManifestSHA256: "sha256:" + hex.EncodeToString(digest[:]),
		Repo:           "owner/model", Revision: revision, File: sourcePath,
	}
	if len(policy.ManifestCID) != 59 {
		t.Fatal(fmt.Errorf("unexpected test CID length %d", len(policy.ManifestCID)))
	}
	return policy, block
}
