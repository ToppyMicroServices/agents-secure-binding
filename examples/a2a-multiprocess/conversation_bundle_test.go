// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const bundleTestPythonPath = "/tmp/python"

func TestConversationBundleOptions(t *testing.T) {
	t.Parallel()
	digest := "sha256:" + strings.Repeat("a", 64)
	base := options{
		promptFile: "/tmp/prompt.txt", agentAModelDir: "/tmp/model-a",
		agentAModelManifest: "/tmp/model-a.json", agentAModelManifestSHA256: digest,
		llmRequestTimeout: defaultConversationRequestTimeout,
	}
	for _, test := range []struct {
		name    string
		change  func(*options)
		wantErr bool
	}{
		{name: "local bundle without llama options"},
		{name: "IPFS bundle", change: func(opts *options) {
			opts.agentAModelManifest = ""
			opts.agentAModelManifestCID = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
		}},
		{name: "legacy GGUF path", change: func(opts *options) { opts.agentAGGUFPath = "/tmp/model.gguf" }, wantErr: true},
		{name: "legacy direct digest", change: func(opts *options) { opts.agentAGGUFSHA256 = digest }, wantErr: true},
		{name: "legacy manifest setting", change: func(opts *options) { opts.agentAGGUFRepo = "owner/model" }, wantErr: true},
		{name: "multiple manifest sources", change: func(opts *options) { opts.agentAModelManifestCID = "cid" }, wantErr: true},
		{name: "no manifest source", change: func(opts *options) { opts.agentAModelManifest = "" }, wantErr: true},
		{name: "no manifest digest", change: func(opts *options) { opts.agentAModelManifestSHA256 = "" }, wantErr: true},
		{name: "invalid manifest digest", change: func(opts *options) { opts.agentAModelManifestSHA256 = "sha256:untrusted" }, wantErr: true},
		{name: "relative model directory", change: func(opts *options) { opts.agentAModelDir = "models" }, wantErr: true},
		{name: "relative manifest path", change: func(opts *options) { opts.agentAModelManifest = "model.json" }, wantErr: true},
		{name: "partial llama settings", change: func(opts *options) { opts.llamaServerPath = "/tmp/llama-server" }, wantErr: true},
		{name: "verified llama settings", change: func(opts *options) {
			opts.llamaServerPath, opts.llamaServerSHA256 = "/tmp/llama-server", digest
		}},
		{name: "partial Python settings", change: func(opts *options) { opts.pythonPath = bundleTestPythonPath }, wantErr: true},
		{name: "missing Python dependencies", change: func(opts *options) {
			opts.pythonPath, opts.pythonSHA256 = bundleTestPythonPath, digest
		}, wantErr: true},
		{name: "verified Python settings", change: func(opts *options) {
			opts.pythonPath, opts.pythonSHA256, opts.pythonSitePackages = bundleTestPythonPath, digest, "/tmp/site-packages"
			opts.transformersDevice = "mps"
		}},
		{name: "unsupported device", change: func(opts *options) { opts.transformersDevice = "auto" }, wantErr: true},
		{name: "zero request timeout", change: func(opts *options) { opts.llmRequestTimeout = 0 }, wantErr: true},
		{name: "negative request timeout", change: func(opts *options) { opts.llmRequestTimeout = -time.Second }, wantErr: true},
		{name: "excessive request timeout", change: func(opts *options) { opts.llmRequestTimeout = maxConversationRequestTimeout + time.Nanosecond }, wantErr: true},
		{name: "minimum positive request timeout", change: func(opts *options) { opts.llmRequestTimeout = time.Nanosecond }},
		{name: "maximum request timeout", change: func(opts *options) { opts.llmRequestTimeout = maxConversationRequestTimeout }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			opts := base
			if test.change != nil {
				test.change(&opts)
			}
			err := validateAgentAConversationOptions(opts)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateAgentAConversationOptions() = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestConversationBundleChildArguments(t *testing.T) {
	t.Parallel()
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	opts := options{
		workflow: workflowLLMConversation, promptFile: "/tmp/prompt.txt",
		agentAModelDir: "/tmp/model-a", agentAModelManifest: "/tmp/model-a.json", agentAModelManifestSHA256: digestA,
		agentBModelDir: "/tmp/model-b", agentBModelManifestCID: "agent-b-cid", agentBModelManifestSHA256: digestB,
		pythonPath: bundleTestPythonPath, pythonSHA256: digestA, pythonSitePackages: "/tmp/site-packages", transformersDevice: "mps",
		llamaServerPath: "/tmp/llama-server", llamaServerSHA256: digestB, kuboAPIURL: "http://127.0.0.1:5001",
		llmRequestTimeout: 2 * time.Minute,
	}
	for _, test := range []struct {
		name        string
		args        []string
		want        map[string]string
		otherPrefix string
	}{
		{
			name: "Agent A", args: agentAProcessArgs(opts, "state", "manager", "attester", "verifier", "agent-b"),
			want: map[string]string{
				"--agent-a-model-dir": opts.agentAModelDir, "--agent-a-model-manifest": opts.agentAModelManifest,
				"--agent-a-model-manifest-sha256": digestA,
			}, otherPrefix: "--agent-b-model",
		},
		{
			name: "Agent B", args: conversationModelArgs(opts, "agent-b", agentBModelConfig(opts)),
			want: map[string]string{
				"--agent-b-model-dir": opts.agentBModelDir, "--agent-b-model-manifest-cid": opts.agentBModelManifestCID,
				"--agent-b-model-manifest-sha256": digestB,
			}, otherPrefix: "--agent-a-model",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := argumentValues(t, test.args)
			for name, want := range test.want {
				if values[name] != want {
					t.Errorf("%s = %q, want %q", name, values[name], want)
				}
			}
			for name, want := range map[string]string{
				"--python-path": opts.pythonPath, "--python-sha256": opts.pythonSHA256,
				"--python-site-packages": opts.pythonSitePackages, "--transformers-device": opts.transformersDevice,
				"--llama-server-path": opts.llamaServerPath, "--llama-server-sha256": opts.llamaServerSHA256,
				"--kubo-api-url":        opts.kuboAPIURL,
				"--llm-request-timeout": opts.llmRequestTimeout.String(),
			} {
				if values[name] != want {
					t.Errorf("%s = %q, want %q", name, values[name], want)
				}
			}
			for flag := range values {
				if strings.HasPrefix(flag, test.otherPrefix) || strings.Contains(flag, "-gguf-") {
					t.Errorf("unexpected model flag in %s arguments: %s", test.name, flag)
				}
			}
		})
	}
}

func argumentValues(t *testing.T, args []string) map[string]string {
	t.Helper()
	if len(args)%2 != 0 {
		t.Fatalf("expected flag/value pairs: %v", args)
	}
	values := make(map[string]string, len(args)/2)
	for i := 0; i < len(args); i += 2 {
		if _, found := values[args[i]]; found {
			t.Fatalf("duplicate argument %s", args[i])
		}
		values[args[i]] = args[i+1]
	}
	return values
}

func TestConversationWorkflowModelBundlesWithLoRA(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := newManagedConversationFixture(t, directory, "agent-a-output", "agent-b-output")
	aRoot, aManifest, aRaw, aAdapterDigest := writeConversationBundle(t, directory, "a", fixture.agentAPath)
	bRoot, _, bRaw, bAdapterDigest := writeConversationBundle(t, directory, "b", fixture.agentBPath)
	bSum := sha256.Sum256(bRaw)
	bCIDBytes := append([]byte{1, 0x55, 0x12, sha256.Size}, bSum[:]...)
	bCID := "b" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bCIDBytes))
	kubo := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/v0/block/get" || request.URL.Query().Get("arg") != bCID {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = writer.Write(bRaw)
	}))
	defer kubo.Close()
	promptPath := filepath.Join(directory, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte("authorized prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "asb-a2a")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build A2A conversation tool: %v\n%s", err, output)
	}
	arguments := []string{
		"--debug-simple", "--workflow", workflowLLMConversation, "--prompt-file", promptPath,
		"--llama-server-path", fixture.serverPath, "--llama-server-sha256", fixture.serverSHA256,
		"--agent-a-model-dir", aRoot, "--agent-a-model-manifest", aManifest, "--agent-a-model-manifest-sha256", sha256Bytes(aRaw),
		"--agent-b-model-dir", bRoot, "--agent-b-model-manifest-cid", bCID, "--agent-b-model-manifest-sha256", sha256Bytes(bRaw),
		"--kubo-api-url", kubo.URL,
		"--llm-request-timeout", "2m",
	}
	run := exec.Command(binary, arguments...)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run A2A model bundles with LoRA: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("agent-b-output")) {
		t.Fatalf("Agent B output missing\n%s", output)
	}
	for _, test := range []struct{ name, tracePath, digest string }{
		{"Agent A", fixture.agentATracePath, aAdapterDigest},
		{"Agent B", fixture.agentBTracePath, bAdapterDigest},
	} {
		trace := readFakeLlamaTrace(t, test.tracePath)
		if len(trace) != 1 || trace[0].AdapterSHA256 != test.digest {
			t.Fatalf("%s trace = %+v; want one request using approved adapter %s", test.name, trace, test.digest)
		}
	}
}

func writeConversationBundle(t *testing.T, directory, agent, modelPath string) (string, string, []byte, string) {
	t.Helper()
	root := filepath.Join(directory, "bundle-"+agent)
	for _, component := range []string{"model", "adapter"} {
		if err := os.MkdirAll(filepath.Join(root, component), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	model, err := os.ReadFile(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	adapter := []byte("GGUFtest-only-adapter-" + agent)
	for path, data := range map[string][]byte{"model/model.gguf": model, "adapter/lora.gguf": adapter} {
		if err := os.WriteFile(filepath.Join(root, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type file struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	type component struct {
		Format     string `json:"format,omitempty"`
		Entrypoint string `json:"entrypoint"`
		Files      []file `json:"files"`
	}
	manifest := struct {
		Schema  string    `json:"schema"`
		Format  string    `json:"format"`
		Model   component `json:"model"`
		Adapter component `json:"adapter"`
	}{
		Schema: "asb.model-bundle/v1", Format: "gguf",
		Model:   component{Entrypoint: "model.gguf", Files: []file{{"model.gguf", sha256Bytes(model), len(model)}}},
		Adapter: component{Format: "gguf", Entrypoint: "lora.gguf", Files: []file{{"lora.gguf", sha256Bytes(adapter), len(adapter)}}},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest-"+agent+".json")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, manifestPath, raw, sha256Bytes(adapter)
}
