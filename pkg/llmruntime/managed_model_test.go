// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestManagedTransformersCommandUsesPrivateBundle(t *testing.T) {
	root, manifest := bundleTestSafetensors(t)
	manifest.Adapter = &bundleComponent{Format: formatPEFTLoRA, Files: bundleTestFiles(t, root, "adapter", map[string]string{
		"adapter_config.json": `{"peft_type":"LORA"}`, "adapter_model.safetensors": "approved LoRA",
	})}
	bundle, err := PrepareModelBundle(context.Background(), bundleTestPolicy(t, root, manifest))
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	interpreter := filepath.Join(root, "python")
	interpreterBytes := []byte("test interpreter; never executed")
	if err := os.WriteFile(interpreter, interpreterBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	packages := filepath.Join(root, "site-packages")
	if err := os.Mkdir(packages, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", "/untrusted/packages")
	t.Setenv("HF_TOKEN", "must-not-be-inherited")
	command, err := managedBundleCommand(context.Background(), bundle, ManagedModelConfig{
		PythonPath: interpreter, PythonSHA256: testSHA256(interpreterBytes), PythonSitePackages: packages,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(bundle.Directory(), "python"), "-I", "-S", "-B",
		filepath.Join(bundle.Directory(), "transformers_server.py"), "--site-packages", packages,
		"--model", bundle.ModelPath(), "--socket", filepath.Join(bundle.Directory(), "llama.sock"),
		"--device", "cpu", "--adapter", bundle.AdapterPath(),
	}
	if !reflect.DeepEqual(command.Args, want) || command.Dir != bundle.Directory() {
		t.Fatalf("unexpected command: %v in %s", command.Args, command.Dir)
	}
	environment := strings.Join(command.Env, "\n")
	if strings.Contains(environment, "PYTHONPATH") || strings.Contains(environment, "HF_TOKEN") ||
		!strings.Contains(environment, "HF_HUB_OFFLINE=1") || !strings.Contains(environment, "TRANSFORMERS_OFFLINE=1") {
		t.Fatal("unsafe child environment")
	}
	staged, err := os.ReadFile(command.Path)
	if err != nil || string(staged) != string(interpreterBytes) {
		t.Fatal("interpreter was not copied and pinned")
	}
	staged, err = os.ReadFile(command.Args[4])
	if err != nil || string(staged) != string(transformersServer) {
		t.Fatal("server script differs from embedded code")
	}
}

// This opt-in test uses actual tiny local Safetensors and PEFT fixtures made by
// scripts/test-llm-safetensors.py. Normal Go tests need no Python dependencies.
func TestManagedSafetensorsIntegration(t *testing.T) {
	filename := os.Getenv("ASB_SAFETENSORS_TEST_CONFIG")
	if filename == "" {
		t.Skip("set ASB_SAFETENSORS_TEST_CONFIG to run real local inference")
	}
	var fixture struct {
		PythonPath         string `json:"python_path"`
		PythonSHA256       string `json:"python_sha256"`
		PythonSitePackages string `json:"python_site_packages"`
		Bundles            []struct {
			Name           string `json:"name"`
			RootPath       string `json:"root_path"`
			ManifestPath   string `json:"manifest_path"`
			ManifestSHA256 string `json:"manifest_sha256"`
		} `json:"bundles"`
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Bundles) < 3 {
		t.Fatalf("invalid integration fixture: %v", err)
	}
	for _, entry := range fixture.Bundles {
		t.Run(entry.Name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			managed, err := NewManagedModel(ctx, ManagedModelConfig{
				Bundle:     ModelBundleConfig{RootPath: entry.RootPath, ManifestPath: entry.ManifestPath, ManifestSHA256: entry.ManifestSHA256},
				PythonPath: fixture.PythonPath, PythonSHA256: fixture.PythonSHA256,
				PythonSitePackages: fixture.PythonSitePackages, Device: "cpu",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer managed.Close()
			response, err := managed.Generate(ctx, Request{System: "Reply briefly.", Input: "Hello"})
			if err != nil || strings.TrimSpace(response.Text) == "" {
				t.Fatalf("real local inference: %+v, %v", response, err)
			}
		})
	}
}
