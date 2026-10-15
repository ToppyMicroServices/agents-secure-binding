// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func bundleTestDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func bundleTestFiles(t *testing.T, root, component string, contents map[string]string) []bundleFile {
	t.Helper()
	var names []string
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	var files []bundleFile
	for _, name := range names {
		filename := filepath.Join(root, component, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(contents[name]), 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, bundleFile{Path: name, SHA256: testSHA256([]byte(contents[name])), Size: int64(len(contents[name]))})
	}
	return files
}

func bundleTestPolicy(t *testing.T, root string, manifest modelBundleManifest) ModelBundleConfig {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return bundleTestRawPolicy(t, root, raw)
}

func bundleTestRawPolicy(t *testing.T, root string, raw []byte) ModelBundleConfig {
	t.Helper()
	filename := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(filename, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return ModelBundleConfig{RootPath: root, ManifestPath: filename, ManifestSHA256: testSHA256(raw)}
}

func bundleTestSafetensors(t *testing.T) (string, modelBundleManifest) {
	t.Helper()
	root := bundleTestDirectory(t)
	manifest := modelBundleManifest{Schema: modelBundleSchema, Format: formatSafetensors}
	manifest.Model.Files = bundleTestFiles(t, root, "model", map[string]string{
		"config.json":           `{"model_type":"test"}`,
		"model.safetensors":     "approved base weights",
		"tokenizer.json":        `{"version":"1.0"}`,
		"tokenizer_config.json": `{"chat_template":"approved template"}`,
	})
	return root, manifest
}

func TestPrepareModelBundleCopiesApprovedBaseAndLoRA(t *testing.T) {
	root, manifest := bundleTestSafetensors(t)
	manifest.Adapter = &bundleComponent{Format: formatPEFTLoRA, Files: bundleTestFiles(t, root, "adapter", map[string]string{
		"adapter_config.json":       `{"peft_type":"LORA","base_model_name_or_path":"owner/reviewed-base"}`,
		"adapter_model.safetensors": "approved adaptation",
	})}
	// An undeclared file is never made available to the runtime.
	if err := os.WriteFile(filepath.Join(root, "model", "unapproved.bin"), []byte("pickle"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := bundleTestPolicy(t, root, manifest)
	bundle, err := PrepareModelBundle(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	if bundle.Format() != formatSafetensors || !bundle.HasAdapter() || bundle.ManifestSHA256() != policy.ManifestSHA256 {
		t.Fatal("wrong prepared metadata")
	}
	if bundle.ModelPath() == filepath.Join(root, "model") || bundle.AdapterPath() == filepath.Join(root, "adapter") {
		t.Fatal("runtime received mutable source path")
	}
	for _, component := range []struct {
		source bundleComponent
		dir    string
	}{{manifest.Model, bundle.ModelPath()}, {*manifest.Adapter, bundle.AdapterPath()}} {
		for _, file := range component.source.Files {
			data, err := os.ReadFile(filepath.Join(component.dir, file.Path))
			if err != nil || testSHA256(data) != file.SHA256 {
				t.Fatalf("copied %s differs: %v", file.Path, err)
			}
			info, err := os.Stat(filepath.Join(component.dir, file.Path))
			if err != nil || info.Mode().Perm() != 0o400 {
				t.Fatalf("copied file is not read-only: %v", err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(bundle.ModelPath(), "unapproved.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("undeclared file copied: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "model", "model.safetensors"), []byte("changed after prepare"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(bundle.ModelPath(), "model.safetensors"))
	if err != nil || string(data) != "approved base weights" {
		t.Fatal("source mutation changed prepared model")
	}
	directory := bundle.Directory()
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private copy retained after close: %v", err)
	}
}

func TestPrepareModelBundleGGUFAdapter(t *testing.T) {
	root := bundleTestDirectory(t)
	manifest := modelBundleManifest{
		Schema: modelBundleSchema, Format: formatGGUF,
		Model:   bundleComponent{Entrypoint: "base.gguf", Files: bundleTestFiles(t, root, "model", map[string]string{"base.gguf": "GGUF base"})},
		Adapter: &bundleComponent{Format: formatGGUF, Entrypoint: "tuning.gguf", Files: bundleTestFiles(t, root, "adapter", map[string]string{"tuning.gguf": "GGUF adapter"})},
	}
	bundle, err := PrepareModelBundle(context.Background(), bundleTestPolicy(t, root, manifest))
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	if filepath.Base(bundle.ModelPath()) != "base.gguf" || filepath.Base(bundle.AdapterPath()) != "tuning.gguf" {
		t.Fatal("wrong GGUF entrypoints")
	}
}

func TestPrepareModelBundlePinnedIPFS(t *testing.T) {
	root, manifest := bundleTestSafetensors(t)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, tamper := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/api/v0/block/get" {
				t.Error("wrong Kubo request")
			}
			content := raw
			if tamper {
				content = append(append([]byte(nil), raw...), ' ')
			}
			_, _ = w.Write(content)
		}))
		pinned := testPinnedManifestConfig(raw, server.URL)
		bundle, err := PrepareModelBundle(context.Background(), ModelBundleConfig{
			RootPath: root, ManifestCID: pinned.CID, ManifestSHA256: pinned.ManifestSHA256, KuboAPIURL: server.URL,
		})
		server.Close()
		if tamper {
			if bundle != nil || !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("tampered IPFS manifest accepted: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if err := bundle.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestPrepareModelBundleRejectsChangedApprovedFiles(t *testing.T) {
	for _, filename := range []string{"model.safetensors", "config.json", "tokenizer.json", "tokenizer_config.json", "adapter/adapter_model.safetensors", "adapter/adapter_config.json"} {
		t.Run(filename, func(t *testing.T) {
			root, manifest := bundleTestSafetensors(t)
			manifest.Adapter = &bundleComponent{Format: formatPEFTLoRA, Files: bundleTestFiles(t, root, "adapter", map[string]string{
				"adapter_config.json":       `{"peft_type":"LORA"}`,
				"adapter_model.safetensors": "approved adaptation",
			})}
			policy := bundleTestPolicy(t, root, manifest)
			name := filepath.Join(root, "model", filename)
			if strings.HasPrefix(filename, "adapter/") {
				name = filepath.Join(root, filename)
			}
			if err := os.WriteFile(name, []byte("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
			bundle, err := PrepareModelBundle(context.Background(), policy)
			if bundle != nil || !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("PrepareModelBundle = %v, %v", bundle, err)
			}
		})
	}
}

func TestPrepareModelBundleRejectsUnapprovedCombination(t *testing.T) {
	root, manifest := bundleTestSafetensors(t)
	policy := bundleTestPolicy(t, root, manifest)
	manifest.Adapter = &bundleComponent{Format: formatPEFTLoRA, Files: bundleTestFiles(t, root, "adapter", map[string]string{
		"adapter_config.json":       `{"peft_type":"LORA"}`,
		"adapter_model.safetensors": "unapproved adaptation",
	})}
	changed := bundleTestPolicy(t, root, manifest)
	changed.ManifestSHA256 = policy.ManifestSHA256
	bundle, err := PrepareModelBundle(context.Background(), changed)
	if bundle != nil || !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("changed combination accepted: %v", err)
	}
}

func TestPrepareModelBundleShardedSafetensorsCoverage(t *testing.T) {
	for _, test := range []struct {
		name, index string
		valid       bool
	}{
		{name: "all shards", index: `{"metadata":{"total_size":123},"weight_map":{"layer.a":"model-1.safetensors","layer.b":"nested/model-2.safetensors"}}`, valid: true},
		{name: "undeclared shard", index: `{"weight_map":{"layer.a":"model-1.safetensors","layer.b":"model-3.safetensors"}}`},
		{name: "unused declared shard", index: `{"weight_map":{"layer.a":"model-1.safetensors"}}`},
		{name: "index traversal", index: `{"weight_map":{"layer.a":"../model-1.safetensors"}}`},
		{name: "duplicate tensor", index: `{"weight_map":{"layer.a":"model-1.safetensors","layer.a":"nested/model-2.safetensors"}}`},
		{name: "empty index", index: `{"weight_map":{}}`},
		{name: "wrong type", index: `{"weight_map":{"layer.a":1}}`},
		{name: "wrong member case", index: `{"WEIGHT_MAP":{"layer.a":"model-1.safetensors","layer.b":"nested/model-2.safetensors"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := bundleTestDirectory(t)
			manifest := modelBundleManifest{Schema: modelBundleSchema, Format: formatSafetensors}
			manifest.Model.Files = bundleTestFiles(t, root, "model", map[string]string{
				"config.json": `{}`, "model.safetensors.index.json": test.index,
				"model-1.safetensors": "shard one", "nested/model-2.safetensors": "shard two",
			})
			bundle, err := PrepareModelBundle(context.Background(), bundleTestPolicy(t, root, manifest))
			if test.valid {
				if err != nil {
					t.Fatal(err)
				}
				defer bundle.Close()
			} else if bundle != nil || !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("invalid shard set accepted: %v", err)
			}
		})
	}
}

func TestParseModelBundleRejectsUnsafeDeclarations(t *testing.T) {
	_, base := bundleTestSafetensors(t)
	for _, test := range []struct {
		name   string
		mutate func(*modelBundleManifest)
	}{
		{name: "traversal", mutate: func(m *modelBundleManifest) { m.Model.Files[0].Path = "../config.json" }},
		{name: "absolute", mutate: func(m *modelBundleManifest) { m.Model.Files[0].Path = "/config.json" }},
		{name: "backslash", mutate: func(m *modelBundleManifest) { m.Model.Files[0].Path = `foo\config.json` }},
		{name: "duplicate path", mutate: func(m *modelBundleManifest) { m.Model.Files = append(m.Model.Files, m.Model.Files[0]) }},
		{name: "case collision", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "CONFIG.JSON"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "directory case collision", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "Nested/a.json"
			m.Model.Files = append(m.Model.Files, f)
			f.Path = "nested/b.json"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "file directory collision", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "config.json/file.json"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "pickle", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "pytorch_model.bin"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "remote code", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "modeling.py"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "implicit base adapter", mutate: func(m *modelBundleManifest) {
			f := m.Model.Files[0]
			f.Path = "adapter_config.json"
			m.Model.Files = append(m.Model.Files, f)
		}},
		{name: "no config", mutate: func(m *modelBundleManifest) { m.Model.Files = m.Model.Files[1:] }},
		{name: "negative size", mutate: func(m *modelBundleManifest) { m.Model.Files[0].Size = -1 }},
		{name: "unknown format", mutate: func(m *modelBundleManifest) { m.Format = "pytorch" }},
		{name: "safetensors entrypoint", mutate: func(m *modelBundleManifest) { m.Model.Entrypoint = "model.safetensors" }},
		{name: "adapter format mismatch", mutate: func(m *modelBundleManifest) {
			m.Adapter = &bundleComponent{Format: formatGGUF, Entrypoint: "adapter.gguf", Files: m.Model.Files[:1]}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := base
			m.Model.Files = append([]bundleFile(nil), base.Model.Files...)
			test.mutate(&m)
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseModelBundle(raw); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("unsafe declaration accepted: %v", err)
			}
		})
	}
}

func TestParseModelBundleRejectsAmbiguousJSON(t *testing.T) {
	_, manifest := bundleTestSafetensors(t)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	good := string(raw)
	for _, bad := range []string{
		strings.Replace(good, `"schema":`, `"schema":"asb.model-bundle/v1","schema":`, 1),
		strings.Replace(good, `"path":`, `"path":"ignored","path":`, 1),
		strings.Replace(good, `"schema":`, `"SCHEMA":`, 1),
		strings.Replace(good, `"files":`, `"unknown":true,"files":`, 1),
		good + `{}`, strings.TrimSuffix(good, "}") + `,"adapter":null}`,
	} {
		if _, err := parseModelBundle([]byte(bad)); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("ambiguous JSON accepted: %v", err)
		}
	}
}

func TestPrepareModelBundleRejectsSymlinksAndMissingFiles(t *testing.T) {
	for _, target := range []string{"leaf", "component directory", "root directory", "manifest", "missing"} {
		t.Run(target, func(t *testing.T) {
			root, manifest := bundleTestSafetensors(t)
			policy := bundleTestPolicy(t, root, manifest)
			source := filepath.Join(root, "model", "model.safetensors")
			switch target {
			case "leaf":
				if err := os.Rename(source, source+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(source+".original", source); err != nil {
					t.Fatal(err)
				}
			case "component directory":
				if err := os.Rename(filepath.Join(root, "model"), filepath.Join(root, "original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("original", filepath.Join(root, "model")); err != nil {
					t.Fatal(err)
				}
			case "root directory":
				link := filepath.Join(bundleTestDirectory(t), "linked")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				policy.RootPath = link
			case "manifest":
				if err := os.Rename(policy.ManifestPath, policy.ManifestPath+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(policy.ManifestPath+".original", policy.ManifestPath); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(source); err != nil {
					t.Fatal(err)
				}
			}
			bundle, err := PrepareModelBundle(context.Background(), policy)
			if bundle != nil || !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("unsafe filesystem accepted: %v", err)
			}
		})
	}
}

func TestPrepareModelBundleRejectsOtherPEFTMethods(t *testing.T) {
	for _, config := range []string{`{"peft_type":"IA3"}`, `{"peft_type":"LORA","peft_type":"LORA"}`, `{"PEFT_TYPE":"LORA"}`, `null`} {
		root, manifest := bundleTestSafetensors(t)
		manifest.Adapter = &bundleComponent{Format: formatPEFTLoRA, Files: bundleTestFiles(t, root, "adapter", map[string]string{
			"adapter_config.json": config, "adapter_model.safetensors": "adapter weights",
		})}
		bundle, err := PrepareModelBundle(context.Background(), bundleTestPolicy(t, root, manifest))
		if bundle != nil || !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("non-LoRA/ambiguous config accepted: %v", err)
		}
	}
}

func TestPrepareModelBundleRequiresSingleManifestSource(t *testing.T) {
	root, manifest := bundleTestSafetensors(t)
	policy := bundleTestPolicy(t, root, manifest)
	for _, change := range []func(*ModelBundleConfig){
		func(c *ModelBundleConfig) { c.ManifestPath = "" },
		func(c *ModelBundleConfig) { c.ManifestCID = "also set" },
		func(c *ModelBundleConfig) { c.ManifestSHA256 = "" },
		func(c *ModelBundleConfig) { c.RootPath = "relative" },
	} {
		c := policy
		change(&c)
		bundle, err := PrepareModelBundle(context.Background(), c)
		if bundle != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid policy accepted: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if bundle, err := PrepareModelBundle(ctx, policy); bundle != nil || err == nil {
		t.Fatal("cancelled context accepted")
	}
}
