// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

//go:embed transformers_server.py
var transformersServer []byte

// ManagedModelConfig selects a pinned bundle and the runtime for its format.
// GGUF uses ServerPath; Safetensors uses PythonPath and PythonSitePackages.
// Python packages, the standard library, native libraries and OS remain trusted
// deployment dependencies. Their bytes are not covered by PythonSHA256.
type ManagedModelConfig struct {
	Bundle             ModelBundleConfig
	ServerPath         string
	ServerSHA256       string
	PythonPath         string
	PythonSHA256       string
	PythonSitePackages string
	Device             string
	// RequestTimeout bounds one generation. Zero uses 20 seconds; the maximum
	// permitted value is ten minutes.
	RequestTimeout time.Duration
}

// NewManagedModel checks the full base/adapter combination before starting a
// private local server. It supports GGUF with an optional GGUF LoRA, or a local
// Safetensors checkpoint with an optional PEFT LoRA. Remote APIs are not used.
func NewManagedModel(ctx context.Context, config ManagedModelConfig) (*ManagedGGUF, error) {
	if _, err := resolveManagedRequestTimeout(config.RequestTimeout); err != nil {
		return nil, err
	}
	bundle, err := PrepareModelBundle(ctx, config.Bundle)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = bundle.Close()
		}
	}()
	command, err := managedBundleCommand(ctx, bundle, config)
	if err != nil {
		return nil, err
	}
	managed, err := startManagedServer(ctx, bundle.Directory(), command, config.RequestTimeout)
	if err != nil {
		return nil, err
	}
	keep = true
	return managed, nil
}

func managedBundleCommand(ctx context.Context, bundle *PreparedModelBundle, config ManagedModelConfig) (*exec.Cmd, error) {
	dir := bundle.Directory()
	socket := filepath.Join(dir, "llama.sock")
	var command *exec.Cmd
	if bundle.Format() == formatGGUF {
		server := filepath.Join(dir, "llama-server")
		if !validAbsolutePath(config.ServerPath) || !validSHA256(config.ServerSHA256) {
			return nil, fmt.Errorf("%w: GGUF server path and digest", ErrInvalidConfig)
		}
		if err := copyVerifiedFile(config.ServerPath, server, config.ServerSHA256, 0, true); err != nil {
			return nil, err
		}
		arguments := []string{"--model", bundle.ModelPath(), "--alias", managedModelAlias, "--host", socket, "--no-webui"}
		if bundle.HasAdapter() {
			arguments = append(arguments, "--lora", bundle.AdapterPath())
		}
		command = exec.CommandContext(ctx, server, arguments...)
		command.Env = []string{}
	} else {
		var err error
		command, err = transformersCommand(ctx, bundle, config, socket)
		if err != nil {
			return nil, err
		}
	}
	command.Dir = dir
	return command, nil
}

func transformersCommand(ctx context.Context, bundle *PreparedModelBundle, config ManagedModelConfig, socket string) (*exec.Cmd, error) {
	if !validAbsolutePath(config.PythonPath) || !validSHA256(config.PythonSHA256) || !validAbsolutePath(config.PythonSitePackages) {
		return nil, fmt.Errorf("%w: Python executable, digest and trusted package directory required", ErrInvalidConfig)
	}
	info, err := os.Lstat(config.PythonSitePackages)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: Python package directory", ErrInvalidConfig)
	}
	device := config.Device
	if device == "" {
		device = "cpu"
	}
	if device != "cpu" && device != "cuda" && device != "mps" {
		return nil, fmt.Errorf("%w: Transformers device", ErrInvalidConfig)
	}
	dir := bundle.Directory()
	python := filepath.Join(dir, "python")
	if err := copyVerifiedFile(config.PythonPath, python, config.PythonSHA256, 0, true); err != nil {
		return nil, err
	}
	script := filepath.Join(dir, "transformers_server.py")
	if err := os.WriteFile(script, transformersServer, 0o400); err != nil {
		return nil, fmt.Errorf("%w: stage Transformers server", ErrInvalidConfig)
	}
	arguments := []string{
		"-I", "-S", "-B", script,
		"--site-packages", config.PythonSitePackages,
		"--model", bundle.ModelPath(), "--socket", socket, "--device", device,
	}
	if bundle.HasAdapter() {
		arguments = append(arguments, "--adapter", bundle.AdapterPath())
	}
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return nil, fmt.Errorf("%w: private runtime home", ErrInvalidConfig)
	}
	command := exec.CommandContext(ctx, python, arguments...)
	command.Env = []string{
		"HOME=" + home,
		"HF_HOME=" + filepath.Join(home, "huggingface"),
		"HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1", "HF_HUB_DISABLE_TELEMETRY=1",
		"TOKENIZERS_PARALLELISM=false",
	}
	return command, nil
}
