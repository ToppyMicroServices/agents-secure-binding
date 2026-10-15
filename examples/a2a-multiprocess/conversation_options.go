// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxConversationPromptBytes        = 64 * 1024
	defaultConversationRequestTimeout = 20 * time.Second
	maxConversationRequestTimeout     = 10 * time.Minute
)

func conversationRequestTimeout(opts options) time.Duration {
	if opts.llmRequestTimeout == 0 {
		return defaultConversationRequestTimeout
	}
	return opts.llmRequestTimeout
}

func conversationA2ATimeout(opts options) time.Duration {
	return conversationRequestTimeout(opts) + 15*time.Second
}

func validateConversationOptions(opts options) error {
	if err := validateAgentAConversationOptions(opts); err != nil {
		return err
	}
	if err := validateAgentBConversationOptions(opts); err != nil {
		return err
	}
	return nil
}

func validateAgentAConversationOptions(opts options) error {
	if err := rejectUnverifiedConversationOptions(opts); err != nil {
		return err
	}
	if opts.promptFile == "" {
		return fmt.Errorf("prompt file is required for llm-conversation")
	}
	return validateConversationModelOptions(opts, "Agent A", agentAModelConfig(opts))
}

func validateAgentBConversationOptions(opts options) error {
	if err := rejectUnverifiedConversationOptions(opts); err != nil {
		return err
	}
	return validateConversationModelOptions(opts, "Agent B", agentBModelConfig(opts))
}

func rejectUnverifiedConversationOptions(opts options) error {
	for _, legacy := range []struct {
		flag  string
		value string
	}{
		{"--agent-a-llm-url", opts.agentALLMURL},
		{"--agent-a-llm-model", opts.agentALLMModel},
		{"--agent-b-llm-url", opts.agentBLLMURL},
		{"--agent-b-llm-model", opts.agentBLLMModel},
	} {
		if legacy.value != "" {
			return fmt.Errorf("%s cannot be used for llm-conversation: model weights cannot be verified through an external endpoint", legacy.flag)
		}
	}
	if opts.allowInsecureLLMLoopback {
		return fmt.Errorf("--allow-insecure-llm-loopback cannot be used for llm-conversation")
	}
	return nil
}

func validateManagedServerOptions(opts options) error {
	if !validManagedFilePath(opts.llamaServerPath) {
		return fmt.Errorf("--llama-server-path must be an absolute clean path for llm-conversation")
	}
	if !validManagedSHA256(opts.llamaServerSHA256) {
		return fmt.Errorf("--llama-server-sha256 must be sha256: followed by 64 lowercase hex characters")
	}
	return nil
}

func validateConversationModelOptions(opts options, name string, config conversationModelConfig) error {
	if opts.llmRequestTimeout <= 0 || opts.llmRequestTimeout > maxConversationRequestTimeout {
		return fmt.Errorf("--llm-request-timeout must be positive and at most 10m")
	}
	if err := validatePythonOptions(opts); err != nil {
		return err
	}
	if !config.usesBundle() {
		if err := validateManagedServerOptions(opts); err != nil {
			return err
		}
		return validateManagedModelOptions(name, config.GGUFPath, config.GGUFPolicy)
	}
	if config.GGUFPath != "" || config.GGUFPolicy != (modelDigestPolicy{}) {
		return fmt.Errorf("%s model bundle and legacy GGUF settings are mutually exclusive", name)
	}
	if opts.llamaServerPath != "" || opts.llamaServerSHA256 != "" {
		if err := validateManagedServerOptions(opts); err != nil {
			return err
		}
	}
	if !validManagedFilePath(config.Bundle.RootPath) {
		return fmt.Errorf("%s model directory must be an absolute clean path", name)
	}
	if (config.Bundle.ManifestPath == "") == (config.Bundle.ManifestCID == "") {
		return fmt.Errorf("%s model bundle requires exactly one local manifest or manifest CID", name)
	}
	if config.Bundle.ManifestPath != "" && !validManagedFilePath(config.Bundle.ManifestPath) {
		return fmt.Errorf("%s model manifest must be an absolute clean path", name)
	}
	if !validManagedSHA256(config.Bundle.ManifestSHA256) {
		return fmt.Errorf("%s model manifest requires a trusted SHA-256 digest", name)
	}
	return nil
}

func validatePythonOptions(opts options) error {
	if opts.pythonPath != "" || opts.pythonSHA256 != "" || opts.pythonSitePackages != "" {
		if !validManagedFilePath(opts.pythonPath) || !validManagedSHA256(opts.pythonSHA256) ||
			!validManagedFilePath(opts.pythonSitePackages) {
			return fmt.Errorf("Python runtime requires absolute clean --python-path and --python-site-packages paths and a trusted --python-sha256 digest")
		}
	}
	switch opts.transformersDevice {
	case "", "cpu", "cuda", "mps":
		return nil
	default:
		return fmt.Errorf("--transformers-device must be cpu, cuda, or mps")
	}
}

func validateManagedModelOptions(name, path string, policy modelDigestPolicy) error {
	if !validManagedFilePath(path) {
		return fmt.Errorf("%s GGUF path must be an absolute clean path for llm-conversation", name)
	}
	if policy.ManifestCID == "" {
		if policy.ManifestSHA256 != "" || policy.Repo != "" || policy.Revision != "" || policy.File != "" {
			return fmt.Errorf("%s GGUF manifest settings require a CID", name)
		}
		if !validManagedSHA256(policy.DirectSHA256) {
			return fmt.Errorf("%s GGUF SHA-256 must be sha256: followed by 64 lowercase hex characters", name)
		}
		return nil
	}
	if policy.DirectSHA256 != "" {
		return fmt.Errorf("%s GGUF direct digest and DHT manifest are mutually exclusive", name)
	}
	if !validManagedSHA256(policy.ManifestSHA256) || policy.Repo == "" || policy.Revision == "" || policy.File == "" {
		return fmt.Errorf("%s GGUF manifest requires a trusted digest and exact Hugging Face source", name)
	}
	return nil
}

func validManagedFilePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func validManagedSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, digit := range value[len("sha256:"):] {
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func readConversationPrompt(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open conversation prompt: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect conversation prompt: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("conversation prompt must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConversationPromptBytes+1))
	if err != nil {
		return "", fmt.Errorf("read conversation prompt: %w", err)
	}
	if len(raw) > maxConversationPromptBytes {
		return "", fmt.Errorf("conversation prompt exceeds %d bytes", maxConversationPromptBytes)
	}
	if !utf8.Valid(raw) || strings.TrimSpace(string(raw)) == "" {
		return "", fmt.Errorf("conversation prompt must be non-empty UTF-8 text")
	}
	return string(raw), nil
}

func orchestratorChildEnvironment(opts options, role string) ([]string, error) {
	redisSecret := effectiveRedisPasswordEnv(opts.redisPasswordEnv)
	if !validEnvironmentName(redisSecret) {
		return nil, fmt.Errorf("Redis password environment variable name is invalid")
	}
	for _, legacyName := range []string{opts.agentAAPIKeyEnv, opts.agentBAPIKeyEnv} {
		if legacyName != "" && !validEnvironmentName(legacyName) {
			return nil, fmt.Errorf("legacy LLM API key environment variable name is invalid")
		}
	}
	secretNames := []string{redisSecret, "ASB_AGENT_A_LLM_API_KEY", "ASB_AGENT_B_LLM_API_KEY", opts.agentAAPIKeyEnv, opts.agentBAPIKeyEnv}
	allowed := ""
	if effectiveAcceptanceStore(opts.acceptanceStore) == acceptanceStoreRedis && role == "replay" {
		allowed = redisSecret
	}
	return isolateSecretEnvironment(os.Environ(), allowed, secretNames...), nil
}

func isolateSecretEnvironment(base []string, allowed string, secretNames ...string) []string {
	secrets := make(map[string]struct{}, len(secretNames))
	for _, name := range secretNames {
		secrets[name] = struct{}{}
	}
	filtered := make([]string, 0, len(base))
	allowedEntry := ""
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, secret := secrets[name]; !secret {
			filtered = append(filtered, entry)
			continue
		}
		if name == allowed {
			allowedEntry = entry
		}
	}
	if allowedEntry != "" {
		filtered = append(filtered, allowedEntry)
	}
	return filtered
}

func validEnvironmentName(value string) bool {
	if value == "" || len(value) > 128 || !strings.HasPrefix(value, "ASB_") {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if i == 0 {
			if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
			continue
		}
		if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
