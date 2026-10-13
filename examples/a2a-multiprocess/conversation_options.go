// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxConversationPromptBytes = 64 * 1024

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
	if err := validateManagedServerOptions(opts); err != nil {
		return err
	}
	if err := validateManagedModelOptions("Agent A", opts.agentAGGUFPath, opts.agentAGGUFSHA256); err != nil {
		return err
	}
	return nil
}

func validateAgentBConversationOptions(opts options) error {
	if err := rejectUnverifiedConversationOptions(opts); err != nil {
		return err
	}
	if err := validateManagedServerOptions(opts); err != nil {
		return err
	}
	if err := validateManagedModelOptions("Agent B", opts.agentBGGUFPath, opts.agentBGGUFSHA256); err != nil {
		return err
	}
	return nil
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

func validateManagedModelOptions(name, path, digest string) error {
	if !validManagedFilePath(path) {
		return fmt.Errorf("%s GGUF path must be an absolute clean path for llm-conversation", name)
	}
	if !validManagedSHA256(digest) {
		return fmt.Errorf("%s GGUF SHA-256 must be sha256: followed by 64 lowercase hex characters", name)
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
