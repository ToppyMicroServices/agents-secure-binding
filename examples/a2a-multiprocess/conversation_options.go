// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
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
	if opts.agentAAPIKeyEnv == opts.agentBAPIKeyEnv {
		return fmt.Errorf("Agent A and Agent B API keys must use different environment variable names")
	}
	redisSecret := effectiveRedisPasswordEnv(opts.redisPasswordEnv)
	if redisSecret == opts.agentAAPIKeyEnv || redisSecret == opts.agentBAPIKeyEnv {
		return fmt.Errorf("Redis and LLM credentials must use different environment variable names")
	}
	return nil
}

func validateAgentAConversationOptions(opts options) error {
	if opts.promptFile == "" {
		return fmt.Errorf("prompt file is required for llm-conversation")
	}
	if opts.agentALLMURL == "" || opts.agentALLMModel == "" {
		return fmt.Errorf("Agent A LLM URL and model are required for llm-conversation")
	}
	if !validEnvironmentName(opts.agentAAPIKeyEnv) {
		return fmt.Errorf("Agent A API key environment variable name is invalid")
	}
	return nil
}

func validateAgentBConversationOptions(opts options) error {
	if opts.agentBLLMURL == "" || opts.agentBLLMModel == "" {
		return fmt.Errorf("Agent B LLM URL and model are required for llm-conversation")
	}
	if !validEnvironmentName(opts.agentBAPIKeyEnv) {
		return fmt.Errorf("Agent B API key environment variable name is invalid")
	}
	return nil
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
	secretNames := []string{redisSecret}
	allowed := ""
	if effectiveAcceptanceStore(opts.acceptanceStore) == acceptanceStoreRedis && role == "replay" {
		allowed = redisSecret
	}
	if effectiveWorkflow(opts.workflow) == workflowLLMConversation {
		if !validEnvironmentName(opts.agentAAPIKeyEnv) || !validEnvironmentName(opts.agentBAPIKeyEnv) {
			return nil, fmt.Errorf("LLM API key environment variable name is invalid")
		}
		if opts.agentAAPIKeyEnv == opts.agentBAPIKeyEnv {
			return nil, fmt.Errorf("Agent A and Agent B API keys must use different environment variable names")
		}
		if redisSecret == opts.agentAAPIKeyEnv || redisSecret == opts.agentBAPIKeyEnv {
			return nil, fmt.Errorf("Redis and LLM credentials must use different environment variable names")
		}
		secretNames = append(secretNames, opts.agentAAPIKeyEnv, opts.agentBAPIKeyEnv)
		switch role {
		case "agent-a":
			allowed = opts.agentAAPIKeyEnv
		case "agent-b":
			allowed = opts.agentBAPIKeyEnv
		}
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
