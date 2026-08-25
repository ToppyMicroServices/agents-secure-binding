// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thinksyncs/agents-secure-binding/pkg/llmruntime"
)

const (
	agentASystemPrompt       = "You are Agent A. Turn the user's goal into one concise plain-text request for Agent B. Return only the request."
	agentBSystemPrompt       = "You are Agent B. Answer the verified request from Agent A in plain text. Do not claim access to data or tools you do not have."
	maxConversationTextBytes = 128 * 1024
	conversationA2ATimeout   = 35 * time.Second
)

func runAgentAConversation(ctx context.Context, opts options, out outputWriter) (runErr error) {
	if err := validateAgentAConversationOptions(opts); err != nil {
		return err
	}
	reporter, err := newTestRunReporter(opts, out)
	if err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			reporter.recordInfrastructureError()
		}
		if err := reporter.finish(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	for name, value := range map[string]string{
		"manager": opts.managerURL, "attester": opts.attesterURL,
		"verifier": opts.verifierURL, "agent-b": opts.agentBURL,
	} {
		if value == "" {
			return fmt.Errorf("%s URL is required", name)
		}
	}
	prompt, err := readConversationPrompt(opts.promptFile)
	if err != nil {
		return err
	}
	generator, err := newConversationGenerator(opts.agentALLMURL, opts.agentALLMModel, opts.agentAAPIKeyEnv, opts.allowInsecureLLMLoopback)
	if err != nil {
		return fmt.Errorf("configure Agent A LLM: %w", err)
	}

	dir := roleDirectory(opts.stateDir, "agent-a")
	signingKey, err := loadPrivateKey(filepath.Join(dir, signingKeyFile))
	if err != nil {
		return err
	}
	managerClient, err := serviceClient(opts, opts.managerURL)
	if err != nil {
		return err
	}
	attesterClient, err := serviceClient(opts, opts.attesterURL)
	if err != nil {
		return err
	}
	verifierClient, err := serviceClient(opts, opts.verifierURL)
	if err != nil {
		return err
	}
	agentBTLS, err := loadClientTLS(opts.stateDir, "agent-a", opts.agentBURL)
	if err != nil {
		return err
	}
	agentLeaf, err := certificateLeaf(agentBTLS.Certificates[0])
	if err != nil {
		return err
	}
	for _, service := range []struct {
		name   string
		client *http.Client
		url    string
	}{
		{name: "Manager", client: managerClient, url: opts.managerURL},
		{name: "Attester", client: attesterClient, url: opts.attesterURL},
		{name: "Verifier", client: verifierClient, url: opts.verifierURL},
		{name: "Agent B", client: newHTTPClient(agentBTLS.Clone()), url: opts.agentBURL},
	} {
		if err := waitForHealthy(ctx, service.client, service.url, 10*time.Second); err != nil {
			return fmt.Errorf("wait for %s: %w", service.name, err)
		}
	}
	if err := discoverAgentCard(ctx, newHTTPClient(agentBTLS.Clone()), opts.agentBURL); err != nil {
		return err
	}

	reporter.printConversationHeader(opts.attestationMode)
	generated, err := generator.Generate(ctx, llmruntime.Request{System: agentASystemPrompt, Input: prompt})
	if err != nil {
		return fmt.Errorf("Agent A LLM generation failed: %w", err)
	}
	connection, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	request := newTaskRequestWithText(demoResource, generated.Text)
	request, err = issueBoundRequest(ctx, connection, request, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf, nil)
	if err != nil {
		connection.close()
		return err
	}
	result, err := connection.sendWithTimeout(request, a2aVersion, conversationA2ATimeout)
	connection.close()
	if err != nil {
		return err
	}
	if err := reporter.record("ASB-A2A-LLM-001", "selected LLM round trip", "unbound_llm_interaction", result, http.StatusOK, ""); err != nil {
		return err
	}
	responseText, err := completedConversationText(result.task)
	if err != nil {
		return err
	}
	if opts.reportFormat == "text" {
		fmt.Fprintf(out, "\nAgent A -> Agent B:\n%s\n\nAgent B -> Agent A:\n%s\n", generated.Text, responseText)
	}
	return nil
}

func runAgentAConversationV2(ctx context.Context, opts options, out outputWriter) (runErr error) {
	if err := validateAgentAConversationOptions(opts); err != nil {
		return err
	}
	reporter, err := newTestRunReporter(opts, out)
	if err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			reporter.recordInfrastructureError()
		}
		if err := reporter.finish(); runErr == nil && err != nil {
			runErr = err
		}
	}()
	for name, value := range map[string]string{
		"manager": opts.managerURL, "attester": opts.attesterURL,
		"verifier": opts.verifierURL, "agent-b": opts.agentBURL,
	} {
		if value == "" {
			return fmt.Errorf("%s URL is required", name)
		}
	}
	prompt, err := readConversationPrompt(opts.promptFile)
	if err != nil {
		return err
	}
	generator, err := newConversationGenerator(opts.agentALLMURL, opts.agentALLMModel, opts.agentAAPIKeyEnv, opts.allowInsecureLLMLoopback)
	if err != nil {
		return fmt.Errorf("configure Agent A LLM: %w", err)
	}

	dir := roleDirectory(opts.stateDir, "agent-a")
	signingKey, err := loadPrivateKey(filepath.Join(dir, signingKeyFile))
	if err != nil {
		return err
	}
	managerClient, err := serviceClient(opts, opts.managerURL)
	if err != nil {
		return err
	}
	attesterClient, err := serviceClient(opts, opts.attesterURL)
	if err != nil {
		return err
	}
	verifierClient, err := serviceClient(opts, opts.verifierURL)
	if err != nil {
		return err
	}
	agentBTLS, err := loadClientTLS(opts.stateDir, "agent-a", opts.agentBURL)
	if err != nil {
		return err
	}
	agentLeaf, err := certificateLeaf(agentBTLS.Certificates[0])
	if err != nil {
		return err
	}
	for _, service := range []struct {
		name   string
		client *http.Client
		url    string
	}{
		{name: "Manager", client: managerClient, url: opts.managerURL},
		{name: "Attester", client: attesterClient, url: opts.attesterURL},
		{name: "Verifier", client: verifierClient, url: opts.verifierURL},
		{name: "Agent B", client: newHTTPClient(agentBTLS.Clone()), url: opts.agentBURL},
	} {
		if err := waitForHealthy(ctx, service.client, service.url, 10*time.Second); err != nil {
			return fmt.Errorf("wait for %s: %w", service.name, err)
		}
	}
	if err := discoverAgentCardV2(ctx, newHTTPClient(agentBTLS.Clone()), opts.agentBURL); err != nil {
		return err
	}

	reporter.printConversationHeader(opts.attestationMode)
	generated, err := generator.Generate(ctx, llmruntime.Request{System: agentASystemPrompt, Input: prompt})
	if err != nil {
		return fmt.Errorf("Agent A LLM generation failed: %w", err)
	}
	connection, err := dialAgentB(opts.agentBURL, agentBTLS)
	if err != nil {
		return err
	}
	challenge, err := connection.challengeV2()
	if err != nil {
		connection.close()
		return err
	}
	request := newTaskRequestV2()
	request.Message.Parts[0].Text = generated.Text
	request, err = issueBoundRequestV2(ctx, connection, challenge, request, managerClient, opts.managerURL, attesterClient, opts.attesterURL, verifierClient, opts.verifierURL, signingKey, agentLeaf, nil)
	if err != nil {
		connection.close()
		return err
	}
	result, err := connection.sendV2WithTimeout(request, conversationA2ATimeout)
	connection.close()
	if err != nil {
		return err
	}
	if err := reporter.record("ASB-A2A-LLM-001", "selected LLM round trip", "unbound_llm_interaction", result, http.StatusOK, ""); err != nil {
		return err
	}
	responseText, err := completedConversationTextV2(result.task)
	if err != nil {
		return err
	}
	if opts.reportFormat == "text" {
		fmt.Fprintf(out, "\nAgent A -> Agent B:\n%s\n\nAgent B -> Agent A:\n%s\n", generated.Text, responseText)
	}
	return nil
}

func newConversationGenerator(baseURL, model, apiKeyEnvironment string, allowInsecureLoopback bool) (llmruntime.Generator, error) {
	apiKey := ""
	if apiKeyEnvironment != "" {
		apiKey = os.Getenv(apiKeyEnvironment)
	}
	return llmruntime.NewOpenAICompatible(llmruntime.Config{
		BaseURL: baseURL, Model: model, APIKey: apiKey,
		AllowInsecureLoopback: allowInsecureLoopback,
	})
}

func completedConversationText(response a2aTaskResponse) (string, error) {
	task := response.Task
	if task.ID == "" || task.ID == demoTaskID || task.ContextID != demoContextID || task.Status.State != "TASK_STATE_COMPLETED" {
		return "", fmt.Errorf("Agent B returned an invalid completed Task")
	}
	if len(task.Artifacts) != 1 || len(task.Artifacts[0].Parts) != 1 {
		return "", fmt.Errorf("Agent B must return exactly one text artifact")
	}
	part := task.Artifacts[0].Parts[0]
	if part.MediaType != "text/plain" || !validConversationText(part.Text) {
		return "", fmt.Errorf("Agent B returned invalid conversation text")
	}
	return part.Text, nil
}

func completedConversationTextV2(response a2aTaskResponse) (string, error) {
	task := response.Task
	if task.ID != demoTaskID || task.ContextID != demoThreadID || task.Status.State != "TASK_STATE_COMPLETED" {
		return "", fmt.Errorf("Agent B returned an invalid completed draft-06 Task")
	}
	if len(task.Artifacts) != 1 || len(task.Artifacts[0].Parts) != 1 {
		return "", fmt.Errorf("Agent B must return exactly one text artifact")
	}
	part := task.Artifacts[0].Parts[0]
	if part.MediaType != "text/plain" || !validConversationText(part.Text) {
		return "", fmt.Errorf("Agent B returned invalid conversation text")
	}
	return part.Text, nil
}

func validConversationText(value string) bool {
	if !utf8.ValidString(value) || len(value) > maxConversationTextBytes || strings.TrimSpace(value) == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}
