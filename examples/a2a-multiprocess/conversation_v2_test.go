// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thinksyncs/agents-secure-binding/pkg/a2asecuritytest"
	"github.com/thinksyncs/agents-secure-binding/pkg/atls/identitypolicy"
	"github.com/thinksyncs/agents-secure-binding/pkg/clients"
	"github.com/thinksyncs/agents-secure-binding/pkg/llmruntime"
)

type recordingConversationGeneratorV2 struct {
	calls    int
	request  llmruntime.Request
	response llmruntime.Response
}

func (g *recordingConversationGeneratorV2) Generate(_ context.Context, request llmruntime.Request) (llmruntime.Response, error) {
	g.calls++
	g.request = request
	return g.response, nil
}

func TestDraft06ConversationGeneratorRunsOnlyForAcceptedBoundInput(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	request := newTaskRequestV2()
	request.Message.Parts[0].Text = "A-LLM-SENTINEL::bound-message"
	expected := identitypolicy.BindingV2{BindingContextSHA256: "sha256:bound-context"}
	prepared, err := prepareConversationInputV2(request, expected)
	if err != nil {
		t.Fatal(err)
	}
	accepted := acceptedConversationAssertionV2(now, expected.BindingContextSHA256)

	t.Run("accepted", func(t *testing.T) {
		generator := &recordingConversationGeneratorV2{response: llmruntime.Response{Text: "B-LLM-SENTINEL::artifact"}}
		server := &agentBServerV2{generator: generator, clock: func() time.Time { return now }}
		got, err := server.generateAcceptedConversationArtifactV2(context.Background(), prepared, request, accepted)
		if err != nil {
			t.Fatal(err)
		}
		if got != generator.response.Text || generator.calls != 1 {
			t.Fatalf("generation = %q, calls = %d", got, generator.calls)
		}
		if generator.request.System != agentBSystemPrompt || generator.request.Input != request.Message.Parts[0].Text {
			t.Fatalf("generator request = %#v", generator.request)
		}
	})

	tests := map[string]func(*a2aSendMessageRequest, *preparedConversationInputV2, *identitypolicy.AcceptedAssertionV2){
		"tampered text": func(request *a2aSendMessageRequest, _ *preparedConversationInputV2, _ *identitypolicy.AcceptedAssertionV2) {
			request.Message.Parts[0].Text = "tampered after binding"
		},
		"blank input": func(request *a2aSendMessageRequest, prepared *preparedConversationInputV2, _ *identitypolicy.AcceptedAssertionV2) {
			request.Message.Parts[0].Text = " \n\t "
			prepared.text = request.Message.Parts[0].Text
			prepared.textSHA256 = sha256String([]byte(prepared.text))
		},
		"control input": func(request *a2aSendMessageRequest, prepared *preparedConversationInputV2, _ *identitypolicy.AcceptedAssertionV2) {
			request.Message.Parts[0].Text = "invalid\x00input"
			prepared.text = request.Message.Parts[0].Text
			prepared.textSHA256 = sha256String([]byte(prepared.text))
		},
		"oversized input": func(request *a2aSendMessageRequest, prepared *preparedConversationInputV2, _ *identitypolicy.AcceptedAssertionV2) {
			request.Message.Parts[0].Text = strings.Repeat("x", maxConversationTextBytes+1)
			prepared.text = request.Message.Parts[0].Text
			prepared.textSHA256 = sha256String([]byte(prepared.text))
		},
		"different accepted context": func(_ *a2aSendMessageRequest, _ *preparedConversationInputV2, accepted *identitypolicy.AcceptedAssertionV2) {
			accepted.Scope.BindingContextSHA256 = "sha256:other-context"
		},
		"replay not committed": func(_ *a2aSendMessageRequest, _ *preparedConversationInputV2, accepted *identitypolicy.AcceptedAssertionV2) {
			accepted.ReplayCommit.State = ""
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			requestCopy := request
			requestCopy.Message.Parts = append([]a2aPart(nil), request.Message.Parts...)
			preparedCopy := prepared
			acceptedCopy := accepted
			mutate(&requestCopy, &preparedCopy, &acceptedCopy)
			generator := &recordingConversationGeneratorV2{response: llmruntime.Response{Text: "must-not-run"}}
			server := &agentBServerV2{generator: generator, clock: func() time.Time { return now }}
			if _, err := server.generateAcceptedConversationArtifactV2(context.Background(), preparedCopy, requestCopy, acceptedCopy); err == nil {
				t.Fatal("invalid or tampered input was accepted")
			}
			if generator.calls != 0 {
				t.Fatalf("generator calls = %d, want 0", generator.calls)
			}
		})
	}
}

func TestDraft06ConversationTextChangesTaskContext(t *testing.T) {
	first := newTaskRequestV2()
	first.Message.Parts[0].Text = "model-a-output-one"
	second := first
	second.Message.Parts = append([]a2aPart(nil), first.Message.Parts...)
	second.Message.Parts[0].Text = "model-a-output-two"

	firstContexts, err := canonicalRequestContextsV2(first)
	if err != nil {
		t.Fatal(err)
	}
	secondContexts, err := canonicalRequestContextsV2(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstContexts.Task, secondContexts.Task) {
		t.Fatal("changing generated text did not change the draft-06 task context")
	}
	if !bytes.Equal(firstContexts.Target, secondContexts.Target) {
		t.Fatal("changing generated text unexpectedly changed the target context")
	}
}

func TestConversationWorkflowSelectedLLMsRoundTripV2(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	const (
		agentAModel   = "fixture-agent-a-v2"
		agentBModel   = "fixture-agent-b-v2"
		agentAKeyName = "ASB_TEST_V2_AGENT_A_LLM_API_KEY"
		agentBKeyName = "ASB_TEST_V2_AGENT_B_LLM_API_KEY"
		agentAKey     = "agent-a-v2-private-key-sentinel"
		agentBKey     = "agent-b-v2-private-key-sentinel"
		prompt        = "Prepare a draft-06 request for the authorized document."
		agentAOutput  = "A-V2-LLM-SENTINEL::bound-message"
		agentBOutput  = "B-V2-LLM-SENTINEL::returned-artifact"
	)

	agentARuntime := newFakeChatRuntime(t, agentAModel, agentAKey, agentAOutput)
	defer agentARuntime.Close()
	agentBRuntime := newFakeChatRuntime(t, agentBModel, agentBKey, agentBOutput)
	defer agentBRuntime.Close()

	temporaryDirectory := t.TempDir()
	promptPath := filepath.Join(temporaryDirectory, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte(prompt), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(temporaryDirectory, "asb-a2a")
	reportPath := filepath.Join(temporaryDirectory, "conversation-report.json")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = os.Environ()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build A2A conversation tool: %v\n%s", err, output)
	}

	run := exec.Command(binary,
		"--role", "orchestrator",
		"--workflow", workflowLLMConversation,
		"--binding-profile", bindingProfileDraft06V2,
		"--prompt-file", promptPath,
		"--agent-a-llm-url", agentARuntime.URL,
		"--agent-a-llm-model", agentAModel,
		"--agent-a-api-key-env", agentAKeyName,
		"--agent-b-llm-url", agentBRuntime.URL,
		"--agent-b-llm-model", agentBModel,
		"--agent-b-api-key-env", agentBKeyName,
		"--allow-insecure-llm-loopback",
		"--report", reportPath,
	)
	baseEnvironment := isolateSecretEnvironment(os.Environ(), "", agentAKeyName, agentBKeyName)
	run.Env = append(baseEnvironment, agentAKeyName+"="+agentAKey, agentBKeyName+"="+agentBKey)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run draft-06 A2A LLM conversation: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte(agentBOutput)) {
		t.Fatalf("conversation stdout did not contain Agent B output\n%s", output)
	}

	if got := agentARuntime.Calls(); got != 1 {
		t.Fatalf("Agent A LLM calls = %d, want 1", got)
	}
	if got := agentBRuntime.Calls(); got != 1 {
		t.Fatalf("Agent B LLM calls = %d, want 1", got)
	}
	agentARequests := agentARuntime.Requests()
	agentBRequests := agentBRuntime.Requests()
	if len(agentARequests) != 1 || len(agentBRequests) != 1 {
		t.Fatalf("recorded requests = A:%d B:%d, want one each", len(agentARequests), len(agentBRequests))
	}
	assertChatRequest(t, agentARequests[0], agentAModel, agentAKey, agentASystemPrompt, prompt)
	assertChatRequest(t, agentBRequests[0], agentBModel, agentBKey, agentBSystemPrompt, agentAOutput)

	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	report := decodeA2ATestReport(t, reportBytes)
	if report.Profile != bindingProfileDraft06V2+"+llm-conversation-v1" || report.Status != a2asecuritytest.StatusPass ||
		report.Summary.Total != 1 || report.Summary.Passed != 1 || len(report.Scenarios) != 1 {
		t.Fatalf("conversation report = profile %q status %q summary %+v scenarios %d",
			report.Profile, report.Status, report.Summary, len(report.Scenarios))
	}
	for _, privateValue := range []string{
		agentAKey, agentBKey, prompt, agentAOutput, agentBOutput, agentARuntime.URL, agentBRuntime.URL,
	} {
		if bytes.Contains(reportBytes, []byte(privateValue)) {
			t.Fatalf("conversation report disclosed %q", privateValue)
		}
	}
}

func acceptedConversationAssertionV2(now time.Time, bindingContextSHA256 string) identitypolicy.AcceptedAssertionV2 {
	return identitypolicy.AcceptedAssertionV2{
		Scope: identitypolicy.AcceptedScopeV2{
			Audience: demoAudience, BindingContextSHA256: bindingContextSHA256,
		},
		AcceptedProfile: identitypolicy.ProfileSelectionV2{
			ProfileType: clients.TokenTypeSessionBinding, ProfileVersion: clients.ProfileVersionV2,
			BindingProfile: bindingProfileDraft06V2, ProtocolID: v2ProtocolID,
		},
		AcceptedActor: identitypolicy.AcceptedActorV2{ID: demoAgentIssuer},
		AcceptedInteraction: identitypolicy.AcceptedInteractionV2{
			Type: v2InteractionType, TaskID: demoTaskID, ThreadID: demoThreadID, IntentRef: demoIntent,
		},
		AcceptedTarget: &identitypolicy.AcceptedTargetV2{Resource: demoResource, Operation: demoOperation},
		ReplayCommit: identitypolicy.ReplayCommitV2{
			State: identitypolicy.ReplayCommitStateCommittedV2, RetainUntil: now.Add(2 * time.Minute),
		},
		EffectiveAuthorization: identitypolicy.AuthorizationV2{
			CapabilityRef: demoCapability, Scopes: []string{demoReadScope}, Resources: []string{demoResource},
		},
		Expiry: now.Add(time.Minute),
	}
}
