// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/a2asecuritytest"
)

func TestConversationServerWriteTimeoutCoversModelCall(t *testing.T) {
	t.Parallel()

	if got := serverWriteTimeout(options{workflow: workflowLLMConversation}, "agent-b"); got != 30*time.Second {
		t.Fatalf("conversation Agent B write timeout = %s, want 30s", got)
	}
	if conversationA2ATimeout != 35*time.Second {
		t.Fatalf("conversation A2A timeout = %s, want 35s", conversationA2ATimeout)
	}
	if got := serverWriteTimeout(options{workflow: workflowSecurityTest}, "agent-b"); got != 10*time.Second {
		t.Fatalf("security-test Agent B write timeout = %s, want 10s", got)
	}
}

func TestIsolateSecretEnvironmentSeparatesRoleSecrets(t *testing.T) {
	t.Parallel()
	const (
		agentASecretName = "ASB_TEST_AGENT_A_KEY"
		agentBSecretName = "ASB_TEST_AGENT_B_KEY"
	)
	base := []string{
		"PATH=/usr/bin",
		"SHARED=value",
		agentASecretName + "=agent-a-secret",
		agentBSecretName + "=agent-b-secret",
		"MALFORMED",
	}

	tests := []struct {
		name    string
		allowed string
		want    map[string]string
	}{
		{
			name:    "agent a",
			allowed: agentASecretName,
			want: map[string]string{
				"PATH": "/usr/bin", "SHARED": "value", agentASecretName: "agent-a-secret",
			},
		},
		{
			name:    "agent b",
			allowed: agentBSecretName,
			want: map[string]string{
				"PATH": "/usr/bin", "SHARED": "value", agentBSecretName: "agent-b-secret",
			},
		},
		{
			name: "non llm role",
			want: map[string]string{"PATH": "/usr/bin", "SHARED": "value"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := environmentMap(isolateSecretEnvironment(base, test.allowed, agentASecretName, agentBSecretName))
			if len(got) != len(test.want) {
				t.Fatalf("isolated environment = %v, want %v", got, test.want)
			}
			for name, value := range test.want {
				if got[name] != value {
					t.Fatalf("isolated environment %s = %q, want %q", name, got[name], value)
				}
			}
			if test.allowed != agentASecretName {
				if _, present := got[agentASecretName]; present {
					t.Fatal("Agent A secret crossed a role boundary")
				}
			}
			if test.allowed != agentBSecretName {
				if _, present := got[agentBSecretName]; present {
					t.Fatal("Agent B secret crossed a role boundary")
				}
			}
		})
	}
}

func TestOrchestratorChildEnvironmentConfinesRedisAndLLMSecrets(t *testing.T) {
	const (
		agentAName = "ASB_TEST_ISOLATION_AGENT_A"
		agentBName = "ASB_TEST_ISOLATION_AGENT_B"
		redisName  = "ASB_TEST_ISOLATION_REDIS"
	)
	t.Setenv(agentAName, "agent-a-secret")
	t.Setenv(agentBName, "agent-b-secret")
	t.Setenv(redisName, "redis-secret-not-for-argv")
	opts := options{
		workflow: workflowLLMConversation, acceptanceStore: acceptanceStoreRedis,
		agentAAPIKeyEnv: agentAName, agentBAPIKeyEnv: agentBName, redisPasswordEnv: redisName,
	}
	want := map[string]string{"agent-a": agentAName, "agent-b": agentBName, "replay": redisName, "manager": ""}
	for role, allowed := range want {
		environment, err := orchestratorChildEnvironment(opts, role)
		if err != nil {
			t.Fatalf("%s environment: %v", role, err)
		}
		values := environmentMap(environment)
		for _, secret := range []string{agentAName, agentBName, redisName} {
			_, present := values[secret]
			if present != (secret == allowed) {
				t.Fatalf("%s sees %s = %v, want %v", role, secret, present, secret == allowed)
			}
		}
	}
	arguments := strings.Join(replayProcessArgs(opts), "\x00")
	if strings.Contains(arguments, "redis-secret-not-for-argv") {
		t.Fatal("Redis password crossed into child command-line arguments")
	}

	opts.redisPasswordEnv = agentAName
	if _, err := orchestratorChildEnvironment(opts, "replay"); err == nil {
		t.Fatal("Redis and LLM secret environment name collision was accepted")
	}
}

func TestCanonicalRequestContextCoversConversationText(t *testing.T) {
	t.Parallel()
	first := newTaskRequestWithText(demoResource, "model-a-output-one")
	second := first
	second.Message.Parts = append([]a2aPart(nil), first.Message.Parts...)
	second.Message.Parts[0] = first.Message.Parts[0]
	second.Message.Parts[0].Text = "model-a-output-two"

	firstContext, err := canonicalRequestContext(first)
	if err != nil {
		t.Fatal(err)
	}
	secondContext, err := canonicalRequestContext(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstContext, secondContext) {
		t.Fatal("changing the generated conversation text did not change the bound request context")
	}
}

func TestCompletedConversationTextStrictValidation(t *testing.T) {
	t.Parallel()
	const validText = "Agent B result\nsecond line"
	response := validCompletedConversationResponse(validText)
	got, err := completedConversationText(response)
	if err != nil {
		t.Fatal(err)
	}
	if got != validText {
		t.Fatalf("completedConversationText() = %q, want %q", got, validText)
	}

	invalidUTF8 := string([]byte{0xff})
	tests := []struct {
		name   string
		mutate func(*a2aTaskResponse)
	}{
		{name: "missing task id", mutate: func(value *a2aTaskResponse) { value.Task.ID = "" }},
		{name: "authorization task id reused", mutate: func(value *a2aTaskResponse) { value.Task.ID = demoTaskID }},
		{name: "wrong context", mutate: func(value *a2aTaskResponse) { value.Task.ContextID = "other-context" }},
		{name: "not completed", mutate: func(value *a2aTaskResponse) { value.Task.Status.State = "TASK_STATE_RUNNING" }},
		{name: "missing artifact", mutate: func(value *a2aTaskResponse) { value.Task.Artifacts = nil }},
		{name: "two artifacts", mutate: func(value *a2aTaskResponse) {
			value.Task.Artifacts = append(value.Task.Artifacts, value.Task.Artifacts[0])
		}},
		{name: "missing part", mutate: func(value *a2aTaskResponse) { value.Task.Artifacts[0].Parts = nil }},
		{name: "two parts", mutate: func(value *a2aTaskResponse) {
			value.Task.Artifacts[0].Parts = append(value.Task.Artifacts[0].Parts, value.Task.Artifacts[0].Parts[0])
		}},
		{name: "wrong media type", mutate: func(value *a2aTaskResponse) {
			value.Task.Artifacts[0].Parts[0].MediaType = "application/json"
		}},
		{name: "blank text", mutate: func(value *a2aTaskResponse) { value.Task.Artifacts[0].Parts[0].Text = " \n\t " }},
		{name: "invalid utf8", mutate: func(value *a2aTaskResponse) { value.Task.Artifacts[0].Parts[0].Text = invalidUTF8 }},
		{name: "control character", mutate: func(value *a2aTaskResponse) {
			value.Task.Artifacts[0].Parts[0].Text = "invalid\x00text"
		}},
		{name: "oversized text", mutate: func(value *a2aTaskResponse) {
			value.Task.Artifacts[0].Parts[0].Text = strings.Repeat("x", maxConversationTextBytes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			invalid := validCompletedConversationResponse(validText)
			test.mutate(&invalid)
			text, err := completedConversationText(invalid)
			if err == nil || text != "" {
				t.Fatalf("completedConversationText() = %q, %v; want empty text and error", text, err)
			}
		})
	}
}

func TestConversationWorkflowSelectedLLMsRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	const (
		agentAModel      = "fixture-agent-a-v1"
		agentBModel      = "fixture-agent-b-v1"
		agentAKeyName    = "ASB_TEST_AGENT_A_LLM_API_KEY"
		agentBKeyName    = "ASB_TEST_AGENT_B_LLM_API_KEY"
		agentAKey        = "agent-a-private-key-sentinel"
		agentBKey        = "agent-b-private-key-sentinel"
		prompt           = "Prepare a request for the authorized document."
		agentAOutput     = "A-LLM-SENTINEL::bound-message-7f3c"
		agentBOutput     = "B-LLM-SENTINEL::returned-artifact-91ad"
		conversationName = "direct-agent-v1+llm-conversation-v1"
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
		t.Fatalf("run A2A LLM conversation: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte(agentBOutput)) {
		t.Fatalf("conversation stdout did not contain Agent B output\n%s", output)
	}

	agentARequests := agentARuntime.Requests()
	agentBRequests := agentBRuntime.Requests()
	if got := agentARuntime.Calls(); got != 1 {
		t.Fatalf("Agent A LLM calls = %d, want 1", got)
	}
	if got := agentBRuntime.Calls(); got != 1 {
		t.Fatalf("Agent B LLM calls = %d, want 1", got)
	}
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
	if report.Profile != conversationName || report.Status != a2asecuritytest.StatusPass ||
		report.Summary.Total != 1 || report.Summary.Passed != 1 || len(report.Scenarios) != 1 {
		t.Fatalf("conversation report = profile %q status %q summary %+v scenarios %d",
			report.Profile, report.Status, report.Summary, len(report.Scenarios))
	}
	if report.Scenarios[0].ID != "ASB-A2A-LLM-001" || report.Scenarios[0].Status != a2asecuritytest.StatusPass {
		t.Fatalf("conversation scenario = %+v", report.Scenarios[0])
	}
	for _, privateValue := range []string{
		agentAKey, agentBKey, prompt, agentAOutput, agentBOutput, agentARuntime.URL, agentBRuntime.URL,
	} {
		if bytes.Contains(reportBytes, []byte(privateValue)) {
			t.Fatalf("conversation report disclosed %q", privateValue)
		}
	}
}

type recordedChatRequest struct {
	Method        string
	Path          string
	ContentType   string
	Authorization string
	Model         string
	Messages      []recordedChatMessage
}

type recordedChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type fakeChatRequest struct {
	Model    string                `json:"model"`
	Messages []recordedChatMessage `json:"messages"`
}

type fakeChatRuntime struct {
	URL        string
	server     *httptest.Server
	calls      atomic.Int32
	requestsMu sync.Mutex
	requests   []recordedChatRequest
}

func newFakeChatRuntime(t *testing.T, model, apiKey, output string) *fakeChatRuntime {
	t.Helper()
	runtime := &fakeChatRuntime{}
	runtime.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		runtime.calls.Add(1)
		recorded := recordedChatRequest{
			Method: request.Method, Path: request.URL.Path,
			ContentType: request.Header.Get("Content-Type"), Authorization: request.Header.Get("Authorization"),
		}
		decoder := json.NewDecoder(io.LimitReader(request.Body, 256*1024+1))
		decoder.DisallowUnknownFields()
		var body fakeChatRequest
		if err := decoder.Decode(&body); err != nil {
			t.Errorf("decode fake LLM request: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			t.Errorf("fake LLM request has trailing JSON: %v", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		recorded.Model = body.Model
		recorded.Messages = append([]recordedChatMessage(nil), body.Messages...)
		runtime.requestsMu.Lock()
		runtime.requests = append(runtime.requests, recorded)
		runtime.requestsMu.Unlock()

		if request.Method != http.MethodPost || request.URL.Path != "/v1/chat/completions" {
			t.Errorf("fake LLM request = %s %s, want POST /v1/chat/completions", request.Method, request.URL.Path)
		}
		if request.Header.Get("Content-Type") != applicationJSONMediaType {
			t.Errorf("fake LLM Content-Type = %q, want application/json", request.Header.Get("Content-Type"))
		}
		if body.Model != model {
			t.Errorf("fake LLM model = %q, want %q", body.Model, model)
		}
		if request.Header.Get("Authorization") != "Bearer "+apiKey {
			t.Errorf("fake LLM received the wrong role API key")
		}

		w.Header().Set("Content-Type", applicationJSONMediaType)
		response := map[string]any{
			"id": "chatcmpl-fixture", "object": "chat.completion", "created": int64(1), "model": model,
			"choices": []map[string]any{{
				"index": 0, "message": map[string]string{"role": "assistant", "content": output}, "finish_reason": "stop",
			}},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode fake LLM response: %v", err)
		}
	}))
	runtime.URL = runtime.server.URL
	return runtime
}

func (r *fakeChatRuntime) Close() {
	r.server.Close()
}

func (r *fakeChatRuntime) Calls() int32 {
	return r.calls.Load()
}

func (r *fakeChatRuntime) Requests() []recordedChatRequest {
	r.requestsMu.Lock()
	defer r.requestsMu.Unlock()
	return append([]recordedChatRequest(nil), r.requests...)
}

func assertChatRequest(t *testing.T, request recordedChatRequest, model, apiKey, system, input string) {
	t.Helper()
	if request.Method != http.MethodPost || request.Path != "/v1/chat/completions" || request.ContentType != applicationJSONMediaType {
		t.Fatalf("chat request transport = %s %s %q", request.Method, request.Path, request.ContentType)
	}
	if request.Authorization != "Bearer "+apiKey {
		t.Fatal("chat request used the wrong role API key")
	}
	if request.Model != model {
		t.Fatalf("chat request model = %q, want %q", request.Model, model)
	}
	wantMessages := []recordedChatMessage{{Role: "system", Content: system}, {Role: "user", Content: input}}
	if len(request.Messages) != len(wantMessages) {
		t.Fatalf("chat request messages = %+v, want %+v", request.Messages, wantMessages)
	}
	for index := range wantMessages {
		if request.Messages[index] != wantMessages[index] {
			t.Fatalf("chat request message[%d] = %+v, want %+v", index, request.Messages[index], wantMessages[index])
		}
	}
}

func validCompletedConversationResponse(text string) a2aTaskResponse {
	return a2aTaskResponse{Task: a2aTask{
		ID: "task-conversation-result", ContextID: demoContextID,
		Status: a2aTaskStatus{State: "TASK_STATE_COMPLETED"},
		Artifacts: []a2aArtifact{{
			ArtifactID: "artifact-conversation-result",
			Parts:      []a2aPart{{Text: text, MediaType: "text/plain"}},
		}},
	}}
}

func environmentMap(environment []string) map[string]string {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		if ok {
			values[name] = value
		}
	}
	return values
}
