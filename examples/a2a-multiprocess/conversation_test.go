// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestOrchestratorChildEnvironmentDoesNotForwardLegacyLLMSecrets(t *testing.T) {
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
	want := map[string]string{"agent-a": "", "agent-b": "", "replay": redisName, "manager": ""}
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
		prompt           = "Prepare a request for the authorized document."
		agentAOutput     = "A-LLM-SENTINEL::bound-message-7f3c"
		agentBOutput     = "B-LLM-SENTINEL::returned-artifact-91ad"
		conversationName = "direct-agent-v1+llm-conversation-v1"
	)

	temporaryDirectory := t.TempDir()
	fixture := newManagedConversationFixture(t, temporaryDirectory, agentAOutput, agentBOutput)
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
		"--debug-simple",
		"--role", "orchestrator",
		"--workflow", workflowLLMConversation,
		"--prompt-file", promptPath,
	)
	run.Args = append(run.Args, fixture.arguments()...)
	run.Args = append(run.Args,
		"--report", reportPath,
	)
	run.Env = append(os.Environ(), "ASB_TEST_ENV_POISON=must-not-reach-llama", "LLAMA_ARG_MODEL=/untrusted/model.gguf")
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run A2A LLM conversation: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte(agentBOutput)) {
		t.Fatalf("conversation stdout did not contain Agent B output\n%s", output)
	}

	agentARequests := readFakeLlamaTrace(t, fixture.agentATracePath)
	agentBRequests := readFakeLlamaTrace(t, fixture.agentBTracePath)
	if len(agentARequests) != 1 || len(agentBRequests) != 1 {
		t.Fatalf("recorded requests = A:%d B:%d, want one each", len(agentARequests), len(agentBRequests))
	}
	assertManagedChatRequest(t, agentARequests[0], agentASystemPrompt, prompt)
	assertManagedChatRequest(t, agentBRequests[0], agentBSystemPrompt, agentAOutput)

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
		prompt, agentAOutput, agentBOutput, fixture.agentAPath, fixture.agentBPath,
	} {
		if bytes.Contains(reportBytes, []byte(privateValue)) {
			t.Fatalf("conversation report disclosed %q", privateValue)
		}
	}
}

func TestManagedConversationFailsClosedBeforeInference(t *testing.T) {
	if testing.Short() {
		t.Skip("multiprocess loopback test disabled in short mode")
	}
	directory := t.TempDir()
	fixture := newManagedConversationFixture(t, directory, "agent-a-output", "agent-b-output")
	promptPath := filepath.Join(directory, "prompt.txt")
	if err := os.WriteFile(promptPath, []byte("authorized prompt"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "asb-a2a")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build A2A conversation tool: %v\n%s", err, output)
	}
	wrongDigest := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name       string
		omit       string
		change     string
		value      string
		extra      []string
		tamperPath string
	}{
		{name: "missing server digest", omit: "--llama-server-sha256"},
		{name: "missing Agent A digest", omit: "--agent-a-gguf-sha256"},
		{name: "missing Agent B digest", omit: "--agent-b-gguf-sha256"},
		{name: "changed server digest", change: "--llama-server-sha256", value: wrongDigest},
		{name: "changed Agent A digest", change: "--agent-a-gguf-sha256", value: wrongDigest},
		{name: "changed Agent B digest", change: "--agent-b-gguf-sha256", value: wrongDigest},
		{name: "tampered Agent A bytes", tamperPath: fixture.agentAPath},
		{name: "tampered Agent B bytes", tamperPath: fixture.agentBPath},
		{name: "legacy URL", extra: []string{"--agent-a-llm-url", "http://127.0.0.1:11434"}},
		{name: "legacy model ID", extra: []string{"--agent-b-llm-model", "unverified-label"}},
		{name: "legacy loopback opt-in", extra: []string{"--allow-insecure-llm-loopback"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_ = os.Remove(fixture.agentATracePath)
			_ = os.Remove(fixture.agentBTracePath)
			if test.tamperPath != "" {
				original, err := os.ReadFile(test.tamperPath)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(test.tamperPath, original, 0600); err != nil {
						t.Errorf("restore test model: %v", err)
					}
				})
				modified := append([]byte(nil), original...)
				modified[len(modified)-1] ^= 1
				if err := os.WriteFile(test.tamperPath, modified, 0600); err != nil {
					t.Fatal(err)
				}
			}
			arguments := fixture.arguments()
			if test.omit != "" {
				arguments = omitConversationArgument(t, arguments, test.omit)
			}
			if test.change != "" {
				arguments = changeConversationArgument(t, arguments, test.change, test.value)
			}
			reportPath := filepath.Join(t.TempDir(), "rejected-report.json")
			runArgs := []string{"--debug-simple", "--role", "orchestrator", "--workflow", workflowLLMConversation, "--prompt-file", promptPath}
			runArgs = append(runArgs, arguments...)
			runArgs = append(runArgs, test.extra...)
			runArgs = append(runArgs, "--report", reportPath)
			output, err := exec.Command(binary, runArgs...).CombinedOutput()
			if err == nil {
				t.Fatalf("unverified model was accepted:\n%s", output)
			}
			if len(readFakeLlamaTrace(t, fixture.agentATracePath)) != 0 || len(readFakeLlamaTrace(t, fixture.agentBTracePath)) != 0 {
				t.Fatalf("unverified model was used for inference:\n%s", output)
			}
			if reportBytes, err := os.ReadFile(reportPath); err == nil {
				report := decodeA2ATestReport(t, reportBytes)
				if report.Status == a2asecuritytest.StatusPass || report.Summary.Passed != 0 {
					t.Fatalf("unverified model produced a successful report: %+v", report)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}

func omitConversationArgument(t *testing.T, arguments []string, flag string) []string {
	t.Helper()
	for index := 0; index+1 < len(arguments); index += 2 {
		if arguments[index] == flag {
			return append(arguments[:index:index], arguments[index+2:]...)
		}
	}
	t.Fatalf("missing fixture argument %s", flag)
	return nil
}

func changeConversationArgument(t *testing.T, arguments []string, flag, value string) []string {
	t.Helper()
	for index := 0; index+1 < len(arguments); index += 2 {
		if arguments[index] == flag {
			arguments[index+1] = value
			return arguments
		}
	}
	t.Fatalf("missing fixture argument %s", flag)
	return nil
}

type recordedChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type fakeChatRequest struct {
	Model    string                `json:"model"`
	Messages []recordedChatMessage `json:"messages"`
}

type fakeLlamaTrace struct {
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	ContentType   string          `json:"content_type"`
	Authorization string          `json:"authorization"`
	Request       fakeChatRequest `json:"request"`
}

type managedConversationFixture struct {
	serverPath      string
	serverSHA256    string
	agentAPath      string
	agentASHA256    string
	agentATracePath string
	agentBPath      string
	agentBSHA256    string
	agentBTracePath string
}

func newManagedConversationFixture(t *testing.T, directory, agentAOutput, agentBOutput string) managedConversationFixture {
	t.Helper()
	fixture := managedConversationFixture{serverPath: filepath.Join(directory, "fake-llama-server")}
	build := exec.Command("go", "build", "-o", fixture.serverPath, "./testdata/fake-llama-server")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test-only llama-server: %v\n%s", err, output)
	}
	fixture.serverSHA256 = fileSHA256(t, fixture.serverPath)
	fixture.agentAPath = filepath.Join(directory, "agent-a.gguf")
	fixture.agentATracePath = filepath.Join(directory, "agent-a-requests.jsonl")
	fixture.agentASHA256 = writeFakeGGUF(t, fixture.agentAPath, fixture.agentATracePath, agentAOutput)
	fixture.agentBPath = filepath.Join(directory, "agent-b.gguf")
	fixture.agentBTracePath = filepath.Join(directory, "agent-b-requests.jsonl")
	fixture.agentBSHA256 = writeFakeGGUF(t, fixture.agentBPath, fixture.agentBTracePath, agentBOutput)
	return fixture
}

func writeFakeGGUF(t *testing.T, path, tracePath, output string) string {
	t.Helper()
	content, err := json.Marshal(struct {
		Output    string `json:"output"`
		TracePath string `json:"trace_path"`
	}{Output: output, TracePath: tracePath})
	if err != nil {
		t.Fatal(err)
	}
	content = append([]byte("GGUF"), content...)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return sha256Bytes(content)
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Bytes(content)
}

func sha256Bytes(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (fixture managedConversationFixture) arguments() []string {
	return []string{
		"--llama-server-path", fixture.serverPath,
		"--llama-server-sha256", fixture.serverSHA256,
		"--agent-a-gguf-path", fixture.agentAPath,
		"--agent-a-gguf-sha256", fixture.agentASHA256,
		"--agent-b-gguf-path", fixture.agentBPath,
		"--agent-b-gguf-sha256", fixture.agentBSHA256,
	}
}

func readFakeLlamaTrace(t *testing.T, path string) []fakeLlamaTrace {
	t.Helper()
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	var records []fakeLlamaTrace
	for {
		var record fakeLlamaTrace
		if err := decoder.Decode(&record); err == io.EOF {
			return records
		} else if err != nil {
			t.Fatalf("decode fake llama-server trace: %v", err)
		}
		records = append(records, record)
	}
}

func assertManagedChatRequest(t *testing.T, trace fakeLlamaTrace, system, input string) {
	t.Helper()
	if trace.Method != http.MethodPost || trace.Path != "/v1/chat/completions" || trace.ContentType != applicationJSONMediaType {
		t.Fatalf("chat request transport = %s %s %q", trace.Method, trace.Path, trace.ContentType)
	}
	if trace.Authorization != "" {
		t.Fatal("managed chat request unexpectedly used an API key")
	}
	if trace.Request.Model != "asb-verified-model" {
		t.Fatalf("chat request model alias = %q", trace.Request.Model)
	}
	wantMessages := []recordedChatMessage{{Role: "system", Content: system}, {Role: "user", Content: input}}
	if len(trace.Request.Messages) != len(wantMessages) {
		t.Fatalf("chat request messages = %+v, want %+v", trace.Request.Messages, wantMessages)
	}
	for index := range wantMessages {
		if trace.Request.Messages[index] != wantMessages[index] {
			t.Fatalf("chat request message[%d] = %+v, want %+v", index, trace.Request.Messages[index], wantMessages[index])
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
