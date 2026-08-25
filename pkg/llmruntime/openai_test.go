// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewOpenAICompatibleValidatesEndpoint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		baseURL  string
		allow    bool
		wantPath string
		wantErr  bool
	}{
		{name: "https", baseURL: "https://models.example", wantPath: "/v1/chat/completions"},
		{name: "https base path", baseURL: "https://models.example/api/", wantPath: "/api/v1/chat/completions"},
		{name: "common v1 base URL", baseURL: "https://api.openai.com/v1", wantPath: "/v1/chat/completions"},
		{name: "nested v1 base URL", baseURL: "https://models.example/gateway/v1/", wantPath: "/gateway/v1/chat/completions"},
		{name: "explicit IPv4 loopback", baseURL: "http://127.0.0.1:8080", allow: true, wantPath: "/v1/chat/completions"},
		{name: "explicit IPv6 loopback", baseURL: "http://[::1]:8080", allow: true, wantPath: "/v1/chat/completions"},
		{name: "explicit localhost", baseURL: "http://localhost:8080", allow: true, wantPath: "/v1/chat/completions"},
		{name: "empty", wantErr: true},
		{name: "relative", baseURL: "models.example", wantErr: true},
		{name: "unsupported scheme", baseURL: "ftp://models.example", wantErr: true},
		{name: "cleartext loopback not enabled", baseURL: "http://127.0.0.1:8080", wantErr: true},
		{name: "cleartext remote", baseURL: "http://192.0.2.1", allow: true, wantErr: true},
		{name: "cleartext unspecified", baseURL: "http://0.0.0.0", allow: true, wantErr: true},
		{name: "userinfo", baseURL: "https://user:secret@models.example", wantErr: true},
		{name: "query", baseURL: "https://models.example?token=secret", wantErr: true},
		{name: "empty query", baseURL: "https://models.example?", wantErr: true},
		{name: "fragment", baseURL: "https://models.example/#fragment", wantErr: true},
		{name: "empty fragment", baseURL: "https://models.example/#", wantErr: true},
		{name: "missing host", baseURL: "https:///path", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			generator, err := NewOpenAICompatible(Config{
				BaseURL: test.baseURL, Model: "test-model", AllowInsecureLoopback: test.allow,
			})
			if test.wantErr {
				if !errors.Is(err, ErrInvalidConfig) || generator != nil {
					t.Fatalf("NewOpenAICompatible() = %v, %v; want nil, ErrInvalidConfig", generator, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			client := generator.(*openAICompatible)
			if client.endpoint.Path != test.wantPath {
				t.Fatalf("endpoint path = %q, want %q", client.endpoint.Path, test.wantPath)
			}
			if client.client.Timeout != 20*time.Second {
				t.Fatalf("timeout = %v, want 20s", client.client.Timeout)
			}
		})
	}
}

func TestNewOpenAICompatibleValidatesModelAndKeyWithoutDisclosure(t *testing.T) {
	t.Parallel()
	secret := "secret\nheader"
	for _, config := range []Config{
		{BaseURL: "https://models.example", Model: ""},
		{BaseURL: "https://models.example", Model: " padded "},
		{BaseURL: "https://models.example", Model: "bad\x00model"},
		{BaseURL: "https://models.example", Model: "test", APIKey: secret},
	} {
		generator, err := NewOpenAICompatible(config)
		if !errors.Is(err, ErrInvalidConfig) || generator != nil {
			t.Fatalf("NewOpenAICompatible(%+v) = %v, %v", config, generator, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("configuration error disclosed API key")
		}
	}
}

func TestOpenAICompatibleUsesGuardedDirectTransportOnlyForHTTP(t *testing.T) {
	t.Parallel()
	httpsGenerator, err := NewOpenAICompatible(Config{BaseURL: "https://models.example/v1", Model: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if transport := httpsGenerator.(*openAICompatible).client.Transport; transport != nil {
		t.Fatalf("HTTPS transport = %T, want the standard nil transport", transport)
	}

	httpGenerator, err := NewOpenAICompatible(Config{
		BaseURL: "http://localhost:8080/v1", Model: "test", AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := httpGenerator.(*openAICompatible).client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport = %T, want *http.Transport", httpGenerator.(*openAICompatible).client.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("cleartext loopback transport configured a proxy")
	}
	if transport.DialContext == nil {
		t.Fatal("cleartext loopback transport omitted its guarded dialer")
	}
}

func TestResolveLoopbackRejectsEmptyMixedAndRemoteResults(t *testing.T) {
	t.Parallel()
	remote := net.ParseIP("192.0.2.10")
	loopback4 := net.ParseIP("127.0.0.1")
	loopback6 := net.ParseIP("::1")
	tests := []struct {
		name      string
		host      string
		addresses []net.IPAddr
		lookupErr error
		want      int
		wantErr   bool
	}{
		{name: "IPv4 literal", host: "127.0.0.1", want: 1},
		{name: "IPv6 literal", host: "::1", want: 1},
		{name: "resolved loopback", host: "localhost", addresses: []net.IPAddr{{IP: loopback6}, {IP: loopback4}}, want: 2},
		{name: "remote literal", host: "192.0.2.10", wantErr: true},
		{name: "empty resolution", host: "localhost", wantErr: true},
		{name: "failed resolution", host: "localhost", lookupErr: errors.New("lookup failed"), wantErr: true},
		{name: "remote resolution", host: "localhost", addresses: []net.IPAddr{{IP: remote}}, wantErr: true},
		{name: "mixed resolution", host: "localhost", addresses: []net.IPAddr{{IP: loopback4}, {IP: remote}}, wantErr: true},
		{name: "nil address", host: "localhost", addresses: []net.IPAddr{{}}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return test.addresses, test.lookupErr
			}
			addresses, err := resolveLoopback(context.Background(), test.host, lookup)
			if test.wantErr {
				if !errors.Is(err, errLoopback) {
					t.Fatalf("resolveLoopback() error = %v, want errLoopback", err)
				}
				return
			}
			if err != nil || len(addresses) != test.want {
				t.Fatalf("resolveLoopback() = %v, %v; want %d addresses", addresses, err, test.want)
			}
		})
	}
}

func TestLoopbackDialContextDialsResolvedIPNotHostname(t *testing.T) {
	t.Parallel()
	lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "localhost" {
			t.Fatalf("lookup host = %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	var dialed string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q", network)
		}
		dialed = address
		return nil, errors.New("sentinel dial failure")
	}
	_, err := loopbackDialContext(lookup, dial)(context.Background(), "tcp", "localhost:8080")
	if !errors.Is(err, errLoopback) {
		t.Fatalf("dial error = %v, want errLoopback", err)
	}
	if dialed != "127.0.0.1:8080" {
		t.Fatalf("dialed address = %q, want resolved loopback IP", dialed)
	}
}

func TestOpenAICompatibleGenerate(t *testing.T) {
	t.Parallel()
	const (
		apiKey = "test-api-key"
		model  = "model-a"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/gateway/v1/chat/completions" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxHTTPBodyBytes+1))
		if err != nil {
			t.Errorf("read request: %v", err)
			return
		}
		var request chatCompletionRequest
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if request.Model != model || len(request.Messages) != 2 ||
			request.Messages[0] != (chatMessage{Role: "system", Content: "Be concise."}) ||
			request.Messages[1] != (chatMessage{Role: "user", Content: "Hello\nAgent B"}) {
			t.Errorf("request = %+v", request)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"id":"response-1","object":"chat.completion","created":1,"model":"model-a","choices":[{"index":0,"message":{"role":"assistant","content":"Hello from Agent B."},"finish_reason":"stop"}],"usage":{"total_tokens":12},"system_fingerprint":null,"service_tier":"default"}`)
	}))
	defer server.Close()

	generator, err := NewOpenAICompatible(Config{
		BaseURL: server.URL + "/gateway/", Model: model, APIKey: apiKey, AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := generator.Generate(context.Background(), Request{System: "Be concise.", Input: "Hello\nAgent B"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Text != "Hello from Agent B." {
		t.Fatalf("response text = %q", response.Text)
	}
}

func TestOpenAICompatibleOmitsAuthorizationWithoutKey(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["Authorization"]; present {
			t.Error("Authorization header was present without an API key")
		}
		writeCompletion(w, "local response")
	}))
	defer server.Close()
	generator := newTestGenerator(t, server.URL, "")
	if _, err := generator.Generate(context.Background(), Request{Input: "local prompt"}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAICompatibleRejectsRedirect(t *testing.T) {
	t.Parallel()
	var followed atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		writeCompletion(w, "unexpected")
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	generator := newTestGenerator(t, source.URL, "")
	_, err := generator.Generate(context.Background(), Request{Input: "do not redirect"})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("Generate() error = %v, want ErrProvider", err)
	}
	if followed.Load() {
		t.Fatal("client followed provider redirect")
	}
}

func TestOpenAICompatibleDoesNotDiscloseProviderBodyOrSecrets(t *testing.T) {
	t.Parallel()
	const (
		apiKey    = "private-provider-key"
		input     = "private prompt text"
		errorBody = "provider diagnostic with private content"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, errorBody)
	}))
	defer server.Close()
	generator := newTestGenerator(t, server.URL, apiKey)
	_, err := generator.Generate(context.Background(), Request{Input: input})
	if !errors.Is(err, ErrProvider) {
		t.Fatalf("Generate() error = %v, want ErrProvider", err)
	}
	for _, secret := range []string{apiKey, input, errorBody} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("provider error disclosed %q", secret)
		}
	}
}

func TestOpenAICompatibleValidatesRequestBeforeNetwork(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	defer server.Close()
	generator := newTestGenerator(t, server.URL, "")
	invalidUTF8 := string([]byte{0xff})
	for _, request := range []Request{
		{},
		{Input: "   "},
		{Input: "bad\x00input"},
		{Input: invalidUTF8},
		{Input: strings.Repeat("x", maxInputBytes+1)},
		{System: "bad\x00system", Input: "valid"},
		{System: strings.Repeat("x", maxSystemBytes+1), Input: "valid"},
	} {
		_, err := generator.Generate(context.Background(), request)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("Generate(%q) error = %v, want ErrInvalidRequest", request.Input, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("provider calls = %d, want 0", calls.Load())
	}
}

func TestOpenAICompatibleRejectsMalformedResponses(t *testing.T) {
	t.Parallel()
	invalidUTF8 := string([]byte{'{', '"', 0xff, '"', '}'})
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "content type", contentType: "text/plain", body: `{"choices":[{"index":0,"message":{"content":"ok"}}]}`},
		{name: "invalid UTF-8", contentType: "application/json", body: invalidUTF8},
		{name: "duplicate member", contentType: "application/json", body: `{"choices":[],"choices":[]}`},
		{name: "case-folded alias", contentType: "application/json", body: `{"CHOICES":[{"index":0,"message":{"content":"ok"}}]}`},
		{name: "case-folded duplicate", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"ok"}}],"CHOICES":[{"index":0,"message":{"content":"other"}}]}`},
		{name: "unknown member", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"ok"}}],"unexpected":true}`},
		{name: "trailing value", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"ok"}}]} {}`},
		{name: "no choices", contentType: "application/json", body: `{"choices":[]}`},
		{name: "two choices", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"one"}},{"index":1,"message":{"content":"two"}}]}`},
		{name: "wrong index", contentType: "application/json", body: `{"choices":[{"index":1,"message":{"content":"one"}}]}`},
		{name: "empty text", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"  "}}]}`},
		{name: "control in text", contentType: "application/json", body: `{"choices":[{"index":0,"message":{"content":"bad\u0000text"}}]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			generator := newTestGenerator(t, server.URL, "")
			_, err := generator.Generate(context.Background(), Request{Input: "test"})
			if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Generate() error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestOpenAICompatibleRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", maxHTTPBodyBytes+1))
	}))
	defer server.Close()
	generator := newTestGenerator(t, server.URL, "")
	_, err := generator.Generate(context.Background(), Request{Input: "test"})
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("Generate() error = %v, want ErrInvalidResponse", err)
	}
}

func TestOpenAICompatibleHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	generator := newTestGenerator(t, server.URL, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := generator.Generate(ctx, Request{Input: "test"})
	if !errors.Is(err, ErrProvider) || strings.Contains(err.Error(), "test") {
		t.Fatalf("Generate() error = %v, want sanitized ErrProvider", err)
	}
}

func newTestGenerator(t *testing.T, baseURL, apiKey string) Generator {
	t.Helper()
	generator, err := NewOpenAICompatible(Config{
		BaseURL: baseURL, Model: "test-model", APIKey: apiKey, AllowInsecureLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

func writeCompletion(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, text)
}
