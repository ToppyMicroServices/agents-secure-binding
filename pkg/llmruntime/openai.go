// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package llmruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxHTTPBodyBytes = 256 * 1024
	maxModelBytes    = 512
	maxSystemBytes   = 64 * 1024
	maxInputBytes    = 128 * 1024
	maxOutputBytes   = 128 * 1024
	maxAPIKeyBytes   = 16 * 1024
	requestTimeout   = 20 * time.Second
)

var (
	// ErrInvalidConfig indicates that a Generator configuration is unsafe or
	// incomplete.
	ErrInvalidConfig = errors.New("llm runtime: invalid configuration")
	// ErrInvalidRequest indicates that model input is outside the bounded text
	// contract.
	ErrInvalidRequest = errors.New("llm runtime: invalid request")
	// ErrProvider indicates that the configured runtime was unavailable or
	// returned a non-success HTTP status. Provider bodies are not exposed.
	ErrProvider = errors.New("llm runtime: provider request failed")
	// ErrInvalidResponse indicates that a successful provider response was
	// malformed or outside the bounded text contract.
	ErrInvalidResponse = errors.New("llm runtime: invalid provider response")

	errRedirect = errors.New("llm runtime: redirect rejected")
	errLoopback = errors.New("llm runtime: cleartext endpoint did not resolve only to loopback")
)

var chatCompletionMemberNames = map[string]struct{}{
	"id": {}, "object": {}, "created": {}, "model": {}, "choices": {},
	"usage": {}, "system_fingerprint": {}, "service_tier": {},
	"index": {}, "message": {}, "logprobs": {}, "finish_reason": {},
	"role": {}, "content": {}, "refusal": {}, "annotations": {},
	"audio": {}, "tool_calls": {}, "function_call": {},
}

var chatCompletionOpaqueMembers = map[string]struct{}{
	"usage": {}, "system_fingerprint": {}, "service_tier": {},
	"logprobs": {}, "finish_reason": {}, "refusal": {}, "annotations": {},
	"audio": {}, "tool_calls": {}, "function_call": {},
}

// Config selects an OpenAI-compatible model endpoint. APIKey may be empty for
// a local runtime. Cleartext HTTP is accepted only for an explicitly enabled
// loopback endpoint.
type Config struct {
	BaseURL               string
	Model                 string
	APIKey                string
	AllowInsecureLoopback bool
}

type openAICompatible struct {
	endpoint *url.URL
	model    string
	apiKey   string
	client   *http.Client
}

type chatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// The optional fields below are part of the ordinary OpenAI-compatible
// response envelope. They are decoded only so unknown top-level fields can be
// rejected; ASB does not expose or trust them.
type chatCompletionResponse struct {
	ID                string          `json:"id,omitempty"`
	Object            string          `json:"object,omitempty"`
	Created           int64           `json:"created,omitempty"`
	Model             string          `json:"model,omitempty"`
	Choices           []chatChoice    `json:"choices"`
	Usage             json.RawMessage `json:"usage,omitempty"`
	SystemFingerprint json.RawMessage `json:"system_fingerprint,omitempty"`
	ServiceTier       json.RawMessage `json:"service_tier,omitempty"`
}

type chatChoice struct {
	Index        int                 `json:"index"`
	Message      chatResponseMessage `json:"message"`
	Logprobs     json.RawMessage     `json:"logprobs,omitempty"`
	FinishReason json.RawMessage     `json:"finish_reason,omitempty"`
}

type chatResponseMessage struct {
	Role         string          `json:"role,omitempty"`
	Content      string          `json:"content"`
	Refusal      json.RawMessage `json:"refusal,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
	Audio        json.RawMessage `json:"audio,omitempty"`
	ToolCalls    json.RawMessage `json:"tool_calls,omitempty"`
	FunctionCall json.RawMessage `json:"function_call,omitempty"`
}

// NewOpenAICompatible creates a provider-neutral Generator backed by the
// OpenAI chat-completions wire format. It never follows redirects.
func NewOpenAICompatible(config Config) (Generator, error) {
	endpoint, err := completionEndpoint(config.BaseURL, config.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	if err := validateIdentifier("model", config.Model, maxModelBytes, true); err != nil {
		return nil, fmt.Errorf("%w: model", ErrInvalidConfig)
	}
	if config.APIKey != "" {
		if err := validateIdentifier("API key", config.APIKey, maxAPIKeyBytes, true); err != nil {
			return nil, fmt.Errorf("%w: API key", ErrInvalidConfig)
		}
	}
	client := &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirect
		},
	}
	if endpoint.Scheme == "http" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = loopbackDialContext(net.DefaultResolver.LookupIPAddr, (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext)
		client.Transport = transport
	}
	return &openAICompatible{endpoint: endpoint, model: config.Model, apiKey: config.APIKey, client: client}, nil
}

func completionEndpoint(raw string, allowInsecureLoopback bool) (*url.URL, error) {
	if raw == "" || !utf8.ValidString(raw) || hasDisallowedControl(raw, false) {
		return nil, fmt.Errorf("%w: base URL", ErrInvalidConfig)
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("%w: base URL", ErrInvalidConfig)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%w: base URL components", ErrInvalidConfig)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !allowInsecureLoopback || !isLoopbackHost(parsed.Hostname()) {
			return nil, fmt.Errorf("%w: cleartext HTTP requires explicit loopback permission", ErrInvalidConfig)
		}
	default:
		return nil, fmt.Errorf("%w: URL scheme", ErrInvalidConfig)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	basePath := strings.TrimRight(parsed.Path, "/")
	if basePath == "/v1" || strings.HasSuffix(basePath, "/v1") {
		parsed.Path = basePath + "/chat/completions"
	} else {
		parsed.Path = basePath + "/v1/chat/completions"
	}
	parsed.RawPath = ""
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

type lookupIPAddrFunc func(context.Context, string) ([]net.IPAddr, error)
type dialContextFunc func(context.Context, string, string) (net.Conn, error)

func loopbackDialContext(lookup lookupIPAddrFunc, dial dialContextFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errLoopback
		}
		addresses, err := resolveLoopback(ctx, host, lookup)
		if err != nil {
			return nil, errLoopback
		}
		for _, resolved := range addresses {
			candidate := resolved.IP.String()
			if resolved.Zone != "" {
				candidate += "%" + resolved.Zone
			}
			connection, dialErr := dial(ctx, network, net.JoinHostPort(candidate, port))
			if dialErr == nil {
				return connection, nil
			}
		}
		return nil, errLoopback
	}
}

func resolveLoopback(ctx context.Context, host string, lookup lookupIPAddrFunc) ([]net.IPAddr, error) {
	if address := net.ParseIP(host); address != nil {
		if !address.IsLoopback() {
			return nil, errLoopback
		}
		return []net.IPAddr{{IP: address}}, nil
	}
	addresses, err := lookup(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errLoopback
	}
	for _, address := range addresses {
		if address.IP == nil || !address.IP.IsLoopback() {
			return nil, errLoopback
		}
	}
	return addresses, nil
}

func (g *openAICompatible) Generate(ctx context.Context, request Request) (Response, error) {
	if ctx == nil {
		return Response{}, fmt.Errorf("%w: missing context", ErrInvalidRequest)
	}
	if err := validateFreeText("system", request.System, maxSystemBytes, false); err != nil {
		return Response{}, fmt.Errorf("%w: system", ErrInvalidRequest)
	}
	if err := validateFreeText("input", request.Input, maxInputBytes, true); err != nil {
		return Response{}, fmt.Errorf("%w: input", ErrInvalidRequest)
	}
	messages := make([]chatMessage, 0, 2)
	if request.System != "" {
		messages = append(messages, chatMessage{Role: "system", Content: request.System})
	}
	messages = append(messages, chatMessage{Role: "user", Content: request.Input})
	payload, err := json.Marshal(chatCompletionRequest{Model: g.model, Messages: messages})
	if err != nil || len(payload) > maxHTTPBodyBytes {
		return Response{}, fmt.Errorf("%w: encoded body", ErrInvalidRequest)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("%w: create HTTP request", ErrProvider)
	}
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Content-Type", "application/json")
	if g.apiKey != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+g.apiKey)
	}

	httpResponse, err := g.client.Do(httpRequest)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Response{}, fmt.Errorf("%w: %v", ErrProvider, ctxErr)
		}
		return Response{}, ErrProvider
	}
	defer httpResponse.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(httpResponse.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("%w: read body", ErrInvalidResponse)
	}
	if len(raw) > maxHTTPBodyBytes {
		return Response{}, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidResponse, maxHTTPBodyBytes)
	}
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return Response{}, fmt.Errorf("%w: HTTP status %d", ErrProvider, httpResponse.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(httpResponse.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Response{}, fmt.Errorf("%w: content type", ErrInvalidResponse)
	}
	decoded, err := decodeChatCompletion(raw)
	if err != nil {
		return Response{}, err
	}
	return Response{Text: decoded.Choices[0].Message.Content}, nil
}

func decodeChatCompletion(raw []byte) (chatCompletionResponse, error) {
	if !utf8.Valid(raw) {
		return chatCompletionResponse{}, fmt.Errorf("%w: JSON encoding", ErrInvalidResponse)
	}
	if err := rejectDuplicateMembers(raw); err != nil {
		return chatCompletionResponse{}, fmt.Errorf("%w: JSON object", ErrInvalidResponse)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response chatCompletionResponse
	if err := decoder.Decode(&response); err != nil {
		return chatCompletionResponse{}, fmt.Errorf("%w: JSON object", ErrInvalidResponse)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return chatCompletionResponse{}, fmt.Errorf("%w: trailing JSON", ErrInvalidResponse)
	}
	if len(response.Choices) != 1 || response.Choices[0].Index != 0 {
		return chatCompletionResponse{}, fmt.Errorf("%w: exactly one indexed choice is required", ErrInvalidResponse)
	}
	if err := validateFreeText("output", response.Choices[0].Message.Content, maxOutputBytes, true); err != nil {
		return chatCompletionResponse{}, fmt.Errorf("%w: output", ErrInvalidResponse)
	}
	return response, nil
}

func validateIdentifier(_ string, value string, maximum int, required bool) error {
	if required && (value == "" || strings.TrimSpace(value) != value) {
		return errors.New("missing or padded value")
	}
	if !utf8.ValidString(value) || len(value) > maximum || hasDisallowedControl(value, false) {
		return errors.New("invalid bounded text")
	}
	return nil
}

func validateFreeText(_ string, value string, maximum int, required bool) error {
	if required && strings.TrimSpace(value) == "" {
		return errors.New("missing text")
	}
	if !utf8.ValidString(value) || len(value) > maximum || hasDisallowedControl(value, true) {
		return errors.New("invalid bounded text")
	}
	return nil
}

func hasDisallowedControl(value string, allowLayout bool) bool {
	for _, character := range value {
		if !unicode.IsControl(character) {
			continue
		}
		if allowLayout && (character == '\n' || character == '\r' || character == '\t') {
			continue
		}
		return true
	}
	return false
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func rejectDuplicateMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, true); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, enforceEnvelopeNames bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON member")
			}
			if enforceEnvelopeNames {
				if _, allowed := chatCompletionMemberNames[key]; !allowed {
					return errors.New("unknown JSON member")
				}
			}
			seen[key] = struct{}{}
			_, opaque := chatCompletionOpaqueMembers[key]
			if err := scanJSONValue(decoder, enforceEnvelopeNames && !opaque); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unclosed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, enforceEnvelopeNames); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unclosed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
