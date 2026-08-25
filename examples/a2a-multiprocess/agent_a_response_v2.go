// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"
)

func decodeChallengeHTTPResponseV2(response *http.Response, now time.Time) (challengeResponseV2, error) {
	if response.StatusCode != http.StatusOK {
		reason, err := decodeProblemHTTPResponseV2(response)
		if err != nil {
			return challengeResponseV2{}, fmt.Errorf("decode challenge problem: %w", err)
		}
		return challengeResponseV2{}, fmt.Errorf("challenge rejected: %s", reason)
	}
	raw, err := readStrictHTTPJSONBodyV2(response, "application/json")
	if err != nil {
		return challengeResponseV2{}, fmt.Errorf("decode challenge response: %w", err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return challengeResponseV2{}, fmt.Errorf("decode challenge response: response must be an object")
	}
	if err := requireExactMemberSetV2(members, "verifier_nonce", "attempt_id", "expires_at"); err != nil {
		return challengeResponseV2{}, fmt.Errorf("decode challenge response: %w", err)
	}
	var challenge challengeResponseV2
	if err := decodeExactJSONV2(raw, &challenge); err != nil {
		return challengeResponseV2{}, fmt.Errorf("decode challenge response: %w", err)
	}
	if _, err := decodeNonceV2(challenge.VerifierNonce, 32); err != nil {
		return challengeResponseV2{}, err
	}
	if _, err := decodeNonceV2(challenge.AttemptID, 16); err != nil {
		return challengeResponseV2{}, err
	}
	if challenge.ExpiresAt <= now.UTC().Unix() {
		return challengeResponseV2{}, fmt.Errorf("challenge is already expired")
	}
	return challenge, nil
}

func decodeA2ASendHTTPResponseV2(response *http.Response) (a2aResult, error) {
	result := a2aResult{status: response.StatusCode}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return a2aResult{}, fmt.Errorf("unsupported successful A2A status %d", response.StatusCode)
		}
		reason, err := decodeProblemHTTPResponseV2(response)
		if err != nil {
			return a2aResult{}, fmt.Errorf("decode A2A problem: %w", err)
		}
		result.reason = reason
		return result, nil
	}
	raw, err := readStrictHTTPJSONBodyV2(response, a2aMediaType)
	if err != nil {
		return a2aResult{}, fmt.Errorf("decode A2A task: %w", err)
	}
	if err := validateExactTaskResponseMembersV2(raw); err != nil {
		return a2aResult{}, fmt.Errorf("decode A2A task: %w", err)
	}
	if err := decodeExactJSONV2(raw, &result.task); err != nil {
		return a2aResult{}, fmt.Errorf("decode A2A task: %w", err)
	}
	if _, err := completedConversationTextV2(result.task); err != nil {
		return a2aResult{}, err
	}
	if result.task.Task.Artifacts[0].ArtifactID == "" || result.task.Task.Artifacts[0].Name == "" {
		return a2aResult{}, fmt.Errorf("Agent B returned an invalid completed draft-06 Task artifact")
	}
	if _, err := time.Parse(time.RFC3339Nano, result.task.Task.Status.Timestamp); err != nil {
		return a2aResult{}, fmt.Errorf("Agent B returned an invalid completed draft-06 Task timestamp")
	}
	return result, nil
}

func validateAgentCardHTTPResponseV2(response *http.Response) error {
	if response.StatusCode != http.StatusOK {
		reason, err := decodeProblemHTTPResponseV2(response)
		if err != nil {
			return fmt.Errorf("decode Agent B card problem: %w", err)
		}
		return fmt.Errorf("discover draft-06 Agent B card: status %d reason %s", response.StatusCode, reason)
	}
	raw, err := readStrictHTTPJSONBodyV2(response, a2aMediaType)
	if err != nil {
		return fmt.Errorf("decode Agent B card: %w", err)
	}
	var card struct {
		SupportedInterfaces []struct {
			ProtocolBinding string `json:"protocolBinding"`
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"supportedInterfaces"`
		Capabilities struct {
			Extensions []struct {
				URI      string `json:"uri"`
				Required bool   `json:"required"`
			} `json:"extensions"`
		} `json:"capabilities"`
		SecuritySchemes      map[string]json.RawMessage `json:"securitySchemes"`
		SecurityRequirements []struct {
			Schemes map[string]json.RawMessage `json:"schemes"`
		} `json:"securityRequirements"`
	}
	if err := json.Unmarshal(raw, &card); err != nil {
		return fmt.Errorf("decode Agent B card: %w", err)
	}
	hasInterface := false
	for _, candidate := range card.SupportedInterfaces {
		if candidate.ProtocolBinding == "HTTP+JSON" && candidate.ProtocolVersion == a2aVersion {
			hasInterface = true
			break
		}
	}
	if !hasInterface {
		return fmt.Errorf("Agent B card does not advertise the required A2A 1.0 HTTP+JSON interface")
	}
	required := map[string]bool{
		securityBindingExtensionV2:   false,
		attestationResultExtensionV2: false,
	}
	for _, extension := range card.Capabilities.Extensions {
		if _, tracked := required[extension.URI]; tracked {
			if extension.Required {
				required[extension.URI] = true
			}
			continue
		}
		if extension.Required {
			return fmt.Errorf("Agent B card requires unsupported extension %q", extension.URI)
		}
	}
	for _, advertised := range required {
		if !advertised {
			return fmt.Errorf("Agent B card does not require the draft-06 extension profile")
		}
	}
	if err := validateAgentCardMutualTLSV2(card.SecuritySchemes, card.SecurityRequirements); err != nil {
		return err
	}
	return nil
}

func validateAgentCardMutualTLSV2(schemes map[string]json.RawMessage, requirements []struct {
	Schemes map[string]json.RawMessage `json:"schemes"`
}) error {
	rawScheme, ok := schemes["mutualTLS"]
	if !ok {
		return fmt.Errorf("Agent B card does not advertise the required mutualTLS security scheme")
	}
	var scheme struct {
		MTLS json.RawMessage `json:"mtlsSecurityScheme"`
	}
	if err := json.Unmarshal(rawScheme, &scheme); err != nil || len(scheme.MTLS) == 0 || string(scheme.MTLS) == "null" {
		return fmt.Errorf("Agent B card has an invalid mutualTLS security scheme")
	}
	var schemeObject map[string]json.RawMessage
	if err := json.Unmarshal(scheme.MTLS, &schemeObject); err != nil {
		return fmt.Errorf("Agent B card has an invalid mutualTLS security scheme")
	}
	for _, requirement := range requirements {
		rawRequirement, present := requirement.Schemes["mutualTLS"]
		if !present {
			continue
		}
		var memberSet map[string]json.RawMessage
		if err := json.Unmarshal(rawRequirement, &memberSet); err != nil {
			continue
		}
		rawList, present := memberSet["list"]
		if !present {
			continue
		}
		var values []string
		if err := json.Unmarshal(rawList, &values); err == nil {
			return nil
		}
	}
	return fmt.Errorf("Agent B card does not require the mutualTLS security scheme")
}

func decodeProblemHTTPResponseV2(response *http.Response) (string, error) {
	raw, err := readStrictHTTPJSONBodyV2(response, problemMediaType)
	if err != nil {
		return "", err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return "", fmt.Errorf("problem response must be an object")
	}
	if err := requireExactMemberSetV2(members, "type", "title", "status", "detail", "reason"); err != nil {
		return "", err
	}
	var remote problem
	if err := decodeExactJSONV2(raw, &remote); err != nil {
		return "", err
	}
	if remote.Status != response.StatusCode {
		return "", fmt.Errorf("problem status %d does not match HTTP status %d", remote.Status, response.StatusCode)
	}
	if remote.Reason == "" || remote.Title == "" || remote.Detail == "" || remote.Type != "urn:agents-secure-binding:problem:"+remote.Reason {
		return "", fmt.Errorf("problem response is outside the current server envelope")
	}
	return remote.Reason, nil
}

func readStrictHTTPJSONBodyV2(response *http.Response, expectedMediaType string) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, fmt.Errorf("response body is unavailable")
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, fmt.Errorf("response must have exactly one Content-Type header")
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != expectedMediaType || len(parameters) != 0 {
		return nil, fmt.Errorf("response has unsupported Content-Type %q", response.Header.Get("Content-Type"))
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(raw) == 0 || len(raw) > maxBodySize {
		return nil, fmt.Errorf("response body is empty or too large")
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("response body must be valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeStrictJSONValueV2(decoder); err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, fmt.Errorf("response contains trailing JSON")
	}
	return raw, nil
}

func decodeExactJSONV2(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("response contains trailing JSON")
	}
	return nil
}

func validateExactTaskResponseMembersV2(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("Task response must be an object")
	}
	if err := requireExactMemberSetV2(root, "task"); err != nil {
		return err
	}
	var task map[string]json.RawMessage
	if err := json.Unmarshal(root["task"], &task); err != nil {
		return fmt.Errorf("task must be an object")
	}
	if err := requireExactMemberSetV2(task, "id", "contextId", "status", "artifacts"); err != nil {
		return err
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(task["status"], &status); err != nil {
		return fmt.Errorf("task status must be an object")
	}
	if err := requireExactMemberSetV2(status, "state", "timestamp"); err != nil {
		return err
	}
	var artifacts []json.RawMessage
	if err := json.Unmarshal(task["artifacts"], &artifacts); err != nil || len(artifacts) != 1 {
		return fmt.Errorf("task artifacts must contain exactly one object")
	}
	var artifact map[string]json.RawMessage
	if err := json.Unmarshal(artifacts[0], &artifact); err != nil {
		return fmt.Errorf("task artifact must be an object")
	}
	if err := requireExactMemberSetV2(artifact, "artifactId", "name", "parts"); err != nil {
		return err
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(artifact["parts"], &parts); err != nil || len(parts) != 1 {
		return fmt.Errorf("task artifact parts must contain exactly one object")
	}
	var part map[string]json.RawMessage
	if err := json.Unmarshal(parts[0], &part); err != nil {
		return fmt.Errorf("task artifact part must be an object")
	}
	return requireExactMemberSetV2(part, "text", "mediaType")
}
