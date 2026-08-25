// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDecodeChallengeHTTPResponseV2AcceptsExactEnvelope(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	attempt := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	body := fmt.Sprintf(`{"verifier_nonce":%q,"attempt_id":%q,"expires_at":%d}`, nonce, attempt, now.Add(time.Minute).Unix())

	challenge, err := decodeChallengeHTTPResponseV2(responseForClientValidationV2(http.StatusOK, "application/json", []byte(body)), now)
	if err != nil {
		t.Fatalf("decodeChallengeHTTPResponseV2() error = %v", err)
	}
	if challenge.VerifierNonce != nonce || challenge.AttemptID != attempt || challenge.ExpiresAt != now.Add(time.Minute).Unix() {
		t.Fatalf("challenge = %+v", challenge)
	}
}

func TestDecodeA2ASendHTTPResponseV2AcceptsCurrentEnvelopes(t *testing.T) {
	completedAt := time.Date(2026, 8, 25, 12, 0, 0, 123, time.UTC)
	operationResult, err := completedOperationResultV2(newTaskRequestV2(), "completed text", completedAt)
	if err != nil {
		t.Fatalf("completedOperationResultV2() error = %v", err)
	}
	result, err := decodeA2ASendHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, operationResult.Body))
	if err != nil {
		t.Fatalf("decode success error = %v", err)
	}
	if result.status != http.StatusOK || result.task.Task.ID != demoTaskID {
		t.Fatalf("success result = %+v", result)
	}

	problemBody := []byte(`{"type":"urn:agents-secure-binding:problem:challenge-rejected","title":"Challenge rejected","status":403,"detail":"not valid","reason":"challenge-rejected"}`)
	result, err = decodeA2ASendHTTPResponseV2(responseForClientValidationV2(http.StatusForbidden, problemMediaType, problemBody))
	if err != nil {
		t.Fatalf("decode problem error = %v", err)
	}
	if result.status != http.StatusForbidden || result.reason != "challenge-rejected" {
		t.Fatalf("problem result = %+v", result)
	}
}

func TestValidateAgentCardHTTPResponseV2AcceptsSemanticProfileAndStandardFields(t *testing.T) {
	body := fmt.Sprintf(`{
		"name":"Agent B",
		"description":"standard field",
		"supportedInterfaces":[
			{"url":"https://agent-b.example","protocolBinding":"GRPC","protocolVersion":"1.0"},
			{"url":"https://agent-b.example","protocolBinding":"HTTP+JSON","protocolVersion":"1.0","tenant":"example"}
		],
		"capabilities":{"streaming":false,"extensions":[
			{"uri":%q,"required":true,"description":"binding"},
			{"uri":%q,"required":true},
			{"uri":"urn:example:optional","required":false}
		]},
		"securitySchemes":{"mutualTLS":{"mtlsSecurityScheme":{"description":"mTLS"}}},
		"securityRequirements":[{"schemes":{"mutualTLS":{"list":[]}}}],
		"skills":[]
	}`, securityBindingExtensionV2, attestationResultExtensionV2)
	if err := validateAgentCardHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, []byte(body))); err != nil {
		t.Fatalf("validateAgentCardHTTPResponseV2() error = %v", err)
	}
}

func TestV2ClientResponseValidationRejectsWrongMediaType(t *testing.T) {
	body := []byte(`{"task":{}}`)
	for _, contentType := range []string{"application/json", a2aMediaType + "; charset=utf-8"} {
		t.Run(contentType, func(t *testing.T) {
			_, err := decodeA2ASendHTTPResponseV2(responseForClientValidationV2(http.StatusOK, contentType, body))
			if err == nil || !strings.Contains(err.Error(), "Content-Type") {
				t.Fatalf("error = %v, want Content-Type rejection", err)
			}
		})
	}
}

func TestV2ClientResponseValidationRejectsOversizedTrailingAndDuplicateJSON(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	attempt := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	validChallenge := fmt.Sprintf(`{"verifier_nonce":%q,"attempt_id":%q,"expires_at":%d}`, nonce, attempt, now.Add(time.Minute).Unix())

	tests := []struct {
		name string
		body []byte
	}{
		{name: "oversized", body: bytes.Repeat([]byte{' '}, maxBodySize+1)},
		{name: "trailing value", body: []byte(validChallenge + `{}`)},
		{name: "recursive duplicate", body: []byte(fmt.Sprintf(`{"verifier_nonce":%q,"attempt_id":%q,"expires_at":%d,"nested":{"key":1,"key":2}}`, nonce, attempt, now.Add(time.Minute).Unix()))},
		{name: "invalid utf8", body: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeChallengeHTTPResponseV2(responseForClientValidationV2(http.StatusOK, "application/json", test.body), now); err == nil {
				t.Fatal("malformed response was accepted")
			}
		})
	}
}

func TestDecodeChallengeHTTPResponseV2RejectsUnsupportedMember(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	attempt := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16))
	body := fmt.Sprintf(`{"verifier_nonce":%q,"attempt_id":%q,"expires_at":%d,"extra":true}`, nonce, attempt, now.Add(time.Minute).Unix())
	if _, err := decodeChallengeHTTPResponseV2(responseForClientValidationV2(http.StatusOK, "application/json", []byte(body)), now); err == nil {
		t.Fatal("challenge with an unsupported member was accepted")
	}
}

func TestValidateAgentCardHTTPResponseV2RejectsSubstringOnlyExtension(t *testing.T) {
	tests := []struct {
		name             string
		securityURI      string
		securityRequired bool
	}{
		{name: "substring URI", securityURI: "prefix:" + securityBindingExtensionV2 + ":suffix", securityRequired: true},
		{name: "not required", securityURI: securityBindingExtensionV2, securityRequired: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf(`{
				"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
				"capabilities":{"extensions":[
					{"uri":%q,"required":%t},
					{"uri":%q,"required":true}
				]},
				"securitySchemes":{"mutualTLS":{"mtlsSecurityScheme":{}}},
				"securityRequirements":[{"schemes":{"mutualTLS":{"list":[]}}}]
			}`, test.securityURI, test.securityRequired, attestationResultExtensionV2)
			if err := validateAgentCardHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, []byte(body))); err == nil {
				t.Fatal("Agent Card without an exact required extension was accepted")
			}
		})
	}
}

func TestValidateAgentCardHTTPResponseV2RejectsUnsupportedRequiredExtension(t *testing.T) {
	body := fmt.Sprintf(`{
		"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
		"capabilities":{"extensions":[
			{"uri":%q,"required":true},
			{"uri":%q,"required":true},
			{"uri":"urn:example:unsupported","required":true}
		]},
		"securitySchemes":{"mutualTLS":{"mtlsSecurityScheme":{}}},
		"securityRequirements":[{"schemes":{"mutualTLS":{"list":[]}}}]
	}`, securityBindingExtensionV2, attestationResultExtensionV2)
	if err := validateAgentCardHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, []byte(body))); err == nil {
		t.Fatal("Agent Card requiring an unsupported extension was accepted")
	}
}

func TestValidateAgentCardHTTPResponseV2RequiresMutualTLS(t *testing.T) {
	base := fmt.Sprintf(`{
		"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
		"capabilities":{"extensions":[
			{"uri":%q,"required":true},
			{"uri":%q,"required":true}
		]},
		%s
	}`, securityBindingExtensionV2, attestationResultExtensionV2, "%s")
	tests := map[string]string{
		"missing scheme":      `"securitySchemes":{},"securityRequirements":[{"schemes":{"mutualTLS":{"list":[]}}}]`,
		"missing requirement": `"securitySchemes":{"mutualTLS":{"mtlsSecurityScheme":{}}},"securityRequirements":[]`,
	}
	for name, securityFields := range tests {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(base, securityFields)
			if err := validateAgentCardHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, []byte(body))); err == nil {
				t.Fatal("Agent Card without complete mutualTLS semantics was accepted")
			}
		})
	}
}

func TestDecodeA2ASendHTTPResponseV2RejectsProblemStatusMismatch(t *testing.T) {
	body := []byte(`{"type":"urn:agents-secure-binding:problem:challenge-rejected","title":"Challenge rejected","status":400,"detail":"not valid","reason":"challenge-rejected"}`)
	_, err := decodeA2ASendHTTPResponseV2(responseForClientValidationV2(http.StatusForbidden, problemMediaType, body))
	if err == nil || !strings.Contains(err.Error(), "does not match HTTP status") {
		t.Fatalf("error = %v, want status mismatch", err)
	}
}

func TestDecodeA2ASendHTTPResponseV2RejectsDuplicateNestedTaskMember(t *testing.T) {
	completedAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	operationResult, err := completedOperationResultV2(newTaskRequestV2(), "completed text", completedAt)
	if err != nil {
		t.Fatalf("completedOperationResultV2() error = %v", err)
	}
	body := bytes.Replace(operationResult.Body, []byte(`"state":"TASK_STATE_COMPLETED"`), []byte(`"state":"TASK_STATE_COMPLETED","state":"TASK_STATE_COMPLETED"`), 1)
	if _, err := decodeA2ASendHTTPResponseV2(responseForClientValidationV2(http.StatusOK, a2aMediaType, body)); err == nil {
		t.Fatal("Task response with a duplicate nested member was accepted")
	}
}

func responseForClientValidationV2(status int, contentType string, body []byte) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", contentType)
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}
