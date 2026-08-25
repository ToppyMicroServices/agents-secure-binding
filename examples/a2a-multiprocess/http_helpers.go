// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	a2aErrorInfoType = "type.googleapis.com/google.rpc.ErrorInfo"
	a2aErrorDomain   = "a2a-protocol.org"
	asbErrorDomain   = "agents-secure-binding"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	reader := io.LimitReader(r.Body, maxBodySize+1)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "request body is not valid for this endpoint")
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid-request", "Invalid request", "request contains trailing data")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, mediaType string, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "response encoding failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(append(payload, '\n')); err != nil {
		return
	}
}

func writeProblem(w http.ResponseWriter, status int, problemType, title, detail string) {
	writeJSON(w, status, problemMediaType, problem{
		Type:   "urn:agents-secure-binding:problem:" + problemType,
		Title:  title,
		Status: status,
		Detail: detail,
		Reason: problemType,
	})
}

func writeA2AProtocolError(w http.ResponseWriter, status int, reason, message string) {
	writeA2AError(w, status, reason, a2aErrorDomain, message)
}

func writeASBA2AError(w http.ResponseWriter, status int, reason, message string) {
	wireReason := "ASB_" + strings.ToUpper(strings.ReplaceAll(reason, "-", "_"))
	writeA2AError(w, status, wireReason, asbErrorDomain, message)
}

func writeA2AError(w http.ResponseWriter, status int, reason, domain, message string) {
	writeJSON(w, status, a2aMediaType, a2aErrorResponse{Error: a2aErrorStatus{
		Code: status, Status: a2aStatusName(status, reason), Message: message,
		Details: []a2aErrorDetail{{Type: a2aErrorInfoType, Reason: reason, Domain: domain}},
	}})
}

func a2aStatusName(status int, reason string) string {
	if reason == "VERSION_NOT_SUPPORTED" || reason == "EXTENSION_SUPPORT_REQUIRED" {
		return "FAILED_PRECONDITION"
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType:
		return "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	default:
		return "INTERNAL"
	}
}

func decodeA2AErrorReason(reader io.Reader, status int) (string, error) {
	var response a2aErrorResponse
	if err := json.NewDecoder(io.LimitReader(reader, maxBodySize)).Decode(&response); err != nil {
		return "", fmt.Errorf("decode A2A error: %w", err)
	}
	if response.Error.Code != status {
		return "", fmt.Errorf("A2A error code %d does not match HTTP status %d", response.Error.Code, status)
	}
	for _, detail := range response.Error.Details {
		if detail.Type != a2aErrorInfoType || detail.Reason == "" {
			continue
		}
		reason := strings.ToLower(strings.ReplaceAll(detail.Reason, "_", "-"))
		reason = strings.TrimPrefix(reason, "asb-")
		if reason == "version-not-supported" {
			return "a2a-version", nil
		}
		return reason, nil
	}
	return "", fmt.Errorf("A2A error has no ErrorInfo reason")
}

func postJSONContext(ctx context.Context, client *http.Client, url string, input, output any) error {
	payload, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var p problem
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxBodySize)).Decode(&p)
		if p.Reason != "" {
			return fmt.Errorf("remote rejected request: %s", p.Reason)
		}
		return fmt.Errorf("remote returned status %d", resp.StatusCode)
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodySize)).Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
