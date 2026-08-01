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
