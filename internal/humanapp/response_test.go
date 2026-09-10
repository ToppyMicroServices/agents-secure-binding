// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpenStoreContextRejectsCancellationBeforeCreatingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.sqlite")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	store, err := OpenStoreContext(ctx, path)
	if !errors.Is(err, ErrUnavailable) || store != nil {
		t.Fatalf("canceled open = %v, %v", store, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled open created state: %v", err)
	}
	if store, err := OpenStoreContext(nil, path); !errors.Is(err, ErrInvalid) || store != nil {
		t.Fatalf("nil context open = %v, %v", store, err)
	}
}

func TestJSONResponsePreservesEncoderBytes(t *testing.T) {
	value := map[string]any{"message": "<ready>", "at": time.Unix(1, 2).UTC()}
	var expected bytes.Buffer
	if err := json.NewEncoder(&expected).Encode(value); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	writeJSONResponse(response, http.StatusCreated, value)
	if response.Code != http.StatusCreated || !bytes.Equal(response.Body.Bytes(), expected.Bytes()) {
		t.Fatalf("response = %d %q, want %q", response.Code, response.Body.Bytes(), expected.Bytes())
	}
}

func TestJSONResponseRejectsEncodingBeforeSuccessHeaders(t *testing.T) {
	response := httptest.NewRecorder()
	writeJSONResponse(response, http.StatusOK, map[string]any{
		"private": "response-private-canary", "at": time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if response.Code != http.StatusServiceUnavailable || !json.Valid(response.Body.Bytes()) || strings.Contains(response.Body.String(), "response-private-canary") {
		t.Fatalf("unsafe error response = %d %s", response.Code, response.Body)
	}
}

type failingResponseWriter struct {
	header http.Header
	status int
	writes int
}

func (w *failingResponseWriter) Header() http.Header    { return w.header }
func (w *failingResponseWriter) WriteHeader(status int) { w.status = status }
func (w *failingResponseWriter) Write([]byte) (int, error) {
	w.writes++
	return 1, io.ErrClosedPipe
}

func TestJSONResponseDoesNotAppendAfterPartialWrite(t *testing.T) {
	writer := &failingResponseWriter{header: make(http.Header)}
	writeJSONResponse(writer, http.StatusOK, map[string]string{"result": "accepted"})
	if writer.status != http.StatusOK || writer.writes != 1 {
		t.Fatalf("status = %d, writes = %d", writer.status, writer.writes)
	}
}
