// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// This test-only process implements the small llama-server HTTP surface needed
// by the managed GGUF integration test. It does not perform model inference.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

type fixtureModel struct {
	Output    string `json:"output"`
	TracePath string `json:"trace_path"`
}

type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

type traceRecord struct {
	Method        string      `json:"method"`
	Path          string      `json:"path"`
	ContentType   string      `json:"content_type"`
	Authorization string      `json:"authorization"`
	Request       chatRequest `json:"request"`
}

func main() {
	if os.Getenv("ASB_TEST_ENV_POISON") != "" || os.Getenv("LLAMA_ARG_MODEL") != "" {
		log.Fatal("inherited parent environment")
	}
	modelPath := flag.String("model", "", "test fixture model path")
	alias := flag.String("alias", "", "model alias")
	socketPath := flag.String("host", "", "private Unix socket path")
	noWebUI := flag.Bool("no-webui", false, "disable web UI")
	flag.Parse()
	if flag.NArg() != 0 || *alias != "asb-verified-model" || !*noWebUI ||
		!filepath.IsAbs(*modelPath) || !filepath.IsAbs(*socketPath) {
		log.Fatal("unexpected managed server arguments")
	}
	raw, err := os.ReadFile(*modelPath)
	if err != nil || !bytes.HasPrefix(raw, []byte("GGUF")) {
		log.Fatal("invalid test fixture model")
	}
	var model fixtureModel
	if err := json.Unmarshal(raw[4:], &model); err != nil || model.Output == "" || model.TracePath == "" {
		log.Fatal("invalid test fixture model data")
	}
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
		decoder.DisallowUnknownFields()
		var request chatRequest
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid chat request", http.StatusBadRequest)
			return
		}
		trace := traceRecord{
			Method: r.Method, Path: r.URL.Path,
			ContentType: r.Header.Get("Content-Type"), Authorization: r.Header.Get("Authorization"),
			Request: request,
		}
		file, err := os.OpenFile(model.TracePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			http.Error(w, "trace unavailable", http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(file).Encode(trace); err != nil {
			_ = file.Close()
			http.Error(w, "trace unavailable", http.StatusInternalServerError)
			return
		}
		if err := file.Close(); err != nil {
			http.Error(w, "trace unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"model":"untrusted-provider-label","timings":{"predicted_n":1},"choices":[{"index":0,"message":{"role":"assistant","content":%q}}]}`, model.Output)
	})
	if err := http.Serve(listener, mux); err != nil {
		log.Fatal(err)
	}
}
