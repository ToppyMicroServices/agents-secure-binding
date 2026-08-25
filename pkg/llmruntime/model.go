// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package llmruntime provides a small provider-neutral text-generation
// boundary for A2A Agent runtimes. Provider credentials remain configuration
// of the concrete Generator and are never part of Request or Response.
package llmruntime

import "context"

// Generator produces one bounded text response.
type Generator interface {
	Generate(context.Context, Request) (Response, error)
}

// Request contains the text made available to a model. System is optional.
type Request struct {
	System string
	Input  string
}

// Response is the model text accepted by the runtime.
type Response struct {
	Text string
}
