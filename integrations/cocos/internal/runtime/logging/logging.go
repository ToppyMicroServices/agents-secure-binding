// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// New returns a JSON slog logger configured from a slog level string.
func New(w io.Writer, levelText string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", levelText, err)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})), nil
}

// NewMock returns a quiet in-memory logger for tests.
func NewMock() *slog.Logger {
	return slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
}

// ExitWithError exits with the value stored in code.
func ExitWithError(code *int) {
	os.Exit(*code)
}
