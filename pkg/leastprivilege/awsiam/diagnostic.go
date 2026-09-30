// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import "errors"

type providerError struct {
	stage, code string
	cause       error
	cli         *CLIFailure
}

// CLIFailure contains bounded process metadata and adapter-selected labels.
// It never contains command arguments, raw output, or unknown provider text.
type CLIFailure struct {
	ExitCode            int    `json:"exit_code"`
	Failure             string `json:"failure"`
	Format              string `json:"format"`
	Parse               string `json:"parse"`
	ProviderCode        string `json:"provider_code,omitempty"`
	StderrBytes         int    `json:"stderr_bytes"`
	StderrLimitExceeded bool   `json:"stderr_limit_exceeded"`
	StdoutLimitExceeded bool   `json:"stdout_limit_exceeded"`
}

func (e *providerError) Error() string { return e.cause.Error() }
func (e *providerError) Unwrap() error { return e.cause }

func providerFailure(stage, code string, cause error) error {
	return &providerError{stage: stage, code: code, cause: cause}
}

// Diagnostic exposes only labels chosen inside the adapter. Never log Error(),
// request data, raw provider diagnostics or credential material.
func Diagnostic(err error) (stage, code string) {
	var failure *providerError
	if errors.As(err, &failure) {
		return failure.stage, failure.code
	}
	return "adapter", "rejected"
}

// CLIDiagnostic returns a copy of the sanitized CLI failure, when available.
func CLIDiagnostic(err error) *CLIFailure {
	var failure *providerError
	if errors.As(err, &failure) && failure.cli != nil {
		copy := *failure.cli
		return &copy
	}
	return nil
}
