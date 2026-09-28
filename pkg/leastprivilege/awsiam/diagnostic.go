// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package awsiam

import "errors"

type providerError struct {
	stage, code string
	cause       error
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
