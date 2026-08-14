// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeBinding strictly decodes and validates one bounded Binding.
func DecodeBinding(r io.Reader) (Binding, error) {
	var binding Binding
	if err := decodeStrict(r, &binding); err != nil {
		return Binding{}, fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

// DecodeDependencyWait strictly decodes and validates one bounded wait.
func DecodeDependencyWait(r io.Reader) (DependencyWait, error) {
	var wait DependencyWait
	if err := decodeStrict(r, &wait); err != nil {
		return DependencyWait{}, fmt.Errorf("%w: %v", ErrInvalidDependencyWait, err)
	}
	if err := wait.Validate(); err != nil {
		return DependencyWait{}, err
	}
	return wait, nil
}

func decodeStrict(r io.Reader, destination any) error {
	if r == nil {
		return fmt.Errorf("missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON: %v", err)
	}
	if len(raw) > MaxDocumentBytes {
		return fmt.Errorf("JSON exceeds %d bytes", MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode JSON: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
