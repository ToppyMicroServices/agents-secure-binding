// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package strictjson validates bounded JSON documents before callers decode
// them into a schema instance or a Go type.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

// ReadDocument reads and validates exactly one bounded JSON value.
func ReadDocument(r io.Reader, maxBytes int64) ([]byte, error) {
	if isNilReader(r) {
		return nil, errors.New("missing JSON input")
	}
	if maxBytes < 1 {
		return nil, errors.New("invalid JSON size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read JSON: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("JSON exceeds %d bytes", maxBytes)
	}
	if err := ValidateDocument(raw, maxBytes); err != nil {
		return nil, err
	}
	return raw, nil
}

func isNilReader(r io.Reader) bool {
	if r == nil {
		return true
	}
	value := reflect.ValueOf(r)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// ValidateDocument validates exactly one bounded JSON value. Object member
// names are compared after JSON unescaping, so an escaped spelling cannot
// bypass duplicate-member rejection.
func ValidateDocument(raw []byte, maxBytes int64) error {
	if maxBytes < 1 {
		return errors.New("invalid JSON size limit")
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("JSON exceeds %d bytes", maxBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("JSON is not valid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			member, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := member.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object member %q", name)
			}
			seen[name] = struct{}{}
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
