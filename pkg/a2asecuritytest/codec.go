// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package a2asecuritytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var reportMemberNames = map[string]struct{}{
	"schema": {}, "tool": {}, "run_id": {}, "profile": {}, "mode": {},
	"attestation": {}, "started_at": {}, "finished_at": {}, "status": {},
	"summary": {}, "scenarios": {},
	"name": {}, "version": {}, "commit": {}, "platform": {},
	"total": {}, "passed": {}, "failed": {}, "indeterminate": {}, "errors": {},
	"id": {}, "risk": {}, "expected": {}, "observed": {},
	"decision": {}, "http_status": {}, "reason": {},
}

// DecodeReport strictly decodes and validates one bounded report.
func DecodeReport(reader io.Reader) (Report, error) {
	if reader == nil {
		return Report{}, invalidReport("missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxReportBytes+1))
	if err != nil {
		return Report{}, invalidReport(fmt.Sprintf("read JSON: %v", err))
	}
	if len(raw) > MaxReportBytes {
		return Report{}, invalidReport(fmt.Sprintf("JSON exceeds %d bytes", MaxReportBytes))
	}
	if !utf8.Valid(raw) {
		return Report{}, invalidReport("JSON is not valid UTF-8")
	}
	if err := rejectDuplicateMembers(raw); err != nil {
		return Report{}, invalidReport(fmt.Sprintf("decode JSON: %v", err))
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, invalidReport(fmt.Sprintf("decode JSON: %v", err))
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Report{}, invalidReport("trailing JSON value")
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func rejectDuplicateMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
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
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object member %q", key)
			}
			if _, allowed := reportMemberNames[key]; !allowed {
				return fmt.Errorf("unknown object member %q", key)
			}
			seen[key] = struct{}{}
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
