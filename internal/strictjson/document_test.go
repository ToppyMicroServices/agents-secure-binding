// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package strictjson

import (
	"bytes"
	"strings"
	"testing"
)

func TestValidateDocumentRejectsAmbiguousJSON(t *testing.T) {
	t.Parallel()
	tests := map[string][]byte{
		"duplicate member":         []byte(`{"value":1,"value":2}`),
		"escaped duplicate member": []byte(`{"value":1,"v\u0061lue":2}`),
		"nested duplicate member":  []byte(`{"outer":[{"value":1,"value":2}]}`),
		"invalid UTF-8":            {'{', '"', 0xff, '"', ':', '1', '}'},
		"trailing value":           []byte(`{"value":1}{"value":2}`),
	}
	for name, raw := range tests {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateDocument(raw, 1<<20); err == nil {
				t.Fatal("unsafe JSON document accepted")
			}
		})
	}
}

func TestReadDocumentEnforcesLimitAndPreservesValidJSON(t *testing.T) {
	t.Parallel()
	const limit = 32
	valid := []byte(`{"outer":[{"value":1}]}`)
	got, err := ReadDocument(bytes.NewReader(valid), limit)
	if err != nil {
		t.Fatalf("valid JSON rejected: %v", err)
	}
	if !bytes.Equal(got, valid) {
		t.Fatalf("read JSON = %q, want %q", got, valid)
	}
	if _, err := ReadDocument(strings.NewReader(strings.Repeat(" ", limit+1)), limit); err == nil {
		t.Fatal("oversized JSON document accepted")
	}
	if _, err := ReadDocument(nil, limit); err == nil {
		t.Fatal("nil JSON reader accepted")
	}
	var typedNil *bytes.Reader
	if _, err := ReadDocument(typedNil, limit); err == nil {
		t.Fatal("typed-nil JSON reader accepted")
	}
}
