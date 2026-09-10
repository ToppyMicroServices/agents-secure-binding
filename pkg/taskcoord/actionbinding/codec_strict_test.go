// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStrictDecodersRejectDuplicateMembersAndOversize(t *testing.T) {
	t.Parallel()
	binding := Binding{
		Schema: BindingSchemaV1, TaskID: "task:1", AssignmentID: "assignment:1",
		ActionID: "action:1", CreatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
	wait := DependencyWait{
		Schema: DependencyWaitSchemaV1, TaskID: "task:1", ActionID: "action:1",
		ActionRevision: 1, DependencyIDs: []string{"dependency:1"},
		DependencySetDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: binding.CreatedAt,
	}
	bindingRaw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	waitRaw, err := json.Marshal(wait)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		raw    []byte
		decode func(*bytes.Reader) error
	}{
		{
			name:   "binding duplicate",
			raw:    bytes.Replace(bindingRaw, []byte(`"action_id":`), []byte(`"action_id":"shadow","action_id":`), 1),
			decode: func(r *bytes.Reader) error { _, err := DecodeBinding(r); return err },
		},
		{
			name:   "binding escaped duplicate",
			raw:    bytes.Replace(bindingRaw, []byte(`"action_id":`), []byte(`"action_id":"shadow","action_i\u0064":`), 1),
			decode: func(r *bytes.Reader) error { _, err := DecodeBinding(r); return err },
		},
		{
			name:   "dependency wait duplicate",
			raw:    bytes.Replace(waitRaw, []byte(`"dependency_ids":`), []byte(`"dependency_ids":[],"dependency_ids":`), 1),
			decode: func(r *bytes.Reader) error { _, err := DecodeDependencyWait(r); return err },
		},
		{
			name:   "binding oversized",
			raw:    append(append([]byte(nil), bindingRaw...), bytes.Repeat([]byte{' '}, MaxDocumentBytes-len(bindingRaw)+1)...),
			decode: func(r *bytes.Reader) error { _, err := DecodeBinding(r); return err },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(bytes.NewReader(test.raw)); err == nil {
				t.Fatal("unsafe JSON document accepted")
			}
		})
	}

	if _, err := DecodeBinding(bytes.NewReader(bindingRaw)); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	if _, err := DecodeDependencyWait(bytes.NewReader(waitRaw)); err != nil {
		t.Fatalf("valid DependencyWait rejected: %v", err)
	}

	var typedNil *bytes.Reader
	if _, err := DecodeBinding(typedNil); !errors.Is(err, ErrInvalidBinding) {
		t.Fatalf("DecodeBinding() typed-nil error = %v, want %v", err, ErrInvalidBinding)
	}
	if _, err := DecodeDependencyWait(typedNil); !errors.Is(err, ErrInvalidDependencyWait) {
		t.Fatalf("DecodeDependencyWait() typed-nil error = %v, want %v", err, ErrInvalidDependencyWait)
	}
}
