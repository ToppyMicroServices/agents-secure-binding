// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thinksyncs/agents-secure-binding/pkg/actionlifecycle"
	"github.com/thinksyncs/agents-secure-binding/pkg/taskcoord"
)

const (
	// BindingSchemaV1 identifies the immutable Task-to-Action binding.
	BindingSchemaV1 = "asb.task-action-binding/v1"
	// DependencyWaitSchemaV1 identifies one immutable dependency-wait decision.
	DependencyWaitSchemaV1 = "asb.task-action-dependency-wait/v1"
	// MaxDocumentBytes bounds strict JSON decoding.
	MaxDocumentBytes = 1 << 20
)

var (
	ErrInvalidBinding            = errors.New("task action binding: invalid binding")
	ErrAssignmentNotAccepted     = errors.New("task action binding: assignment is not accepted")
	ErrInvalidDependencyWait     = errors.New("task action binding: invalid dependency wait")
	ErrDependencyTopologyChanged = errors.New("task action binding: dependency topology changed")
	ErrDependenciesSatisfied     = errors.New("task action binding: dependencies are already satisfied")
	ErrDependenciesPending       = errors.New("task action binding: dependencies remain pending")
	ErrMissingStore              = errors.New("task action binding: missing store")
	ErrNotFound                  = errors.New("task action binding: not found")
	ErrAlreadyExists             = errors.New("task action binding: already exists")
	ErrEventConflict             = errors.New("task action binding: event identifier conflict")
	ErrStoreConflict             = errors.New("task action binding: store compare-and-swap conflict")
	ErrUseDependencyOperation    = errors.New("task action binding: use dependency wait or resume operation")
)

// Binding is the immutable identity join between responsibility and
// execution. Participant identity is derived from the Assignment and is not
// duplicated here.
type Binding struct {
	Schema       string    `json:"schema"`
	TaskID       string    `json:"task_id"`
	AssignmentID string    `json:"assignment_id"`
	ActionID     string    `json:"action_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// Validate checks the standalone shape of an immutable Binding.
func (b Binding) Validate() error {
	if b.Schema != BindingSchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidBinding)
	}
	for name, value := range map[string]string{
		"task_id": b.TaskID, "assignment_id": b.AssignmentID, "action_id": b.ActionID,
	} {
		if err := validateID(name, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
		}
	}
	if b.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is required", ErrInvalidBinding)
	}
	return nil
}

// DependencyWait records the exact dependency topology used to put an Action
// into WAITING. Satisfaction is deliberately not copied: it remains current
// TaskCoord state and is re-read when resuming.
type DependencyWait struct {
	Schema              string    `json:"schema"`
	TaskID              string    `json:"task_id"`
	ActionID            string    `json:"action_id"`
	ActionRevision      uint64    `json:"action_revision"`
	DependencyIDs       []string  `json:"dependency_ids"`
	DependencySetDigest string    `json:"dependency_set_digest"`
	CreatedAt           time.Time `json:"created_at"`
}

// Validate checks the standalone shape and canonical ordering of a wait.
func (w DependencyWait) Validate() error {
	if w.Schema != DependencyWaitSchemaV1 {
		return fmt.Errorf("%w: unsupported schema", ErrInvalidDependencyWait)
	}
	for name, value := range map[string]string{"task_id": w.TaskID, "action_id": w.ActionID} {
		if err := validateID(name, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidDependencyWait, err)
		}
	}
	if w.ActionRevision == 0 {
		return fmt.Errorf("%w: action_revision must be positive", ErrInvalidDependencyWait)
	}
	if len(w.DependencyIDs) == 0 {
		return fmt.Errorf("%w: dependency_ids must not be empty", ErrInvalidDependencyWait)
	}
	for index, id := range w.DependencyIDs {
		if err := validateID("dependency_id", id); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidDependencyWait, err)
		}
		if index > 0 && w.DependencyIDs[index-1] >= id {
			return fmt.Errorf("%w: dependency_ids must be sorted and unique", ErrInvalidDependencyWait)
		}
	}
	if err := validateDigest(w.DependencySetDigest); err != nil {
		return fmt.Errorf("%w: dependency_set_digest: %v", ErrInvalidDependencyWait, err)
	}
	if w.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at is required", ErrInvalidDependencyWait)
	}
	return nil
}

// LinkedAction supplies the current snapshots needed for Task liveness
// projection. DependencyWait is nil for time, signal, manual, and other
// progress sources outside the Task dependency graph.
type LinkedAction struct {
	Binding        Binding
	Assignment     taskcoord.Assignment
	Action         actionlifecycle.Snapshot
	DependencyWait *DependencyWait
}

func validateID(name, value string) error {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func validateDigest(value string) error {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return fmt.Errorf("must be canonical sha256:<lowercase-hex>")
	}
	for _, r := range value[len("sha256:"):] {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return fmt.Errorf("must be canonical sha256:<lowercase-hex>")
		}
	}
	return nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sortedCopy(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}
