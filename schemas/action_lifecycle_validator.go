// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	actionLifecycleSchemaURL   = "https://github.com/thinksyncs/agents-secure-binding/schemas/action-lifecycle-v1.schema.json"
	taskActionBindingSchemaURL = "https://github.com/thinksyncs/agents-secure-binding/schemas/task-action-binding-v1.schema.json"
)

//go:embed action-lifecycle-v1.schema.json
var actionLifecycleSchemaBytes []byte

//go:embed task-action-binding-v1.schema.json
var taskActionBindingSchemaBytes []byte

var (
	actionLifecycleSchemaOnce sync.Once
	actionLifecycleSchema     *jsonschema.Schema
	errActionLifecycleSchema  error

	taskActionBindingSchemaOnce sync.Once
	taskActionBindingSchema     *jsonschema.Schema
	errTaskActionBindingSchema  error
)

// PrepareActionLifecycleValidator compiles the Action snapshot schema so a
// service can fail at startup instead of on its first request.
func PrepareActionLifecycleValidator() error {
	actionLifecycleSchemaOnce.Do(func() {
		actionLifecycleSchema, errActionLifecycleSchema = compileEmbeddedSchema(actionLifecycleSchemaURL, actionLifecycleSchemaBytes)
	})
	if errActionLifecycleSchema != nil {
		return fmt.Errorf("compile Action lifecycle schema: %w", errActionLifecycleSchema)
	}
	return nil
}

// ValidateActionLifecycleJSON validates the JSON shape of one durable Action
// snapshot. Call actionlifecycle.DecodeSnapshot for semantic invariants.
func ValidateActionLifecycleJSON(raw []byte) error {
	if err := PrepareActionLifecycleValidator(); err != nil {
		return err
	}
	return validateEmbeddedJSON("Action lifecycle", actionLifecycleSchema, raw)
}

// PrepareTaskActionBindingValidator compiles the binding document schema.
func PrepareTaskActionBindingValidator() error {
	taskActionBindingSchemaOnce.Do(func() {
		taskActionBindingSchema, errTaskActionBindingSchema = compileEmbeddedSchema(taskActionBindingSchemaURL, taskActionBindingSchemaBytes)
	})
	if errTaskActionBindingSchema != nil {
		return fmt.Errorf("compile Task Action binding schema: %w", errTaskActionBindingSchema)
	}
	return nil
}

// ValidateTaskActionBindingJSON validates the JSON shape of one Binding or
// DependencyWait. Use actionbinding strict decoders for semantic invariants.
func ValidateTaskActionBindingJSON(raw []byte) error {
	if err := PrepareTaskActionBindingValidator(); err != nil {
		return err
	}
	return validateEmbeddedJSON("Task Action binding", taskActionBindingSchema, raw)
}

func compileEmbeddedSchema(url string, raw []byte) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	if err := compiler.AddResource(url, document); err != nil {
		return nil, err
	}
	return compiler.Compile(url)
}

func validateEmbeddedJSON(name string, schema *jsonschema.Schema, raw []byte) error {
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode %s JSON: %w", name, err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("validate %s JSON: %w", name, err)
	}
	return nil
}
