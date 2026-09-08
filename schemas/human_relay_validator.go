// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	humanRelaySchemaURL    = "https://github.com/ToppyMicroServices/agents-secure-binding/schemas/asb-human-relay-v1.schema.json"
	maxHumanRelayJSONBytes = 1 << 20
)

//go:embed asb-human-relay-v1.schema.json
var humanRelaySchemaBytes []byte

var (
	humanRelaySchemaOnce sync.Once
	humanRelaySchema     *jsonschema.Schema
	errHumanRelaySchema  error
)

// PrepareHumanRelayValidator compiles the embedded relay document schema.
func PrepareHumanRelayValidator() error {
	humanRelaySchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(humanRelaySchemaBytes))
		if err != nil {
			errHumanRelaySchema = err
			return
		}
		if err := compiler.AddResource(humanRelaySchemaURL, document); err != nil {
			errHumanRelaySchema = err
			return
		}
		humanRelaySchema, errHumanRelaySchema = compiler.Compile(humanRelaySchemaURL)
	})
	if errHumanRelaySchema != nil {
		return fmt.Errorf("compile Human relay schema: %w", errHumanRelaySchema)
	}
	return nil
}

// ValidateHumanRelayJSON validates one durable Intent, Event, or Receipt.
// Call the humanrelay semantic validators for cross-field time invariants.
func ValidateHumanRelayJSON(raw []byte) error {
	if err := PrepareHumanRelayValidator(); err != nil {
		return err
	}
	if err := strictjson.ValidateDocument(raw, maxHumanRelayJSONBytes); err != nil {
		return fmt.Errorf("decode Human relay JSON: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode Human relay JSON: %w", err)
	}
	if err := humanRelaySchema.Validate(instance); err != nil {
		return fmt.Errorf("validate Human relay JSON: %w", err)
	}
	return nil
}
