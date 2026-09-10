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

const humanIngressResponseSchemaURL = "https://toppymicroservices.github.io/agents-secure-binding/schemas/asb-taskcoord-human-ingress-response-v1.schema.json"

//go:embed asb-taskcoord-human-ingress-response-v1.schema.json
var humanIngressResponseSchemaBytes []byte

var (
	humanIngressResponseOnce   sync.Once
	humanIngressResponseSchema *jsonschema.Schema
	errHumanIngressResponse    error
)

// PrepareHumanIngressResponseValidator compiles the self-contained embedded
// response schema.
func PrepareHumanIngressResponseValidator() error {
	humanIngressResponseOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()

		responseDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(humanIngressResponseSchemaBytes))
		if err != nil {
			errHumanIngressResponse = err
			return
		}
		if err := compiler.AddResource(humanIngressResponseSchemaURL, responseDocument); err != nil {
			errHumanIngressResponse = err
			return
		}
		humanIngressResponseSchema, errHumanIngressResponse = compiler.Compile(humanIngressResponseSchemaURL)
	})
	if errHumanIngressResponse != nil {
		return fmt.Errorf("compile Human ingress response schema: %w", errHumanIngressResponse)
	}
	return nil
}

// ValidateHumanIngressResponseJSON validates one bounded challenge success,
// execute success, or public error body. HTTP status and headers are checked
// separately by the serving endpoint.
func ValidateHumanIngressResponseJSON(raw []byte) error {
	if err := PrepareHumanIngressResponseValidator(); err != nil {
		return err
	}
	if err := strictjson.ValidateDocument(raw, maxHumanIngressJSONBytes); err != nil {
		return fmt.Errorf("decode Human ingress response JSON: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode Human ingress response JSON: %w", err)
	}
	if err := humanIngressResponseSchema.Validate(instance); err != nil {
		return fmt.Errorf("validate Human ingress response JSON: %w", err)
	}
	return nil
}
