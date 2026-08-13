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

//go:embed asb-taskcoord-human-ingress-v1.schema.json
var humanIngressSchema []byte

var (
	humanIngressOnce sync.Once
	humanIngress     *jsonschema.Schema
	humanIngressErr  error
)

// PrepareHumanIngressValidator compiles the embedded schema so a service can
// fail during startup instead of on its first request.
func PrepareHumanIngressValidator() error {
	humanIngressOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		const schemaURL = "https://toppymicroservices.github.io/agents-secure-binding/schemas/asb-taskcoord-human-ingress-v1.schema.json"
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(humanIngressSchema))
		if err != nil {
			humanIngressErr = err
			return
		}
		if err := compiler.AddResource(schemaURL, document); err != nil {
			humanIngressErr = err
			return
		}
		humanIngress, humanIngressErr = compiler.Compile(schemaURL)
	})
	if humanIngressErr != nil {
		return fmt.Errorf("compile Human ingress schema: %w", humanIngressErr)
	}
	return nil
}

// ValidateHumanIngressJSON validates one challenge or execute envelope. It
// validates shape only; callers must separately reject duplicate members and
// verify TLS, signatures, registry state, current state, and replay.
func ValidateHumanIngressJSON(raw []byte) error {
	if err := PrepareHumanIngressValidator(); err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode Human ingress JSON: %w", err)
	}
	if err := humanIngress.Validate(instance); err != nil {
		return fmt.Errorf("validate Human ingress JSON: %w", err)
	}
	return nil
}
