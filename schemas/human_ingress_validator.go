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

const maxHumanIngressJSONBytes = 1 << 20

const humanIngressSchemaURL = "https://toppymicroservices.github.io/agents-secure-binding/schemas/asb-taskcoord-human-ingress-v1.schema.json"

//go:embed asb-taskcoord-human-ingress-v1.schema.json
var humanIngressSchema []byte

var (
	humanIngressOnce      sync.Once
	humanIngress          *jsonschema.Schema
	humanIngressChallenge *jsonschema.Schema
	humanIngressExecute   *jsonschema.Schema
	errHumanIngress       error
)

// PrepareHumanIngressValidator compiles the embedded schema so a service can
// fail during startup instead of on its first request.
func PrepareHumanIngressValidator() error {
	humanIngressOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(humanIngressSchema))
		if err != nil {
			errHumanIngress = err
			return
		}
		if err := compiler.AddResource(humanIngressSchemaURL, document); err != nil {
			errHumanIngress = err
			return
		}
		humanIngress, errHumanIngress = compiler.Compile(humanIngressSchemaURL)
		if errHumanIngress != nil {
			return
		}
		humanIngressChallenge, errHumanIngress = compiler.Compile(humanIngressSchemaURL + "#/$defs/challengeEnvelope")
		if errHumanIngress != nil {
			return
		}
		humanIngressExecute, errHumanIngress = compiler.Compile(humanIngressSchemaURL + "#/$defs/executeEnvelope")
	})
	if errHumanIngress != nil {
		return fmt.Errorf("compile Human ingress schema: %w", errHumanIngress)
	}
	return nil
}

// ValidateHumanIngressJSON validates one bounded challenge or execute
// envelope. Callers must separately verify TLS, signatures, registry state,
// current state, and replay.
func ValidateHumanIngressJSON(raw []byte) error {
	if err := PrepareHumanIngressValidator(); err != nil {
		return err
	}
	if err := strictjson.ValidateDocument(raw, maxHumanIngressJSONBytes); err != nil {
		return fmt.Errorf("decode Human ingress JSON: %w", err)
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

// ValidateHumanIngressChallengeJSON validates one bounded request for the
// challenge route. Execute envelopes are rejected even though the combined
// request schema accepts both route shapes.
func ValidateHumanIngressChallengeJSON(raw []byte) error {
	return validateHumanIngressRouteJSON(raw, "challenge")
}

// ValidateHumanIngressExecuteJSON validates one bounded request for the
// execute route. Challenge envelopes are rejected before challenge lookup.
func ValidateHumanIngressExecuteJSON(raw []byte) error {
	return validateHumanIngressRouteJSON(raw, "execute")
}

func validateHumanIngressRouteJSON(raw []byte, route string) error {
	if err := PrepareHumanIngressValidator(); err != nil {
		return err
	}
	schema := humanIngressChallenge
	if route == "execute" {
		schema = humanIngressExecute
	}
	if err := strictjson.ValidateDocument(raw, maxHumanIngressJSONBytes); err != nil {
		return fmt.Errorf("decode Human ingress %s JSON: %w", route, err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode Human ingress %s JSON: %w", route, err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("validate Human ingress %s JSON: %w", route, err)
	}
	return nil
}
