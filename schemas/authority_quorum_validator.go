// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed authority-quorum-binding-v1.schema.json
var authorityQuorumSchemaBytes []byte

var (
	authorityQuorumOnce sync.Once
	authorityQuorum     *jsonschema.Schema
	errAuthorityQuorum  error
)

func PrepareAuthorityQuorumValidator() error {
	authorityQuorumOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		const schemaURL = "https://toppymicroservices.github.io/agents-secure-binding/schemas/authority-quorum-binding-v1.schema.json"
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(authorityQuorumSchemaBytes))
		if err != nil {
			errAuthorityQuorum = err
			return
		}
		if err := compiler.AddResource(schemaURL, document); err != nil {
			errAuthorityQuorum = err
			return
		}
		authorityQuorum, errAuthorityQuorum = compiler.Compile(schemaURL)
	})
	if errAuthorityQuorum != nil {
		return fmt.Errorf("compile authority quorum schema: %w", errAuthorityQuorum)
	}
	return nil
}

// ValidateAuthorityQuorumJSON validates document shape only. Callers must also
// run the package decoder or Validate method for ordering, digest, threshold,
// membership, freshness, revocation, and atomic-consume checks.
func ValidateAuthorityQuorumJSON(raw []byte) error {
	if err := PrepareAuthorityQuorumValidator(); err != nil {
		return err
	}
	if err := rejectAuthorityQuorumDuplicateMembers(raw); err != nil {
		return err
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode authority quorum JSON: %w", err)
	}
	if err := authorityQuorum.Validate(instance); err != nil {
		return fmt.Errorf("validate authority quorum JSON: %w", err)
	}
	return nil
}

func rejectAuthorityQuorumDuplicateMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanAuthorityQuorumJSONValue(decoder); err != nil {
		return fmt.Errorf("validate authority quorum JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("validate authority quorum JSON: trailing JSON value")
		}
		return fmt.Errorf("validate authority quorum JSON: %w", err)
	}
	return nil
}

func scanAuthorityQuorumJSONValue(decoder *json.Decoder) error {
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
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate object member %q", name)
			}
			seen[name] = struct{}{}
			if err := scanAuthorityQuorumJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanAuthorityQuorumJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}
