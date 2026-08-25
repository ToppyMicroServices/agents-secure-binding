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

const a2aSecurityTestReportSchemaURL = "urn:asb:a2a-security-test-report:v1"

//go:embed a2a-security-test-report-v1.schema.json
var a2aSecurityTestReportSchemaBytes []byte

var (
	a2aSecurityTestReportSchemaOnce sync.Once
	a2aSecurityTestReportSchema     *jsonschema.Schema
	errA2ASecurityTestReportSchema  error
)

// PrepareA2ASecurityTestReportValidator compiles the embedded report schema so
// a service can fail during startup instead of on its first report.
func PrepareA2ASecurityTestReportValidator() error {
	a2aSecurityTestReportSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		compiler.AssertFormat()
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(a2aSecurityTestReportSchemaBytes))
		if err != nil {
			errA2ASecurityTestReportSchema = err
			return
		}
		if err := compiler.AddResource(a2aSecurityTestReportSchemaURL, document); err != nil {
			errA2ASecurityTestReportSchema = err
			return
		}
		a2aSecurityTestReportSchema, errA2ASecurityTestReportSchema = compiler.Compile(a2aSecurityTestReportSchemaURL)
	})
	if errA2ASecurityTestReportSchema != nil {
		return fmt.Errorf("compile A2A Security Test Report schema: %w", errA2ASecurityTestReportSchema)
	}
	return nil
}

// ValidateA2ASecurityTestReportJSON validates the JSON shape of one report.
// Call a2asecuritytest.DecodeReport for bounded decoding and semantic checks.
func ValidateA2ASecurityTestReportJSON(raw []byte) error {
	if err := PrepareA2ASecurityTestReportValidator(); err != nil {
		return err
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return fmt.Errorf("validate A2A Security Test Report JSON: %w", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("decode A2A Security Test Report JSON: %w", err)
	}
	if err := a2aSecurityTestReportSchema.Validate(instance); err != nil {
		return fmt.Errorf("validate A2A Security Test Report JSON: %w", err)
	}
	return nil
}
