// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package policydecision names application authorization outcomes. A policy
// outcome is separate from identity proof verification and execution status.
package policydecision

type Outcome string

const (
	Permit        Outcome = "Permit"
	Deny          Outcome = "Deny"
	Indeterminate Outcome = "Indeterminate"
	NotApplicable Outcome = "NotApplicable"
)
