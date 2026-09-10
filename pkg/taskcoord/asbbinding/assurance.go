// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"

// HumanAssuranceLevel is kept as an alias for source compatibility. The
// canonical durable audit vocabulary lives in package taskcoord.
type HumanAssuranceLevel = taskcoord.HumanAssuranceLevel

const (
	// HumanAssuranceGatewayAssertedForHuman means an authenticated gateway
	// Actor exercised an operation-authority grant for an exact request that
	// the verifier attributed to a Human Participant. It does not prove that
	// the Human was present or personally approved the request.
	HumanAssuranceGatewayAssertedForHuman = taskcoord.HumanAssuranceGatewayAssertedForHuman

	// HumanAssuranceAuthenticatedHumanEvidence means a trusted Human
	// authentication authority produced separate evidence bound to the
	// operation. This repository does not implement that evidence profile.
	HumanAssuranceAuthenticatedHumanEvidence = taskcoord.HumanAssuranceAuthenticatedHumanEvidence

	// HumanAssuranceHumanHeldKeyExactRequest means an enrolled Human-held key
	// signs the domain-separated exact request and its verifier context. This
	// repository does not implement that evidence profile.
	HumanAssuranceHumanHeldKeyExactRequest = taskcoord.HumanAssuranceHumanHeldKeyExactRequest

	// CurrentHumanAssuranceLevel is the only Human assurance level implemented
	// by asb.taskcoord-human-request/v1.
	CurrentHumanAssuranceLevel = HumanAssuranceGatewayAssertedForHuman
)
