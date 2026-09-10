// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import "fmt"

const (
	// HumanRequestProfileV1 identifies the only Human request verification
	// profile that currently emits durable assurance provenance.
	HumanRequestProfileV1 = "asb.taskcoord-human-request/v1"
)

// HumanAssuranceLevel identifies what verified evidence links an accepted
// operation to a Human Participant. It is audit vocabulary, not a
// caller-controlled claim.
type HumanAssuranceLevel string

const (
	// HumanAssuranceGatewayAssertedForHuman means an authenticated gateway
	// Actor exercised an operation-authority grant for an exact request that
	// the verifier attributed to a Human Participant. It does not prove that
	// the Human was present or personally approved the request.
	HumanAssuranceGatewayAssertedForHuman HumanAssuranceLevel = "gateway-asserted-for-human"

	// HumanAssuranceAuthenticatedHumanEvidence means a trusted Human
	// authentication authority produced separate evidence bound to the
	// operation. This repository does not implement that evidence profile.
	HumanAssuranceAuthenticatedHumanEvidence HumanAssuranceLevel = "authenticated-human-evidence"

	// HumanAssuranceHumanHeldKeyExactRequest means an enrolled Human-held key
	// signs the domain-separated exact request and its verifier context. This
	// repository does not implement that evidence profile.
	HumanAssuranceHumanHeldKeyExactRequest HumanAssuranceLevel = "human-held-key-exact-request"
)

// AssuranceProvenance records the profile and assurance level selected by a
// trusted verifier. A non-nil value is copied into the durable audit event.
// Absence means unspecified trusted-internal or legacy provenance; it must not
// be inferred from ActorID, ParticipantID, or ProofID.
type AssuranceProvenance struct {
	ProfileID      string              `json:"profile_id"`
	AssuranceLevel HumanAssuranceLevel `json:"assurance_level"`
}

// Validate accepts only profile/assurance pairs implemented by this version.
// New evidence profiles require an explicit code and schema update.
func (p AssuranceProvenance) Validate() error {
	if p.ProfileID != HumanRequestProfileV1 ||
		p.AssuranceLevel != HumanAssuranceGatewayAssertedForHuman {
		return fmt.Errorf("unsupported assurance profile or level")
	}
	return nil
}

// GatewayAssertedForHumanProvenance returns a detached provenance value for
// the implemented Human request profile.
func GatewayAssertedForHumanProvenance() *AssuranceProvenance {
	return &AssuranceProvenance{
		ProfileID:      HumanRequestProfileV1,
		AssuranceLevel: HumanAssuranceGatewayAssertedForHuman,
	}
}

func cloneAssuranceProvenance(value *AssuranceProvenance) *AssuranceProvenance {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func sameAssuranceProvenance(left, right *AssuranceProvenance) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
