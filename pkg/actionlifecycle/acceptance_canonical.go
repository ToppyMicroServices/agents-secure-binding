// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionlifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/canonicaltranscript"
)

// AcceptanceRequestSchemaV1 domain-separates initial acceptance from later
// Action mutation requests.
const AcceptanceRequestSchemaV1 = "asb.action-accept-request/v1"

// AcceptanceRequestTranscript returns the language-independent v1 transcript
// hashed by AcceptanceRequestDigest. Auth and accepted_at are excluded: Auth
// carries the resulting digest, while the trusted application and Store derive
// and check accepted_at.
func AcceptanceRequestTranscript(def Definition) ([]byte, error) {
	if err := validateID("event_id", def.EventID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("action_id", def.ActionID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateDigest("action_digest", def.ActionDigest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateID("owner_id", def.OwnerID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := def.RecoveryPolicy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if err := validateDigest("acceptance_context_digest", def.AcceptanceContextDigest); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}

	encoder := canonicaltranscript.New(AcceptanceRequestSchemaV1)
	encoder.String(string(EventAccept))
	encoder.String(def.EventID)
	encoder.String(def.ActionID)
	encoder.String(def.ActionDigest)
	encoder.String(def.OwnerID)
	encoder.String(string(def.RecoveryPolicy.Mode))
	encoder.Uint32(def.RecoveryPolicy.MaxAttempts)
	encoder.String(def.RecoveryPolicy.IdempotencyKey)
	encoder.String(def.AcceptanceContextDigest)

	transcript, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("action lifecycle: canonicalize acceptance request: %w", err)
	}
	return transcript, nil
}

// AcceptanceRequestDigest returns the digest that a verifier places in the
// ACCEPT AuthenticatedOperation. It binds every caller-selectable Definition
// field and an application-specific context digest. NewSnapshot recomputes it
// before creating any durable state.
func AcceptanceRequestDigest(def Definition) (string, error) {
	transcript, err := AcceptanceRequestTranscript(def)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
