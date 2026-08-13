// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"fmt"
	"time"
)

// NewInteractionEvent binds an immutable event definition to a freshly
// verified authorization. It does not mutate an Assignment.
func NewInteractionEvent(def InteractionEventDefinition, auth AuthenticatedInteraction) (InteractionEvent, error) {
	event := InteractionEvent{
		Schema:          InteractionEventSchemaV1,
		EventID:         def.EventID,
		InteractionID:   def.InteractionID,
		TaskID:          def.TaskID,
		AssignmentID:    def.AssignmentID,
		Kind:            def.Kind,
		InReplyTo:       def.InReplyTo,
		Supersedes:      def.Supersedes,
		Finality:        def.Finality,
		ContentRef:      def.ContentRef,
		ContentDigest:   def.ContentDigest,
		At:              def.At,
		ActorID:         auth.ActorID,
		ParticipantID:   auth.ParticipantID,
		AuthorizationID: auth.AuthorizationID,
		ProofID:         auth.ProofID,
		EvidenceRef:     def.EvidenceRef,
	}
	if err := validateInteractionAuthorization(def, auth, def.At); err != nil {
		return InteractionEvent{}, err
	}
	if err := event.Validate(); err != nil {
		return InteractionEvent{}, err
	}
	return event, nil
}

func validateInteractionAuthorization(def InteractionEventDefinition, auth AuthenticatedInteraction, at time.Time) error {
	for field, value := range map[string]string{
		"actor_id":         auth.ActorID,
		"participant_id":   auth.ParticipantID,
		"authorization_id": auth.AuthorizationID,
		"proof_id":         auth.ProofID,
		"event_id":         auth.EventID,
		"interaction_id":   auth.InteractionID,
		"task_id":          auth.TaskID,
		"assignment_id":    auth.AssignmentID,
		"verifier_nonce":   auth.VerifierNonce,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrAuthenticationRequired, err)
		}
	}
	if auth.EventID != def.EventID ||
		auth.InteractionID != def.InteractionID ||
		auth.TaskID != def.TaskID ||
		auth.AssignmentID != def.AssignmentID ||
		auth.Kind != def.Kind ||
		auth.InReplyTo != def.InReplyTo ||
		auth.Supersedes != def.Supersedes ||
		auth.Finality != def.Finality ||
		auth.ContentRef != def.ContentRef ||
		auth.ContentDigest != def.ContentDigest ||
		auth.EvidenceRef != def.EvidenceRef ||
		!auth.At.Equal(def.At) {
		return fmt.Errorf("%w: interaction event binding mismatch", ErrAuthenticationRequired)
	}
	if auth.IssuedAt.IsZero() || auth.ExpiresAt.IsZero() || !auth.ExpiresAt.After(auth.IssuedAt) {
		return fmt.Errorf("%w: invalid authorization validity window", ErrAuthenticationRequired)
	}
	if at.Before(auth.IssuedAt) || !at.Before(auth.ExpiresAt) {
		return fmt.Errorf("%w: interaction is outside authorization validity window", ErrAuthenticationRequired)
	}
	return nil
}
