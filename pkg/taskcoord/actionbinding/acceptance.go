// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package actionbinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/canonicaltranscript"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/actionlifecycle"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

// AcceptanceRequestSchemaV1 identifies the final Action acceptance request
// digest recomputed by actionlifecycle.NewSnapshot.
const AcceptanceRequestSchemaV1 = actionlifecycle.AcceptanceRequestSchemaV1

// AcceptanceContextSchemaV1 domain-separates the trusted TaskCoord projection
// nested inside the final Action acceptance request digest.
const AcceptanceContextSchemaV1 = "asb.task-action-accept-context/v1"

// AcceptanceAttemptSchemaV1 domain-separates one verifier proof attempt from
// the business request digest. An exact retry must match both identities.
const AcceptanceAttemptSchemaV1 = "asb.task-action-accept-attempt/v1"

// AcceptanceContextTranscript returns the language-independent v1 transcript
// for the trusted Assignment projection nested in Action acceptance.
func AcceptanceContextTranscript(assignment taskcoord.Assignment) ([]byte, error) {
	if err := assignment.Validate(); err != nil {
		return nil, fmt.Errorf("task action acceptance: invalid Assignment: %w", err)
	}
	if assignment.Status != taskcoord.AssignmentAccepted || assignment.AcceptedAt == nil {
		return nil, ErrAssignmentNotAccepted
	}

	encoder := canonicaltranscript.New(AcceptanceContextSchemaV1)
	encoder.String(assignment.AssignmentID)
	encoder.Uint64(assignment.Revision)
	encoder.String(assignment.TaskID)
	encoder.String(assignment.ParticipantID)
	encoder.String(string(assignment.Role))
	encoder.String(assignment.AuthorityDigest)
	encoder.String(string(assignment.Status))
	transcript, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("task action acceptance: canonicalize context: %w", err)
	}
	return transcript, nil
}

// AcceptanceContextDigest returns the trusted Assignment projection nested in
// the final Action acceptance digest.
func AcceptanceContextDigest(assignment taskcoord.Assignment) (string, error) {
	transcript, err := AcceptanceContextTranscript(assignment)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// AcceptanceRequestDigest returns the final digest that an ASB verifier places
// in AcceptRequest.Auth. NewSnapshot independently recomputes the same value
// from the Action definition and nested trusted Assignment context.
func AcceptanceRequestDigest(assignment taskcoord.Assignment, request AcceptRequest) (string, error) {
	definition, err := acceptanceDefinition(assignment, request, time.Time{})
	if err != nil {
		return "", err
	}
	return actionlifecycle.AcceptanceRequestDigest(definition)
}

// AcceptanceAttemptTranscript returns the language-independent identity input
// for the complete verifier projection. It deliberately includes the proof
// window and nonce.
func AcceptanceAttemptTranscript(auth *actionlifecycle.AuthenticatedOperation) ([]byte, error) {
	if auth == nil {
		return nil, actionlifecycle.ErrAuthenticationRequired
	}
	for name, value := range map[string]string{
		"auth.actor_id":         auth.ActorID,
		"auth.authorization_id": auth.AuthorizationID,
		"auth.proof_id":         auth.ProofID,
		"auth.action_id":        auth.ActionID,
		"auth.verifier_nonce":   auth.VerifierNonce,
	} {
		if err := validateID(name, value); err != nil {
			return nil, fmt.Errorf("%w: %v", actionlifecycle.ErrInvalidEvent, err)
		}
	}
	if auth.Operation != actionlifecycle.EventAccept {
		return nil, fmt.Errorf("%w: authenticated acceptance operation mismatch", actionlifecycle.ErrInvalidEvent)
	}
	for name, value := range map[string]string{
		"auth.action_digest":   auth.ActionDigest,
		"auth.mutation_digest": auth.MutationDigest,
	} {
		if err := validateDigest(value); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", actionlifecycle.ErrInvalidEvent, name, err)
		}
	}
	issuedAt := auth.IssuedAt.UTC()
	expiresAt := auth.ExpiresAt.UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(issuedAt) {
		return nil, fmt.Errorf("%w: authenticated acceptance window is invalid", actionlifecycle.ErrInvalidEvent)
	}

	encoder := canonicaltranscript.New(AcceptanceAttemptSchemaV1)
	encoder.String(auth.ActorID)
	encoder.String(auth.AuthorizationID)
	encoder.String(auth.ProofID)
	encoder.String(string(auth.Operation))
	encoder.String(auth.ActionID)
	encoder.String(auth.ActionDigest)
	encoder.String(auth.MutationDigest)
	encoder.String(auth.VerifierNonce)
	encoder.Time(issuedAt)
	encoder.Time(expiresAt)
	transcript, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("task action acceptance: canonicalize attempt: %w", err)
	}
	return transcript, nil
}

// AcceptanceAttemptFingerprint returns SHA-256 over
// AcceptanceAttemptTranscript. A different fresh proof for the same business
// request therefore requires explicit outcome reconciliation instead of
// rewriting first-commit provenance.
func AcceptanceAttemptFingerprint(auth *actionlifecycle.AuthenticatedOperation) (string, error) {
	transcript, err := AcceptanceAttemptTranscript(auth)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(transcript)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func acceptanceDefinition(
	assignment taskcoord.Assignment,
	request AcceptRequest,
	acceptedAt time.Time,
) (actionlifecycle.Definition, error) {
	if request.AssignmentID != assignment.AssignmentID {
		return actionlifecycle.Definition{}, fmt.Errorf("%w: acceptance Assignment does not match request", ErrInvalidBinding)
	}
	contextDigest, err := AcceptanceContextDigest(assignment)
	if err != nil {
		return actionlifecycle.Definition{}, err
	}
	return actionlifecycle.Definition{
		EventID: request.EventID, ActionID: request.ActionID, ActionDigest: request.ActionDigest,
		OwnerID: assignment.ParticipantID, RecoveryPolicy: request.RecoveryPolicy,
		AcceptanceContextDigest: contextDigest, AcceptedAt: acceptedAt, Auth: request.Auth,
	}, nil
}

func validateAcceptanceRequestShape(request AcceptRequest) error {
	if request.Auth == nil {
		return actionlifecycle.ErrAuthenticationRequired
	}
	for name, value := range map[string]string{
		"assignment_id": request.AssignmentID,
		"event_id":      request.EventID,
		"action_id":     request.ActionID,
	} {
		if err := validateID(name, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
		}
	}
	if err := validateDigest(request.ActionDigest); err != nil {
		return fmt.Errorf("%w: action_digest: %v", ErrInvalidBinding, err)
	}
	if err := request.RecoveryPolicy.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBinding, err)
	}
	if request.Auth.Operation != actionlifecycle.EventAccept || request.Auth.ActionID != request.ActionID ||
		request.Auth.ActionDigest != request.ActionDigest {
		return fmt.Errorf("%w: authenticated acceptance binding mismatch", actionlifecycle.ErrInvalidEvent)
	}
	_, err := AcceptanceAttemptFingerprint(request.Auth)
	return err
}

func validateAcceptanceRequestBinding(assignment taskcoord.Assignment, request AcceptRequest) error {
	if err := validateAcceptanceRequestShape(request); err != nil {
		return err
	}
	digest, err := AcceptanceRequestDigest(assignment, request)
	if err != nil {
		return err
	}
	auth := request.Auth
	if auth.Operation != actionlifecycle.EventAccept || auth.ActionID != request.ActionID ||
		auth.ActionDigest != request.ActionDigest || auth.MutationDigest != digest {
		return fmt.Errorf("%w: authenticated acceptance binding mismatch", actionlifecycle.ErrInvalidEvent)
	}
	return nil
}

func validateAcceptanceRequestAt(assignment taskcoord.Assignment, request AcceptRequest, at time.Time) error {
	if err := validateAcceptanceRequestBinding(assignment, request); err != nil {
		return err
	}
	auth := request.Auth
	issuedAt := auth.IssuedAt.UTC()
	expiresAt := auth.ExpiresAt.UTC()
	at = at.UTC()
	if issuedAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(issuedAt) ||
		at.Before(issuedAt) || !at.Before(expiresAt) {
		return fmt.Errorf("%w: authenticated acceptance is not current", actionlifecycle.ErrInvalidEvent)
	}
	return nil
}
