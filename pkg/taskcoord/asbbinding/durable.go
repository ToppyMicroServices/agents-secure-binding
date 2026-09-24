// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/schemas"
)

var (
	ErrHumanOutcomeNotFound = errors.New("asbbinding: Human operation outcome not found")
	ErrHumanOutcomeConflict = errors.New("asbbinding: Human operation identity already committed")
)

// HumanOutcome retains the first successful response and its original scope.
// OperationID is the request EventID, unique across operation kinds in a store.
// RequestDigest identifies the business request, independently of its proof.
// Response is the original JSON response, including original proof provenance.
// These records are trusted local state, never peer-supplied projections.
type HumanOutcome struct {
	OperationID   string          `json:"operation_id"`
	RequestDigest string          `json:"request_digest"`
	ParticipantID string          `json:"participant_id"`
	ActorID       string          `json:"actor_id"`
	Response      json.RawMessage `json:"response"`
}

func (o HumanOutcome) Validate() error {
	for name, value := range map[string]string{
		"operation_id": o.OperationID, "participant_id": o.ParticipantID, "actor_id": o.ActorID,
	} {
		if err := validateID(name, value); err != nil {
			return err
		}
	}
	if _, err := decodeDigest("request_digest", o.RequestDigest, false); err != nil {
		return err
	}
	if err := schemas.ValidateHumanIngressResponseJSON(o.Response); err != nil {
		return err
	}
	var response ExecuteResponse
	if err := json.Unmarshal(o.Response, &response); err != nil {
		return err
	}
	var eventID, participantID, actorID string
	switch response.Operation {
	case OperationAssignmentOffer, OperationAssignmentTransition:
		if response.Record == nil {
			return ErrInvalidRequest
		}
		eventID, participantID, actorID = response.Record.EventID, response.Record.ParticipantID, response.Record.ActorID
	case OperationAssignmentDelegation:
		if response.ParentRecord == nil {
			return ErrInvalidRequest
		}
		eventID, participantID, actorID = response.ParentRecord.EventID, response.ParentRecord.ParticipantID, response.ParentRecord.ActorID
	case OperationInteractionAppend:
		if response.Interaction == nil {
			return ErrInvalidRequest
		}
		eventID, participantID, actorID = response.Interaction.EventID, response.Interaction.ParticipantID, response.Interaction.ActorID
	default:
		return ErrInvalidRequest
	}
	// The offer's requester can differ from the Assignment owner. Scope is
	// bound to the original authenticated record, not the resulting assignee.
	if eventID != o.OperationID || participantID != o.ParticipantID || actorID != o.ActorID {
		return ErrInvalidRequest
	}
	return nil
}

// HumanTransaction is valid only during RunHumanTransaction. Every method uses
// the same authoritative transaction, including participant reads, mutation,
// outbox insertion, replay consumption, and the immutable first response.
type HumanTransaction interface {
	taskcoord.Store
	identitypolicy.ReplayCache
	LookupHumanOutcome(context.Context, string) (HumanOutcome, error)
	PutHumanOutcome(context.Context, HumanOutcome) error
}

// HumanTransactionStore adds durable acceptance to Ingress. The callback runs
// once, after obtaining the store's serialization boundary. Returning an error
// rolls back all its writes. Success commits them together before returning.
// Implementations must not retry a callback or retain its transaction handle.
// Outcomes must survive restart and must never be overwritten or expire merely
// because the original authorization expired. Storage/commit failures may be
// ambiguous; callers recover using a fresh, separately authorized read.
type HumanTransactionStore interface {
	RunHumanTransaction(context.Context, func(HumanTransaction) error) error
}

// RecoveryRequest authorizes retrieval of one prior outcome, not another
// attempt at executing the business request. The current Human and gateway
// Actor must match the retained scope. A fresh exact recovery grant is required
// even when the original execution grant has expired.
type RecoveryRequest struct {
	ParticipantID string `json:"participant_id"`
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
}

func RecoveryDigest(request RecoveryRequest) (Digest, error) {
	if err := validateID("participant_id", request.ParticipantID); err != nil {
		return Digest{}, err
	}
	if err := validateID("operation_id", request.OperationID); err != nil {
		return Digest{}, err
	}
	if _, err := decodeDigest("request_digest", request.RequestDigest, false); err != nil {
		return Digest{}, err
	}
	encoder := newTranscript(RequestKindOperationRecover)
	encoder.addString("participant_id", request.ParticipantID)
	encoder.addString("operation_id", request.OperationID)
	encoder.addDigest("request_digest", request.RequestDigest)
	return encoder.digest()
}
