// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

var (
	ErrInvalidRequest      = errors.New("human relay: invalid request")
	ErrInvalidProjection   = errors.New("human relay: invalid verified projection")
	ErrUnavailable         = errors.New("human relay: relay grant unavailable")
	ErrMissingStore        = errors.New("human relay: missing store")
	ErrMissingDirectory    = errors.New("human relay: missing grant directory")
	ErrMissingDispatcher   = errors.New("human relay: missing session dispatcher")
	ErrNotFound            = errors.New("human relay: intent not found")
	ErrIntentConflict      = errors.New("human relay: intent identifier conflict")
	ErrGrantConsumed       = errors.New("human relay: reachability grant already consumed")
	ErrDispatchUnavailable = errors.New("human relay: dispatch unavailable")
	ErrDispatchConflict    = errors.New("human relay: dispatch acknowledgement conflict")
)

const (
	maxIDBytes        = 256
	maxReferenceBytes = 2048
)

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Validate checks the exact Agent-controlled relay request.
func (r RelayIntentRequest) Validate() error {
	for field, value := range map[string]string{
		"intent_id": r.IntentID, "grant_id": r.GrantID,
		"requester_participant_id": r.RequesterParticipantID,
		"purpose":                  r.Purpose, "capability": r.Capability,
	} {
		if err := validateID(field, value); err != nil {
			return invalidRequest(err.Error())
		}
	}
	if strings.ContainsAny(r.Purpose, "*?") || strings.ContainsAny(r.Capability, "*?") {
		return invalidRequest("purpose and capability must not contain wildcard characters")
	}
	if !validChannel(r.Channel) {
		return invalidRequest("unsupported relay channel")
	}
	if err := validateHTTPSReference("content_ref", r.ContentRef); err != nil {
		return invalidRequest(err.Error())
	}
	if err := validateDigest("content_digest", r.ContentDigest); err != nil {
		return invalidRequest(err.Error())
	}
	return nil
}

// Validate checks a verifier-created exact-request projection.
func (a AuthenticatedRelayIntent) Validate() error {
	if err := validateDigest("request_digest", a.RequestDigest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProjection, err)
	}
	for field, value := range map[string]string{
		"actor_id": a.ActorID, "authorization_id": a.AuthorizationID,
		"proof_id": a.ProofID, "verifier_nonce": a.VerifierNonce,
	} {
		if err := validateID(field, value); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidProjection, err)
		}
	}
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || !a.ExpiresAt.After(a.IssuedAt) {
		return fmt.Errorf("%w: invalid validity window", ErrInvalidProjection)
	}
	return nil
}

// Validate checks the broker-internal durable intent.
func (i Intent) Validate() error {
	if i.Schema != RelayIntentSchemaV1 {
		return invalidRequest("unsupported intent schema")
	}
	request := RelayIntentRequest{
		IntentID: i.IntentID, GrantID: i.GrantID, RequesterParticipantID: i.RequesterParticipantID,
		Purpose: i.Purpose, Capability: i.Capability, Channel: i.Channel,
		ContentRef: i.ContentRef, ContentDigest: i.ContentDigest,
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if err := validateHTTPSReference("relay_session_ref", i.RelaySessionRef); err != nil {
		return invalidRequest(err.Error())
	}
	for field, value := range map[string]string{
		"actor_id": i.ActorID, "authorization_id": i.AuthorizationID, "proof_id": i.ProofID,
	} {
		if err := validateID(field, value); err != nil {
			return invalidRequest(err.Error())
		}
	}
	if err := validateDigest("request_digest", i.RequestDigest); err != nil {
		return invalidRequest(err.Error())
	}
	if i.QueuedAt.IsZero() {
		return invalidRequest("queued_at is required")
	}
	return nil
}

// Validate checks an append-only relay event.
func (e Event) Validate() error {
	if e.Schema != RelayEventSchemaV1 {
		return invalidRequest("unsupported event schema")
	}
	if err := validateID("event_id", e.EventID); err != nil {
		return invalidRequest(err.Error())
	}
	if err := validateID("intent_id", e.IntentID); err != nil {
		return invalidRequest(err.Error())
	}
	if e.At.IsZero() {
		return invalidRequest("event timestamp is required")
	}
	switch e.Status {
	case StatusQueued, StatusDispatching, StatusCanceled:
		if e.ProviderAckRef != "" {
			return invalidRequest(string(e.Status) + " must not contain provider acknowledgement")
		}
	case StatusProviderAcknowledged:
		if err := validateID("provider_ack_ref", e.ProviderAckRef); err != nil {
			return invalidRequest(err.Error())
		}
	default:
		return invalidRequest("unsupported relay status")
	}
	expectedEventID, err := relayEventID(e.Status, e.IntentID)
	if err != nil {
		return err
	}
	if e.EventID != expectedEventID {
		return invalidRequest("event_id does not match status and intent_id")
	}
	return nil
}

// Validate checks an Agent-facing receipt.
func (r Receipt) Validate() error {
	if r.Schema != RelayReceiptSchemaV1 {
		return invalidRequest("unsupported receipt schema")
	}
	for field, value := range map[string]string{"intent_id": r.IntentID, "grant_id": r.GrantID} {
		if err := validateID(field, value); err != nil {
			return invalidRequest(err.Error())
		}
	}
	if r.Status != StatusQueued && r.Status != StatusDispatching &&
		r.Status != StatusProviderAcknowledged && r.Status != StatusCanceled {
		return invalidRequest("unsupported receipt status")
	}
	if err := validateDigest("content_digest", r.ContentDigest); err != nil {
		return invalidRequest(err.Error())
	}
	if r.QueuedAt.IsZero() || r.UpdatedAt.IsZero() || r.UpdatedAt.Before(r.QueuedAt) {
		return invalidRequest("invalid receipt timestamps")
	}
	return nil
}

func validateID(field, value string) error {
	if value == "" || !utf8.ValidString(value) || len(value) > maxIDBytes || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is not a bounded UTF-8 identifier", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func validateDigest(field, value string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return fmt.Errorf("%s must be 64 lowercase hexadecimal characters", field)
	}
	if _, err := hex.DecodeString(value); err != nil {
		return fmt.Errorf("%s must be hexadecimal", field)
	}
	return nil
}

func validateHTTPSReference(field, value string) error {
	if value == "" || !utf8.ValidString(value) || len(value) > maxReferenceBytes {
		return fmt.Errorf("%s is not a bounded reference", field)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an absolute HTTPS reference without userinfo, query, or fragment", field)
	}
	return nil
}

func validChannel(channel taskcoord.ReachabilityChannel) bool {
	return channel == taskcoord.ReachabilityEmail || channel == taskcoord.ReachabilitySNS || channel == taskcoord.ReachabilityTEL
}

func invalidRequest(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRequest, message)
}
