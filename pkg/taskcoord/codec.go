// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package taskcoord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// DecodeParticipant strictly decodes one bounded Task Participant record.
func DecodeParticipant(r io.Reader) (Participant, error) {
	var participant Participant
	if err := decodeStrict(r, &participant); err != nil {
		return Participant{}, fmt.Errorf("%w: %v", ErrInvalidParticipant, err)
	}
	if err := participant.Validate(); err != nil {
		return Participant{}, err
	}
	return participant, nil
}

// DecodeAssignment strictly decodes one bounded Assignment snapshot.
func DecodeAssignment(r io.Reader) (Assignment, error) {
	var assignment Assignment
	if err := decodeStrict(r, &assignment); err != nil {
		return Assignment{}, fmt.Errorf("%w: %v", ErrInvalidAssignment, err)
	}
	if err := assignment.Validate(); err != nil {
		return Assignment{}, err
	}
	return assignment, nil
}

// DecodeInteractionEvent strictly decodes one bounded immutable interaction
// event.
func DecodeInteractionEvent(r io.Reader) (InteractionEvent, error) {
	var event InteractionEvent
	if err := decodeStrict(r, &event); err != nil {
		return InteractionEvent{}, fmt.Errorf("%w: %v", ErrInvalidInteraction, err)
	}
	if err := event.Validate(); err != nil {
		return InteractionEvent{}, err
	}
	return event, nil
}

// DecodeAgentDiscoveryRecord strictly decodes one Agent-only discovery record.
func DecodeAgentDiscoveryRecord(r io.Reader) (AgentDiscoveryRecord, error) {
	var record AgentDiscoveryRecord
	if err := decodeStrict(r, &record); err != nil {
		return AgentDiscoveryRecord{}, fmt.Errorf("%w: %v", ErrInvalidDiscovery, err)
	}
	if err := record.Validate(); err != nil {
		return AgentDiscoveryRecord{}, err
	}
	return record, nil
}

// DecodeHumanMatchConsent strictly decodes one internal Human opt-in record.
func DecodeHumanMatchConsent(r io.Reader) (HumanMatchConsent, error) {
	var consent HumanMatchConsent
	if err := decodeStrict(r, &consent); err != nil {
		return HumanMatchConsent{}, fmt.Errorf("%w: %v", ErrInvalidReachability, err)
	}
	if err := consent.Validate(); err != nil {
		return HumanMatchConsent{}, err
	}
	return consent, nil
}

// DecodeHumanMatchConsentRevocation strictly decodes one consent withdrawal.
func DecodeHumanMatchConsentRevocation(r io.Reader) (HumanMatchConsentRevocation, error) {
	var revocation HumanMatchConsentRevocation
	if err := decodeStrict(r, &revocation); err != nil {
		return HumanMatchConsentRevocation{}, fmt.Errorf("%w: %v", ErrInvalidReachability, err)
	}
	if err := revocation.Validate(); err != nil {
		return HumanMatchConsentRevocation{}, err
	}
	return revocation, nil
}

// DecodeHumanReachabilityGrant strictly decodes one requester-facing relay
// grant.
func DecodeHumanReachabilityGrant(r io.Reader) (HumanReachabilityGrant, error) {
	var grant HumanReachabilityGrant
	if err := decodeStrict(r, &grant); err != nil {
		return HumanReachabilityGrant{}, fmt.Errorf("%w: %v", ErrInvalidReachability, err)
	}
	if err := grant.Validate(); err != nil {
		return HumanReachabilityGrant{}, err
	}
	return grant, nil
}

// DecodeHumanReachabilityRevocation strictly decodes one grant revocation.
func DecodeHumanReachabilityRevocation(r io.Reader) (HumanReachabilityRevocation, error) {
	var revocation HumanReachabilityRevocation
	if err := decodeStrict(r, &revocation); err != nil {
		return HumanReachabilityRevocation{}, fmt.Errorf("%w: %v", ErrInvalidReachability, err)
	}
	if err := revocation.Validate(); err != nil {
		return HumanReachabilityRevocation{}, err
	}
	return revocation, nil
}

func decodeStrict(r io.Reader, target any) error {
	if r == nil {
		return fmt.Errorf("missing JSON input")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return fmt.Errorf("read JSON: %v", err)
	}
	if len(raw) > MaxDocumentBytes {
		return fmt.Errorf("JSON exceeds %d bytes", MaxDocumentBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode JSON: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}
