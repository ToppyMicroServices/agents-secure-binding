// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package humanrelay implements a privacy-minimized Agent-to-Human relay.
// It consumes an already-active TaskCoord HumanReachabilityGrant and never
// resolves or exposes a Human identifier or direct contact endpoint.
package humanrelay

import (
	"crypto/sha256"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

const (
	RelayIntentSchemaV1  = "asb.human-relay-intent/v1"
	RelayEventSchemaV1   = "asb.human-relay-event/v1"
	RelayReceiptSchemaV1 = "asb.human-relay-receipt/v1"
	MaxDocumentBytes     = 1 << 20
)

// Status describes relay transport progress only. It deliberately has no
// Human decision, read, Assignment, or Action state.
type Status string

const (
	StatusQueued               Status = "QUEUED"
	StatusDispatching          Status = "DISPATCHING"
	StatusProviderAcknowledged Status = "PROVIDER_ACKNOWLEDGED"
	StatusCanceled             Status = "CANCELED"
)

// RelayIntentRequest is the complete Agent-controlled relay request. The
// active grant supplies the opaque relay session; callers cannot select it.
type RelayIntentRequest struct {
	IntentID               string                        `json:"intent_id"`
	GrantID                string                        `json:"grant_id"`
	RequesterParticipantID string                        `json:"requester_participant_id"`
	Purpose                string                        `json:"purpose"`
	Capability             string                        `json:"capability"`
	Channel                taskcoord.ReachabilityChannel `json:"channel"`
	ContentRef             string                        `json:"content_ref"`
	ContentDigest          string                        `json:"content_digest"`
}

// Digest is the canonical SHA-256 digest of one RelayIntentRequest.
type Digest [sha256.Size]byte

// String returns lowercase hexadecimal without a prefix.
func (d Digest) String() string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(d)*2)
	for index, value := range d {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&0x0f]
	}
	return string(encoded)
}

// AuthenticatedRelayIntent is a verifier-created projection for one exact
// request. Raw network claims must not be converted into this value directly.
type AuthenticatedRelayIntent struct {
	RequestDigest   string    `json:"request_digest"`
	ActorID         string    `json:"actor_id"`
	AuthorizationID string    `json:"authorization_id"`
	ProofID         string    `json:"proof_id"`
	VerifierNonce   string    `json:"verifier_nonce"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// QueueCommit is the complete input to the atomic relay authorization and
// persistence boundary. The Store derives the opaque relay session from the
// authoritative reachability grant; callers cannot provide it.
type QueueCommit struct {
	Request       RelayIntentRequest
	Authorization AuthenticatedRelayIntent
	QueuedAt      time.Time
}

// Intent is the durable, privacy-minimized relay authorization record. Its
// RelaySessionRef is broker-issued and opaque; it is never returned in Receipt.
type Intent struct {
	Schema                 string                        `json:"schema"`
	IntentID               string                        `json:"intent_id"`
	GrantID                string                        `json:"grant_id"`
	RequesterParticipantID string                        `json:"requester_participant_id"`
	Purpose                string                        `json:"purpose"`
	Capability             string                        `json:"capability"`
	Channel                taskcoord.ReachabilityChannel `json:"channel"`
	ContentRef             string                        `json:"content_ref"`
	ContentDigest          string                        `json:"content_digest"`
	RelaySessionRef        string                        `json:"relay_session_ref"`
	ActorID                string                        `json:"actor_id"`
	AuthorizationID        string                        `json:"authorization_id"`
	ProofID                string                        `json:"proof_id"`
	RequestDigest          string                        `json:"request_digest"`
	QueuedAt               time.Time                     `json:"queued_at"`
}

// Event records relay transport progress. DISPATCHING means that the broker
// durably reserved the one allowed provider attempt; the outcome may still be
// unknown. CANCELED is used only when reachability became unavailable while
// the intent was still QUEUED, before any provider attempt. Provider
// acknowledgement says only that the configured Human gateway accepted the
// delivery request.
type Event struct {
	Schema         string    `json:"schema"`
	EventID        string    `json:"event_id"`
	IntentID       string    `json:"intent_id"`
	Status         Status    `json:"status"`
	At             time.Time `json:"at"`
	ProviderAckRef string    `json:"provider_ack_ref,omitempty"`
}

// Receipt is the complete Agent-facing response. It intentionally omits the
// Human, candidate, consent, relay session, and provider details.
type Receipt struct {
	Schema        string    `json:"schema"`
	IntentID      string    `json:"intent_id"`
	GrantID       string    `json:"grant_id"`
	Status        Status    `json:"status"`
	ContentDigest string    `json:"content_digest"`
	QueuedAt      time.Time `json:"queued_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// DispatchRequest is passed to a deployment-controlled Human gateway. The
// gateway owns any relay-session-to-contact mapping.
type DispatchRequest struct {
	IntentID        string
	RelaySessionRef string
	Channel         taskcoord.ReachabilityChannel
	ContentRef      string
	ContentDigest   string
}

// ProviderAck is a transport acknowledgement, never a Human decision. At is
// retained for source compatibility and provider telemetry only. Worker uses
// its broker-controlled clock for durable Event and Receipt timestamps.
type ProviderAck struct {
	IntentID string
	AckRef   string
	At       time.Time
}
