// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package schemas

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord"
)

func TestHumanRelaySchemaAcceptsBoundedDocuments(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	documents := []any{
		humanrelay.Intent{
			Schema: humanrelay.RelayIntentSchemaV1, IntentID: "intent:1", GrantID: "grant:1",
			RequesterParticipantID: "agent:1", Purpose: "consultation", Capability: "translation",
			Channel: taskcoord.ReachabilityEmail, ContentRef: "https://content.example/objects/1",
			ContentDigest: strings.Repeat("a", 64), RelaySessionRef: "https://relay.example/sessions/1",
			ActorID: "gateway:agent", AuthorizationID: "authorization:1", ProofID: "proof:1",
			RequestDigest: strings.Repeat("b", 64), QueuedAt: at,
		},
		humanrelay.Event{
			Schema: humanrelay.RelayEventSchemaV1, EventID: "relay-event:v1:b7164850fb4f4a3702a68b8306603832b45baee1038e594f6f869777a1005291", IntentID: "intent:1",
			Status: humanrelay.StatusQueued, At: at,
		},
		humanrelay.Event{
			Schema: humanrelay.RelayEventSchemaV1, EventID: "relay-event:v1:eb6e01f2539a7eaba300901095fa3aea0c7931448d77a1084b5bb2f829020d8b", IntentID: "intent:1",
			Status: humanrelay.StatusDispatching, At: at,
		},
		humanrelay.Event{
			Schema: humanrelay.RelayEventSchemaV1, EventID: "relay-event:v1:08e9f5c1550a63a6bb677018dad225dd1011693765ecd779a657aba7d9c6940d", IntentID: "intent:1",
			Status: humanrelay.StatusProviderAcknowledged, At: at, ProviderAckRef: "provider-ack:1",
		},
		humanrelay.Event{
			Schema: humanrelay.RelayEventSchemaV1, EventID: "relay-event:v1:0c37ef75e7f4d19114cbf417da9bf9232e61e2932b714ebd27da9ebc371f2645", IntentID: "intent:1",
			Status: humanrelay.StatusCanceled, At: at,
		},
		humanrelay.Receipt{
			Schema: humanrelay.RelayReceiptSchemaV1, IntentID: "intent:1", GrantID: "grant:1",
			Status: humanrelay.StatusQueued, ContentDigest: strings.Repeat("a", 64), QueuedAt: at, UpdatedAt: at,
		},
		humanrelay.Receipt{
			Schema: humanrelay.RelayReceiptSchemaV1, IntentID: "intent:2", GrantID: "grant:2",
			Status: humanrelay.StatusDispatching, ContentDigest: strings.Repeat("b", 64), QueuedAt: at, UpdatedAt: at,
		},
		humanrelay.Receipt{
			Schema: humanrelay.RelayReceiptSchemaV1, IntentID: "intent:3", GrantID: "grant:3",
			Status: humanrelay.StatusProviderAcknowledged, ContentDigest: strings.Repeat("c", 64), QueuedAt: at, UpdatedAt: at,
		},
		humanrelay.Receipt{
			Schema: humanrelay.RelayReceiptSchemaV1, IntentID: "intent:4", GrantID: "grant:4",
			Status: humanrelay.StatusCanceled, ContentDigest: strings.Repeat("d", 64), QueuedAt: at, UpdatedAt: at,
		},
	}
	for _, document := range documents {
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateHumanRelayJSON(raw); err != nil {
			t.Fatalf("valid document rejected: %v\n%s", err, raw)
		}
	}
}

func TestHumanRelaySchemaEnforcesProviderAcknowledgementReference(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	missing := humanrelay.Event{
		Schema:   humanrelay.RelayEventSchemaV1,
		EventID:  "relay-event:v1:08e9f5c1550a63a6bb677018dad225dd1011693765ecd779a657aba7d9c6940d",
		IntentID: "intent:1",
		Status:   humanrelay.StatusProviderAcknowledged, At: at,
	}
	raw, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanRelayJSON(raw); err == nil {
		t.Fatal("PROVIDER_ACKNOWLEDGED event without provider_ack_ref accepted")
	}
	callerSelected := humanrelay.Event{
		Schema: humanrelay.RelayEventSchemaV1, EventID: "event:caller-selected", IntentID: "intent:1",
		Status: humanrelay.StatusQueued, At: at,
	}
	raw, err = json.Marshal(callerSelected)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanRelayJSON(raw); err == nil {
		t.Fatal("caller-selected relay event identifier accepted")
	}

	for _, status := range []humanrelay.Status{
		humanrelay.StatusQueued,
		humanrelay.StatusDispatching,
		humanrelay.StatusCanceled,
	} {
		event := humanrelay.Event{
			Schema:  humanrelay.RelayEventSchemaV1,
			EventID: relaySchemaEventID(status), IntentID: "intent:1",
			Status: status, At: at, ProviderAckRef: "provider-ack:forbidden",
		}
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateHumanRelayJSON(raw); err == nil {
			t.Fatalf("%s event with provider_ack_ref accepted", status)
		}
	}
}

func relaySchemaEventID(status humanrelay.Status) string {
	return map[humanrelay.Status]string{
		humanrelay.StatusQueued:               "relay-event:v1:b7164850fb4f4a3702a68b8306603832b45baee1038e594f6f869777a1005291",
		humanrelay.StatusDispatching:          "relay-event:v1:eb6e01f2539a7eaba300901095fa3aea0c7931448d77a1084b5bb2f829020d8b",
		humanrelay.StatusProviderAcknowledged: "relay-event:v1:08e9f5c1550a63a6bb677018dad225dd1011693765ecd779a657aba7d9c6940d",
		humanrelay.StatusCanceled:             "relay-event:v1:0c37ef75e7f4d19114cbf417da9bf9232e61e2932b714ebd27da9ebc371f2645",
	}[status]
}

func TestHumanRelaySchemaRejectsHumanAndContactFields(t *testing.T) {
	t.Parallel()
	invalid := []string{
		`{"schema":"asb.human-relay-receipt/v1","intent_id":"intent:1","grant_id":"grant:1","status":"QUEUED","content_digest":"` + strings.Repeat("a", 64) + `","queued_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z","human_participant_id":"human:private"}`,
		`{"schema":"asb.human-relay-intent/v1","intent_id":"intent:1","grant_id":"grant:1","requester_participant_id":"agent:1","purpose":"consultation","capability":"translation","channel":"EMAIL","content_ref":"mailto:person@example.com","content_digest":"` + strings.Repeat("a", 64) + `","relay_session_ref":"https://relay.example/sessions/1","actor_id":"gateway:agent","authorization_id":"authorization:1","proof_id":"proof:1","request_digest":"` + strings.Repeat("b", 64) + `","queued_at":"2026-09-01T00:00:00Z"}`,
	}
	for _, raw := range invalid {
		if err := ValidateHumanRelayJSON([]byte(raw)); err == nil {
			t.Fatalf("privacy-invalid document accepted: %s", raw)
		}
	}
}

func TestHumanRelaySchemaIdentifierBoundary(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	event := humanrelay.Event{
		Schema:  humanrelay.RelayEventSchemaV1,
		EventID: "relay-event:v1:" + strings.Repeat("e", 64), IntentID: strings.Repeat("i", 256),
		Status: humanrelay.StatusQueued, At: at,
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanRelayJSON(raw); err != nil {
		t.Fatalf("256-character identifiers rejected: %v", err)
	}
	event.EventID += "e"
	raw, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHumanRelayJSON(raw); err == nil {
		t.Fatal("non-canonical relay event identifier accepted")
	}
}
