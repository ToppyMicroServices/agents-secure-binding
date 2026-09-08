// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package humanrelay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

const (
	relayIntentDigestDomain = "ASB-HUMAN-RELAY-INTENT-v1"
	relayEventIDDomain      = "ASB-HUMAN-RELAY-EVENT-ID-v1"
	relayEventIDPrefix      = "relay-event:v1:"
	localGatewayAckIDDomain = "ASB-HUMAN-RELAY-LOCAL-GATEWAY-ACK-ID-v1"
	localGatewayAckIDPrefix = "gateway-ack:v1:"
)

// RequestDigest returns the deterministic digest used by the ASB relay
// profile. It validates the request before encoding it.
func RequestDigest(request RelayIntentRequest) (Digest, error) {
	if err := request.Validate(); err != nil {
		return Digest{}, err
	}
	encoder := intentEncoder{}
	encoder.buffer.WriteString(relayIntentDigestDomain)
	encoder.buffer.WriteByte(0)
	encoder.add("intent_id", []byte(request.IntentID))
	encoder.add("grant_id", []byte(request.GrantID))
	encoder.add("requester_participant_id", []byte(request.RequesterParticipantID))
	encoder.add("purpose", []byte(request.Purpose))
	encoder.add("capability", []byte(request.Capability))
	encoder.add("channel", []byte(request.Channel))
	contentDigest, err := hex.DecodeString(request.ContentDigest)
	if err != nil {
		return Digest{}, invalidRequest("content_digest must be hexadecimal")
	}
	encoder.add("content_ref", []byte(request.ContentRef))
	encoder.add("content_digest", contentDigest)
	if encoder.err != nil {
		return Digest{}, encoder.err
	}
	return sha256.Sum256(encoder.buffer.Bytes()), nil
}

// relayEventID returns the collision-resistant identifier for one relay
// transport event. Status is part of the versioned transcript so distinct
// transport states for one intent cannot share an identifier.
func relayEventID(status Status, intentID string) (string, error) {
	if status != StatusQueued && status != StatusDispatching &&
		status != StatusProviderAcknowledged && status != StatusCanceled {
		return "", invalidRequest("unsupported relay status")
	}
	if err := validateID("intent_id", intentID); err != nil {
		return "", invalidRequest(err.Error())
	}
	encoder := intentEncoder{}
	encoder.buffer.WriteString(relayEventIDDomain)
	encoder.buffer.WriteByte(0)
	encoder.add("status", []byte(status))
	encoder.add("intent_id", []byte(intentID))
	if encoder.err != nil {
		return "", encoder.err
	}
	digest := sha256.Sum256(encoder.buffer.Bytes())
	return relayEventIDPrefix + hex.EncodeToString(digest[:]), nil
}

// localGatewayAckRef keeps the Mac/CI sink compatible with the full relay
// identifier boundary without exposing or concatenating the caller's ID.
func localGatewayAckRef(intentID string) (string, error) {
	if err := validateID("intent_id", intentID); err != nil {
		return "", invalidRequest(err.Error())
	}
	encoder := intentEncoder{}
	encoder.buffer.WriteString(localGatewayAckIDDomain)
	encoder.buffer.WriteByte(0)
	encoder.add("intent_id", []byte(intentID))
	if encoder.err != nil {
		return "", encoder.err
	}
	digest := sha256.Sum256(encoder.buffer.Bytes())
	return localGatewayAckIDPrefix + hex.EncodeToString(digest[:]), nil
}

type intentEncoder struct {
	buffer bytes.Buffer
	err    error
}

func (e *intentEncoder) add(name string, value []byte) {
	if e.err != nil {
		return
	}
	if len(name) > math.MaxUint16 || uint64(len(value)) > math.MaxUint32 {
		e.err = fmt.Errorf("%w: transcript field is too large", ErrInvalidRequest)
		return
	}
	var length [4]byte
	binary.BigEndian.PutUint16(length[:2], uint16(len(name)))
	e.buffer.Write(length[:2])
	e.buffer.WriteString(name)
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	e.buffer.Write(length[:])
	e.buffer.Write(value)
	if e.buffer.Len() > MaxDocumentBytes {
		e.err = fmt.Errorf("%w: transcript exceeds %d bytes", ErrInvalidRequest, MaxDocumentBytes)
	}
}
