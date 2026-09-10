// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
)

const (
	ProfileID                 = "asb.taskcoord-agent-relay/v1"
	RequestContextDomain      = "ASB-TASKCOORD-AGENT-RELAY-CONTEXT-v1"
	AuthorizationDetailPrefix = "urn:asb:taskcoord-agent-relay:v1:sha256:"
)

func AuthorizationDetail(digest humanrelay.Digest) string {
	return AuthorizationDetailPrefix + digest.String()
}

func RequestContext(digest humanrelay.Digest) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(RequestContextDomain)
	buffer.WriteByte(0)
	writeField(&buffer, "request_digest", digest[:])
	return buffer.Bytes()
}

func RequestContextSHA256(digest humanrelay.Digest) string {
	sum := sha256.Sum256(RequestContext(digest))
	return hex.EncodeToString(sum[:])
}

func writeField(buffer *bytes.Buffer, name string, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint16(length[:2], uint16(len(name)))
	buffer.Write(length[:2])
	buffer.WriteString(name)
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer.Write(length[:])
	buffer.Write(value)
}
