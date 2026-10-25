// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
)

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, 5)
	header[0] = frameTypeRequest
	binary.BigEndian.PutUint32(header[1:5], maxFramePayloadLen+1)
	if _, err := buf.Write(header); err != nil {
		t.Fatal(err)
	}

	_, _, err := readFrame(&buf, frameTypeRequest)
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
	if !strings.Contains(err.Error(), "frame payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadFrameRejectsOversizedRequestBeforePayloadRead(t *testing.T) {
	header := make([]byte, 5)
	header[0] = frameTypeRequest
	binary.BigEndian.PutUint32(header[1:], maxRequestFramePayloadLen+1)

	_, _, err := readFrame(bytes.NewReader(header), frameTypeRequest)
	if err == nil || !strings.Contains(err.Error(), "frame payload too large") {
		t.Fatalf("readFrame() error = %v, want request size rejection before reading payload", err)
	}
}

func TestReadFrameRejectsUnexpectedTypeBeforePayloadRead(t *testing.T) {
	for _, tc := range []struct {
		name              string
		gotType, wantType uint8
	}{
		{"server", frameTypeAuthenticator, frameTypeRequest},
		{"client", frameTypeRequest, frameTypeAuthenticator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make([]byte, 5)
			header[0] = tc.gotType
			binary.BigEndian.PutUint32(header[1:], maxFramePayloadLen)

			_, _, err := readFrame(bytes.NewReader(header), tc.wantType)
			if err == nil || !strings.Contains(err.Error(), "unexpected frame type") {
				t.Fatalf("readFrame() error = %v, want type rejection before reading payload", err)
			}
		})
	}
}

func TestReadFrameAcceptsLargestRequest(t *testing.T) {
	req := ea.AuthenticatorRequest{
		Type:       ea.HandshakeTypeClientCertificateRequest,
		Context:    make([]byte, 255),
		Extensions: []ea.Extension{{Type: 1, Data: make([]byte, 0xFFFF-4)}},
	}
	payload, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != maxRequestFramePayloadLen {
		t.Fatalf("largest valid request = %d bytes, want %d", len(payload), maxRequestFramePayloadLen)
	}
	var frame bytes.Buffer
	if err := writeFrame(&frame, frameTypeRequest, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := readFrame(&frame, frameTypeRequest)
	if err != nil || typ != frameTypeRequest || !bytes.Equal(got, payload) {
		t.Fatalf("readFrame() = (%d, %d bytes, %v), want valid request", typ, len(got), err)
	}
}

func TestReadFrameAllowsAuthenticatorAboveRequestLimit(t *testing.T) {
	payload := make([]byte, maxRequestFramePayloadLen+1)
	var frame bytes.Buffer
	if err := writeFrame(&frame, frameTypeAuthenticator, payload); err != nil {
		t.Fatal(err)
	}
	typ, got, err := readFrame(&frame, frameTypeAuthenticator)
	if err != nil || typ != frameTypeAuthenticator || !bytes.Equal(got, payload) {
		t.Fatalf("readFrame() = (%d, %d bytes, %v), want valid authenticator frame", typ, len(got), err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, maxFramePayloadLen+1)
	err := writeFrame(bytes.NewBuffer(nil), frameTypeAuthenticator, payload)
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
	if !strings.Contains(err.Error(), "frame payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}
