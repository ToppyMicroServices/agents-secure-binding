// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameTypeRequest uint8 = iota + 1
	frameTypeAuthenticator
	maxFramePayloadLen = 16 << 20 // 16 MiB
	// A request contains a four-byte handshake header, a one-byte context
	// length, at most 255 context bytes, and a two-byte extension length
	// followed by at most 65535 extension bytes.
	maxRequestFramePayloadLen = 4 + 1 + 255 + 2 + 0xFFFF
)

func writeFrame(w io.Writer, typ uint8, payload []byte) error {
	if len(payload) > maxFramePayloadLen {
		return fmt.Errorf("atls: frame payload too large: %d", len(payload))
	}
	header := make([]byte, 5)
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func readFrame(r io.Reader, expectedType uint8) (uint8, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	if header[0] == 0 {
		return 0, nil, fmt.Errorf("atls: invalid frame type")
	}
	if header[0] != expectedType {
		return 0, nil, fmt.Errorf("atls: unexpected frame type %d", header[0])
	}
	n := binary.BigEndian.Uint32(header[1:5])
	maxLen := uint32(maxFramePayloadLen)
	if expectedType == frameTypeRequest {
		maxLen = maxRequestFramePayloadLen
	}
	if n > maxLen {
		return 0, nil, fmt.Errorf("atls: frame payload too large: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}
