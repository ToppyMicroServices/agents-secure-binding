// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package canonicaltranscript implements the language-independent primitive
// encodings used by ASB request-digest profiles. Profile-specific field order
// remains in the package that owns each semantic model.
package canonicaltranscript

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

// MaxBytes bounds every canonical request transcript before hashing.
const MaxBytes = 16 << 10

// Encoder appends values in the normative order selected by one profile.
type Encoder struct {
	buffer []byte
	err    error
}

// New begins a transcript with its domain/version string.
func New(profile string) *Encoder {
	encoder := &Encoder{buffer: make([]byte, 0, 512)}
	if profile == "" {
		encoder.err = fmt.Errorf("canonical transcript: profile is required")
		return encoder
	}
	encoder.String(profile)
	return encoder
}

// String appends u16be(len(UTF-8 bytes)) followed by the exact bytes. It does
// not normalize Unicode.
func (e *Encoder) String(value string) {
	if e.err != nil {
		return
	}
	if !utf8.ValidString(value) {
		e.err = fmt.Errorf("canonical transcript: string is not valid UTF-8")
		return
	}
	if len(value) > math.MaxUint16 {
		e.err = fmt.Errorf("canonical transcript: string exceeds uint16 length")
		return
	}
	if !e.reserve(2 + len(value)) {
		return
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(value)))
	e.buffer = append(e.buffer, size[:]...)
	e.buffer = append(e.buffer, value...)
}

// Uint32 appends one unsigned 32-bit integer in big-endian order.
func (e *Encoder) Uint32(value uint32) {
	if e.err != nil || !e.reserve(4) {
		return
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	e.buffer = append(e.buffer, encoded[:]...)
}

// Uint64 appends one unsigned 64-bit integer in big-endian order.
func (e *Encoder) Uint64(value uint64) {
	if e.err != nil || !e.reserve(8) {
		return
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	e.buffer = append(e.buffer, encoded[:]...)
}

// Time appends signed Unix seconds as two's-complement i64be followed by
// nanoseconds as u32be. Zone names and offsets do not enter the transcript.
func (e *Encoder) Time(value time.Time) {
	if e.err != nil {
		return
	}
	if value.IsZero() {
		e.err = fmt.Errorf("canonical transcript: timestamp is required")
		return
	}
	if _, err := value.UTC().MarshalText(); err != nil {
		e.err = fmt.Errorf("canonical transcript: timestamp is outside the durable range: %w", err)
		return
	}
	if !e.reserve(12) {
		return
	}
	var encoded [12]byte
	binary.BigEndian.PutUint64(encoded[:8], uint64(value.Unix()))
	binary.BigEndian.PutUint32(encoded[8:], uint32(value.Nanosecond()))
	e.buffer = append(e.buffer, encoded[:]...)
}

// Optional appends 00 for absence or 01 followed by the nested value.
func (e *Encoder) Optional(present bool, appendValue func(*Encoder)) {
	if e.err != nil || !e.reserve(1) {
		return
	}
	if !present {
		e.buffer = append(e.buffer, 0)
		return
	}
	e.buffer = append(e.buffer, 1)
	if appendValue == nil {
		e.err = fmt.Errorf("canonical transcript: present optional value has no encoder")
		return
	}
	appendValue(e)
}

// Bytes returns a detached complete transcript.
func (e *Encoder) Bytes() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return append([]byte(nil), e.buffer...), nil
}

func (e *Encoder) reserve(additional int) bool {
	if additional < 0 || len(e.buffer) > MaxBytes-additional {
		e.err = fmt.Errorf("canonical transcript: exceeds %d bytes", MaxBytes)
		return false
	}
	return true
}
