// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package canonicaltranscript

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestEncoderPrimitiveBytes(t *testing.T) {
	t.Parallel()
	encoder := New("p")
	encoder.String("é")
	encoder.Uint32(1)
	encoder.Uint64(2)
	encoder.Time(time.Unix(-1, 123))
	encoder.Optional(false, nil)
	encoder.Optional(true, func(encoder *Encoder) { encoder.String("") })

	got, err := encoder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0001700002c3a9000000010000000000000002ffffffffffffffff0000007b00010000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("transcript = %x, want %x", got, want)
	}
}

func TestEncoderTimeUsesInstantOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		instant time.Time
		zone    *time.Location
	}{
		{
			name: "ordinary offset",
			instant: time.Date(
				2026, 9, 1, 0, 0, 0, 123456789, time.UTC,
			),
			zone: time.FixedZone("example", 9*60*60),
		},
		{
			name: "offset crosses durable year boundary",
			instant: time.Date(
				9999, 12, 31, 23, 0, 0, 0, time.UTC,
			),
			zone: time.FixedZone("boundary", 14*60*60),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			left := New("time/v1")
			left.Time(test.instant)
			right := New("time/v1")
			right.Time(test.instant.In(test.zone))
			leftBytes, leftErr := left.Bytes()
			rightBytes, rightErr := right.Bytes()
			if leftErr != nil || rightErr != nil {
				t.Fatalf("time encoding errors = %v, %v", leftErr, rightErr)
			}
			if !bytes.Equal(leftBytes, rightBytes) {
				t.Fatalf("the same instant encoded differently: %x != %x", leftBytes, rightBytes)
			}
		})
	}
}

func TestEncoderRejectsNonCanonicalInputs(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*Encoder){
		"invalid UTF-8": func(encoder *Encoder) { encoder.String(string([]byte{0xff})) },
		"zero time":     func(encoder *Encoder) { encoder.Time(time.Time{}) },
		"oversize":      func(encoder *Encoder) { encoder.String(strings.Repeat("a", MaxBytes)) },
		"missing optional encoder": func(encoder *Encoder) {
			encoder.Optional(true, nil)
		},
	}
	for name, appendInvalid := range tests {
		name, appendInvalid := name, appendInvalid
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoder := New("test/v1")
			appendInvalid(encoder)
			if transcript, err := encoder.Bytes(); err == nil || transcript != nil {
				t.Fatalf("Bytes() = %x, %v; want nil, error", transcript, err)
			}
		})
	}
}

func TestEncoderDistinguishesAbsentFromPresentEmpty(t *testing.T) {
	t.Parallel()
	absent := New("optional/v1")
	absent.Optional(false, nil)
	present := New("optional/v1")
	present.Optional(true, func(encoder *Encoder) { encoder.String("") })
	absentBytes, absentErr := absent.Bytes()
	presentBytes, presentErr := present.Bytes()
	if absentErr != nil || presentErr != nil {
		t.Fatalf("optional encoding errors = %v, %v", absentErr, presentErr)
	}
	if bytes.Equal(absentBytes, presentBytes) {
		t.Fatalf("absent and present-empty encodings collide: %x", absentBytes)
	}
}
