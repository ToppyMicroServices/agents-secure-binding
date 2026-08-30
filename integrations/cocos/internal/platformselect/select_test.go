// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package platformselect

import (
	"errors"
	"testing"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
)

func TestResolveExplicitDirectPlatformDoesNotUseLegacyDetection(t *testing.T) {
	panicProbe := func() bool { panic("explicit selection must not probe hardware") }
	for name, want := range map[string]attestation.PlatformType{
		"snp": attestation.SNP,
		"tdx": attestation.TDX,
	} {
		got, err := resolve(name, panicProbe, panicProbe)
		if err != nil || got != want {
			t.Fatalf("resolve(%q) = (%v, %v), want (%v, nil)", name, got, err, want)
		}
	}
}

func TestResolveAutoUsesDirectDevicesOnly(t *testing.T) {
	tests := []struct {
		name      string
		snp       bool
		tdx       bool
		want      attestation.PlatformType
		wantError error
	}{
		{name: "no hardware", want: attestation.NoCC},
		{name: "direct SNP even when a vTPM may also exist", snp: true, want: attestation.SNP},
		{name: "direct TDX", tdx: true, want: attestation.TDX},
		{name: "ambiguous direct devices", snp: true, tdx: true, want: attestation.NoCC, wantError: ErrAmbiguousPlatform},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolve("auto", func() bool { return test.snp }, func() bool { return test.tdx })
			if got != test.want || !errors.Is(err, test.wantError) {
				t.Fatalf("resolve(auto) = (%v, %v), want (%v, %v)", got, err, test.want, test.wantError)
			}
		})
	}
}

func TestResolveRejectsLegacyPlatforms(t *testing.T) {
	for _, name := range []string{"snp-vtpm", "vtpm", "azure", "unknown"} {
		if _, err := resolve(name, nil, nil); !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("resolve(%q) error = %v, want ErrUnsupportedPlatform", name, err)
		}
	}
}
