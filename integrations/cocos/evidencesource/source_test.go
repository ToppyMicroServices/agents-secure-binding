// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package evidencesource

import (
	"context"
	"errors"
	"testing"

	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	platformattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
)

type evidenceSourceClient struct {
	reportData [64]byte
	nonce      [32]byte
	platform   platformattestation.PlatformType
	evidence   []byte
	err        error
}

func (c *evidenceSourceClient) GetAttestation(_ context.Context, reportData [64]byte, nonce [32]byte, platform platformattestation.PlatformType) ([]byte, error) {
	c.reportData = reportData
	c.nonce = nonce
	c.platform = platform
	return append([]byte(nil), c.evidence...), c.err
}

func TestEvidenceSourceUsesLocallyConfiguredPlatform(t *testing.T) {
	client := &evidenceSourceClient{evidence: []byte("evidence")}
	source, err := NewEvidenceSource(client, platformattestation.SNP)
	if err != nil {
		t.Fatal(err)
	}
	request := eaattestation.EvidenceRequest{}
	request.ReportData[0] = 0x42
	request.Nonce[0] = 0x24

	result, err := source.GetEvidence(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if client.platform != platformattestation.SNP {
		t.Fatalf("platform = %v, want SNP", client.platform)
	}
	if client.reportData != request.ReportData || client.nonce != request.Nonce {
		t.Fatal("evidence source did not preserve the ASB binding request")
	}
	if result.MediaType != "application/eat+cwt" || string(result.Evidence) != "evidence" {
		t.Fatalf("unexpected evidence result: %#v", result)
	}
}

func TestNewEvidenceSourceRejectsMissingInputs(t *testing.T) {
	if _, err := NewEvidenceSource(nil, platformattestation.SNP); !errors.Is(err, ErrMissingEvidenceClient) {
		t.Fatalf("error = %v, want ErrMissingEvidenceClient", err)
	}
	if _, err := NewEvidenceSource(&evidenceSourceClient{}, platformattestation.NoCC); !errors.Is(err, ErrInvalidPlatform) {
		t.Fatalf("error = %v, want ErrInvalidPlatform", err)
	}
	for _, platform := range []platformattestation.PlatformType{
		platformattestation.SNPvTPM,
		platformattestation.VTPM,
		platformattestation.Azure,
	} {
		if _, err := NewEvidenceSource(&evidenceSourceClient{}, platform); !errors.Is(err, ErrInvalidPlatform) {
			t.Fatalf("platform %v error = %v, want ErrInvalidPlatform", platform, err)
		}
	}
	if _, err := NewEvidenceSource(&evidenceSourceClient{}, platformattestation.PlatformType(999)); !errors.Is(err, ErrInvalidPlatform) {
		t.Fatalf("unknown platform error = %v, want ErrInvalidPlatform", err)
	}
}

func TestEvidenceSourceFailsClosedOnClientError(t *testing.T) {
	wantErr := errors.New("collector unavailable")
	source, err := NewEvidenceSource(&evidenceSourceClient{err: wantErr}, platformattestation.TDX)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.GetEvidence(context.Background(), eaattestation.EvidenceRequest{}); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped collector error", err)
	}
}
