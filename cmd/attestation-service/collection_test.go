// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	attestationpb "github.com/ToppyMicroServices/agents-secure-binding/v2/internal/proto/attestation/v1"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/google/go-sev-guest/abi"
	sevtesting "github.com/google/go-sev-guest/testing"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type collectionProvider struct {
	evidence []byte
	err      error
	calls    atomic.Int32
}

func (p *collectionProvider) collect() ([]byte, error) {
	p.calls.Add(1)
	return p.evidence, p.err
}

func (p *collectionProvider) Attestation(_, _ []byte) ([]byte, error)  { return p.collect() }
func (p *collectionProvider) TeeAttestation(_ []byte) ([]byte, error)  { return p.collect() }
func (p *collectionProvider) VTpmAttestation(_ []byte) ([]byte, error) { return p.collect() }
func (p *collectionProvider) AzureAttestationToken(_ []byte) ([]byte, error) {
	return p.collect()
}

func collectionService(t *testing.T, provider attestation.Provider) *service {
	t.Helper()
	key, err := eat.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return &service{
		provider:   provider,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		signingKey: key,
		eatFormat:  "CBOR",
		eatIssuer:  "collection-test",
	}
}

func collectionClient(t *testing.T, svc *service) attestationpb.AttestationServiceClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	attestationpb.RegisterAttestationServiceServer(server, svc)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve: %v", err)
		}
	})
	conn, err := grpc.NewClient("passthrough:///collection-test",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return attestationpb.NewAttestationServiceClient(conn)
}

func TestCollectionRPCRejectsEmptyProviderResults(t *testing.T) {
	// The nonempty vTPM bytes are a parser fixture, not hardware evidence.
	payload := bytes.Repeat([]byte{0x42}, 64)
	for _, scenario := range []struct {
		name     string
		evidence []byte
		err      error
		wantCode codes.Code
	}{
		{"nil", nil, nil, codes.Unavailable},
		{"empty", []byte{}, nil, codes.Unavailable},
		{"provider error", nil, errors.New("provider unavailable"), codes.Unknown},
		{"partial result with error", payload, errors.New("provider unavailable"), codes.Unknown},
		{"nonempty", payload, nil, codes.OK},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			provider := &collectionProvider{evidence: scenario.evidence, err: scenario.err}
			svc := collectionService(t, provider)
			client := collectionClient(t, svc)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req := &attestationpb.AttestationRequest{Nonce: make([]byte, 32), PlatformType: attestationpb.PlatformType_PLATFORM_TYPE_VTPM}
			encoded, err := client.FetchAttestation(ctx, req)
			if status.Code(err) != scenario.wantCode || (err != nil && encoded != nil) {
				t.Fatalf("FetchAttestation = %v, %v", encoded, err)
			}
			if err == nil {
				claims, decodeErr := eat.DecodeVerifiedCBOR(encoded.EatToken, &svc.signingKey.PublicKey)
				if decodeErr != nil || !bytes.Equal(claims.RawReport, payload) {
					t.Fatalf("nonempty report was not preserved: %v", decodeErr)
				}
			}
			raw, err := client.FetchRawEvidence(ctx, req)
			if status.Code(err) != scenario.wantCode || (err != nil && raw != nil) ||
				(err == nil && !bytes.Equal(raw.Evidence, payload)) {
				t.Fatalf("FetchRawEvidence = %v, %v", raw, err)
			}
			token, err := client.FetchAzureToken(ctx, &attestationpb.AzureTokenRequest{Nonce: req.Nonce})
			if status.Code(err) != scenario.wantCode || (err != nil && token != nil) ||
				(err == nil && !bytes.Equal(token.Token, payload)) {
				t.Fatalf("FetchAzureToken = %v, %v", token, err)
			}
			if provider.calls.Load() != 3 {
				t.Fatalf("RPC handler did not reach the provider: calls=%d", provider.calls.Load())
			}
		})
	}
}

func TestCollectionRejectsEmptyEvidenceForEveryProviderRoute(t *testing.T) {
	for _, platform := range []attestationpb.PlatformType{
		attestationpb.PlatformType_PLATFORM_TYPE_SNP, attestationpb.PlatformType_PLATFORM_TYPE_TDX,
		attestationpb.PlatformType_PLATFORM_TYPE_VTPM, attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM,
		attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED,
	} {
		t.Run(platform.String(), func(t *testing.T) {
			svc := collectionService(t, &collectionProvider{})
			req := &attestationpb.AttestationRequest{PlatformType: platform, ReportData: make([]byte, 64), Nonce: make([]byte, 32)}
			raw, err := svc.FetchRawEvidence(t.Context(), req)
			if raw != nil || status.Code(err) != codes.Unavailable {
				t.Fatalf("FetchRawEvidence = %v, %v", raw, err)
			}
			if platform != attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED {
				encoded, err := svc.FetchAttestation(t.Context(), req)
				if encoded != nil || status.Code(err) != codes.Unavailable {
					t.Fatalf("FetchAttestation = %v, %v", encoded, err)
				}
			}
		})
	}
}

func TestCollectionRPCEmptyProviderCannotReturnAzureToken(t *testing.T) {
	client := collectionClient(t, collectionService(t, &attestation.EmptyProvider{}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	response, err := client.FetchAzureToken(ctx, &attestationpb.AzureTokenRequest{Nonce: make([]byte, 32)})
	if response != nil || err == nil || status.Code(err) == codes.Unimplemented {
		t.Fatalf("unsupported Azure collection = %v, %v", response, err)
	}
}

func TestCollectionPreservesNoCCSample(t *testing.T) {
	svc := collectionService(t, &attestation.EmptyProvider{})
	req := &attestationpb.AttestationRequest{
		PlatformType: attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED,
		ReportData:   bytes.Repeat([]byte{0x11}, 64), Nonce: bytes.Repeat([]byte{0x22}, 32),
	}
	response, err := svc.FetchAttestation(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := eat.DecodeVerifiedCBOR(response.EatToken, &svc.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{}, req.ReportData...), req.Nonce...)
	if claims.PlatformType != "NoCC" || !bytes.Equal(claims.RawReport, want) {
		t.Fatalf("sample was lost or mislabeled as hardware evidence: %+v", claims)
	}
}

func TestCollectionAcceptsDirectSNPProviderProtobuf(t *testing.T) {
	var reportData [abi.ReportDataSize]byte
	raw := sevtesting.TestRawReport(reportData)
	snpAttestation, err := abi.ReportCertsToProto(raw[:abi.ReportSize])
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := proto.Marshal(snpAttestation)
	if err != nil {
		t.Fatal(err)
	}
	svc := collectionService(t, &collectionProvider{evidence: evidence})
	req := &attestationpb.AttestationRequest{PlatformType: attestationpb.PlatformType_PLATFORM_TYPE_SNP, ReportData: reportData[:]}
	response, err := svc.FetchAttestation(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := eat.DecodeVerifiedCBOR(response.EatToken, &svc.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.PlatformType != "SNP" || !bytes.Equal(claims.RawReport, evidence) ||
		!bytes.Equal(claims.Measurements, snpAttestation.GetReport().GetMeasurement()) {
		t.Fatalf("direct SNP provider report was not preserved in EAT: %+v", claims)
	}
}

func TestCollectionAcceptsSNPvTPMProviderWrapper(t *testing.T) {
	var reportData [abi.ReportDataSize]byte
	raw := sevtesting.TestRawReport(reportData)
	snp, err := abi.ReportCertsToProto(raw[:abi.ReportSize])
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := proto.Marshal(&attest.Attestation{
		AkPub:  []byte("attestation-key"),
		Quotes: []*tpm.Quote{{Quote: []byte("quote")}},
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: snp,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := collectionService(t, &collectionProvider{evidence: evidence})
	req := &attestationpb.AttestationRequest{
		PlatformType: attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM,
		ReportData:   reportData[:], Nonce: make([]byte, 32),
	}
	response, err := svc.FetchAttestation(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := eat.DecodeVerifiedCBOR(response.EatToken, &svc.signingKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.PlatformType != "SNP-vTPM" || !bytes.Equal(claims.RawReport, evidence) ||
		!bytes.Equal(claims.Measurements, snp.GetReport().GetMeasurement()) {
		t.Fatalf("SNP-vTPM provider wrapper was not preserved in EAT: %+v", claims)
	}
}
