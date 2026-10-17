// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package platformmodule

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/proto"
)

// Exercise a valid TLS/EA envelope with the concrete SNP verifier. The test
// root and report are synthetic; this checks local acceptance, not hardware.
func TestRequiredAuthenticatorRejectsInvalidAndSampleEvidence(t *testing.T) {
	serverState, clientState, cert, leaf := requiredEvidenceTLSStates(t)
	requestContext, err := ea.NewRandomContext(16)
	if err != nil {
		t.Fatal(err)
	}
	signatureAlgorithms, err := ea.SignatureAlgorithmsExtension([]uint16{uint16(tls.ECDSAWithP256AndSHA256)})
	if err != nil {
		t.Fatal(err)
	}
	request := &ea.AuthenticatorRequest{
		Type:    ea.HandshakeTypeClientCertificateRequest,
		Context: requestContext,
		Extensions: []ea.Extension{
			signatureAlgorithms,
			ea.CMWAttestationOfferExtension(),
		},
	}
	exported, aikHash, binder, err := eaattestation.ComputeBinding(&serverState, eaattestation.ExporterLabelAttestation, requestContext, leaf)
	if err != nil {
		t.Fatal(err)
	}
	expected := eaattestation.EvidenceBinding{
		ReportData: sha512.Sum512(binder),
		Nonce:      sha256.Sum256(exported),
	}
	fixture := testDirectSNPEvidence(t, expected)
	key := testEATSigningKey(t)
	config := testVerifierConfig(PlatformSNP, testSNPPolicyPath(t, fixture.measurement), &key.PublicKey)
	config.SNPVerificationOptions = fixture.verificationOptions
	config.SNPValidationOptions = fixture.validationOptions
	verifier, err := NewEvidenceVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	policy := eaattestation.VerificationPolicy{EvidenceVerifier: verifier}
	if !policy.RequiresAttestation() {
		t.Fatal("test must require attestation")
	}
	signEvidence := func(report []byte, platform string) []byte {
		t.Helper()
		token, err := eat.EncodeToCBOR(testSignedEnvelopeClaims(report, expected.Nonce[:], platform), key, testEATIssuer)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	var tampered sevsnp.Attestation
	if err := proto.Unmarshal(fixture.providerEvidence, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.Report.Signature[0] ^= 0xff
	tamperedReport, err := proto.Marshal(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	sample := append(append([]byte(nil), expected.ReportData[:]...), expected.Nonce[:]...)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, tc := range []struct {
		name     string
		evidence []byte
		want     error
	}{
		{name: "valid signed SNP control", evidence: signEvidence(fixture.providerEvidence, "SNP")},
		{name: "nonempty malformed EAT", evidence: []byte("not an EAT"), want: eat.ErrSignedCBORRequired},
		{name: "trusted EAT around NoCC sample", evidence: signEvidence(sample, "NoCC"), want: ErrUnsupportedPlatform},
		{name: "trusted EAT around forged SNP signature", evidence: signEvidence(tamperedReport, "SNP"), want: ErrSNPVerification},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := eaattestation.MarshalPayload(eaattestation.Payload{
				Version:   1,
				MediaType: "application/eat+cwt",
				Evidence:  tc.evidence,
				Binder: eaattestation.AttestationBinder{
					ExporterLabel: eaattestation.ExporterLabelAttestation,
					AIKPubHash:    aikHash,
					Binding:       binder,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			extension, err := ea.CMWAttestationDataExtension(payload)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := ea.CreateAuthenticator(&serverState, ea.RoleServer, request, cert, []ea.Extension{extension})
			if err != nil {
				t.Fatal(err)
			}
			// Each call creates an independent validation session. Only the
			// evidence differs; TLS, certificate, EA signature and binder are valid.
			result, err := ea.ValidateAuthenticatorWithAttestation(&clientState, ea.RoleServer, request, auth, &x509.VerifyOptions{Roots: roots}, policy)
			if tc.want != nil {
				if !errors.Is(err, tc.want) || result != nil {
					t.Fatalf("required verification returned (%+v, %v), want nil result and %v", result, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || result.Attestation == nil || !result.Attestation.BindingVerified || !result.Attestation.EvidenceVerified {
				t.Fatalf("valid control did not verify binding and evidence: %+v", result)
			}
		})
	}
}

func requiredEvidenceTLSStates(t *testing.T) (tls.ConnectionState, tls.ConnectionState, tls.Certificate, *x509.Certificate) {
	t.Helper()
	key := testEATSigningKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverPipe, clientPipe := net.Pipe()
	t.Cleanup(func() {
		_ = serverPipe.Close()
		_ = clientPipe.Close()
	})
	server := tls.Server(serverPipe, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	client := tls.Client(clientPipe, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- server.HandshakeContext(ctx) }()
	go func() { errorsCh <- client.HandshakeContext(ctx) }()
	for range 2 {
		if err := <-errorsCh; err != nil {
			t.Fatal(err)
		}
	}
	return server.ConnectionState(), client.ConnectionState(), cert, leaf
}
