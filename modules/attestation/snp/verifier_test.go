// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package snp

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	sevtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/proto"
)

type signedFixture struct {
	raw               []byte
	protobuf          []byte
	reportData        []byte
	verification      *verify.Options
	validation        *validate.Options
	callerTrustedRoot *trust.AMDRootCerts
	signer            *sevtest.AmdSigner
}

func newSignedFixture(t *testing.T) *signedFixture {
	t.Helper()

	createdAt := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	verificationTime := createdAt.Add(time.Hour)
	product := abi.DefaultSevProduct()
	productLine := kds.ProductLine(product)
	signer, err := sevtest.DefaultTestOnlyCertChain(kds.ProductName(product), createdAt)
	if err != nil {
		t.Fatalf("DefaultTestOnlyCertChain() error = %v", err)
	}

	reportData := make([]byte, abi.ReportDataSize)
	for i := range reportData {
		reportData[i] = byte(i + 1)
	}
	rawBuffer := sevtest.CreateRawReport(&sevtest.TestReportOptions{ReportData: reportData})
	rawReport := append([]byte(nil), rawBuffer[:abi.ReportSize]...)
	binary.LittleEndian.PutUint64(rawReport[0x08:0x10], abi.SnpPolicyToBytes(abi.SnpPolicy{}))
	r, s, err := signer.Sign(abi.SignedComponent(rawReport))
	if err != nil {
		t.Fatalf("sign report: %v", err)
	}
	if err := abi.SetSignature(r, s, rawReport); err != nil {
		t.Fatalf("SetSignature() error = %v", err)
	}
	certTable, err := signer.CertTableBytes()
	if err != nil {
		t.Fatalf("CertTableBytes() error = %v", err)
	}
	rawEvidence := append(append([]byte(nil), rawReport...), certTable...)
	attestation, err := abi.ReportCertsToProto(rawEvidence)
	if err != nil {
		t.Fatalf("ReportCertsToProto() error = %v", err)
	}
	attestation.Product = proto.Clone(product).(*sevsnp.SevProduct)
	protobufEvidence, err := proto.Marshal(attestation)
	if err != nil {
		t.Fatalf("proto.Marshal() error = %v", err)
	}

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		Number:             big.NewInt(1),
		ThisUpdate:         createdAt,
		NextUpdate:         createdAt.Add(24 * time.Hour),
	}
	crl, err := x509.CreateRevocationList(
		mathrand.New(mathrand.NewSource(0x5e5)),
		crlTemplate,
		signer.Ark,
		signer.Keys.Ark,
	)
	if err != nil {
		t.Fatalf("CreateRevocationList() error = %v", err)
	}
	getter := sevtest.SimpleGetter(map[string][]byte{
		kds.CrlLinkByKey(productLine, abi.VcekReportSigner): crl,
	})
	root := trust.AMDRootCertsProduct(productLine)
	root.ProductCerts = &trust.ProductCerts{Ark: signer.Ark, Ask: signer.Ask}
	verification := &verify.Options{
		CheckRevocations: true,
		Getter:           getter,
		Now:              verificationTime,
		TrustedRoots: map[string][]*trust.AMDRootCerts{
			productLine: {root},
		},
		Product: proto.Clone(product).(*sevsnp.SevProduct),
	}
	vmpl := 0
	validation := &validate.Options{
		GuestPolicy: abi.SnpPolicy{},
		ReportData:  make([]byte, abi.ReportDataSize),
		VMPL:        &vmpl,
	}

	return &signedFixture{
		raw:               rawEvidence,
		protobuf:          protobufEvidence,
		reportData:        reportData,
		verification:      verification,
		validation:        validation,
		callerTrustedRoot: root,
		signer:            signer,
	}
}

func TestVerifySignedProtobufAndABIWithCertificateTable(t *testing.T) {
	fixture := newSignedFixture(t)
	originalConfiguredReportData := append([]byte(nil), fixture.validation.ReportData...)

	for name, evidence := range map[string][]byte{
		"protobuf":                   fixture.protobuf,
		"ABI with certificate table": fixture.raw,
	} {
		t.Run(name, func(t *testing.T) {
			attestation, err := Verify(
				context.Background(),
				evidence,
				fixture.reportData,
				fixture.verification,
				fixture.validation,
			)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if got := attestation.GetReport().GetReportData(); string(got) != string(fixture.reportData) {
				t.Fatalf("verified REPORT_DATA = %x, want %x", got, fixture.reportData)
			}
		})
	}

	if fixture.callerTrustedRoot.CRL != nil {
		t.Fatal("Verify() mutated the caller's trusted-root CRL cache")
	}
	if string(fixture.validation.ReportData) != string(originalConfiguredReportData) {
		t.Fatal("Verify() mutated the caller's validation REPORT_DATA")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	fixture := newSignedFixture(t)
	attestation, err := Parse(fixture.protobuf)
	if err != nil {
		t.Fatal(err)
	}
	attestation.Report.Signature[0] ^= 0x80
	tampered, err := proto.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(context.Background(), tampered, fixture.reportData, fixture.verification, fixture.validation)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify() error = %v, want ErrVerification", err)
	}
}

func TestVerifyRejectsReportDataMismatch(t *testing.T) {
	fixture := newSignedFixture(t)
	wrong := append([]byte(nil), fixture.reportData...)
	wrong[0] ^= 0xff

	_, err := Verify(context.Background(), fixture.protobuf, wrong, fixture.verification, fixture.validation)
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("Verify() error = %v, want ErrBinding", err)
	}
}

func TestVerifyRejectsDebugEnabledReport(t *testing.T) {
	fixture := newSignedFixture(t)
	attestation, err := Parse(fixture.protobuf)
	if err != nil {
		t.Fatal(err)
	}
	attestation.Report.Policy = abi.SnpPolicyToBytes(abi.SnpPolicy{Debug: true})
	rawReport, err := abi.ReportToAbiBytes(attestation.Report)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := fixture.signer.Sign(abi.SignedComponent(rawReport))
	if err != nil {
		t.Fatal(err)
	}
	if err := abi.SetSignature(r, s, rawReport); err != nil {
		t.Fatal(err)
	}
	attestation.Report, err = abi.ReportToProto(rawReport)
	if err != nil {
		t.Fatal(err)
	}
	debugEvidence, err := proto.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Verify(context.Background(), debugEvidence, fixture.reportData, fixture.verification, fixture.validation)
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Verify() error = %v, want ErrValidation", err)
	}
}

func TestVerifyFailsClosedWhenCRLIsUnavailable(t *testing.T) {
	fixture := newSignedFixture(t)
	verification := *fixture.verification
	verification.Getter = sevtest.SimpleGetter(nil)

	_, err := Verify(context.Background(), fixture.protobuf, fixture.reportData, &verification, fixture.validation)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify() error = %v, want ErrVerification", err)
	}
}

func TestValidateConfigFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*verify.Options, *validate.Options)
	}{
		{name: "no revocation", mutate: func(v *verify.Options, _ *validate.Options) { v.CheckRevocations = false }},
		{name: "no getter", mutate: func(v *verify.Options, _ *validate.Options) { v.Getter = nil }},
		{name: "no product", mutate: func(v *verify.Options, _ *validate.Options) { v.Product = nil }},
		{name: "unknown product", mutate: func(v *verify.Options, _ *validate.Options) { v.Product = &sevsnp.SevProduct{} }},
		{name: "invalid product enum", mutate: func(v *verify.Options, _ *validate.Options) {
			v.Product = &sevsnp.SevProduct{Name: sevsnp.SevProduct_SevProductName(99)}
		}},
		{name: "nil trusted root", mutate: func(v *verify.Options, _ *validate.Options) {
			v.TrustedRoots[kds.ProductLine(v.Product)] = []*trust.AMDRootCerts{nil}
		}},
		{name: "debug allowed", mutate: func(_ *verify.Options, v *validate.Options) { v.GuestPolicy.Debug = true }},
		{name: "no VMPL", mutate: func(_ *verify.Options, v *validate.Options) { v.VMPL = nil }},
		{name: "invalid VMPL", mutate: func(_ *verify.Options, v *validate.Options) { value := 4; v.VMPL = &value }},
		{name: "invalid measurement", mutate: func(_ *verify.Options, v *validate.Options) { v.Measurement = []byte{1} }},
		{name: "nil certificate-table option", mutate: func(_ *verify.Options, v *validate.Options) {
			v.CertTableOptions = map[string]*validate.CertEntryOption{"00000000-0000-0000-0000-000000000000": nil}
		}},
	}

	if !errors.Is(ValidateConfig(nil, &validate.Options{}), ErrInvalidConfig) {
		t.Fatal("nil verification options were accepted")
	}
	if !errors.Is(ValidateConfig(&verify.Options{}, nil), ErrInvalidConfig) {
		t.Fatal("nil validation options were accepted")
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSignedFixture(t)
			test.mutate(fixture.verification, fixture.validation)
			if err := ValidateConfig(fixture.verification, fixture.validation); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("ValidateConfig() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestParseRejectsMalformedEvidence(t *testing.T) {
	tests := [][]byte{
		nil,
		{0x0a, 0x00},
		make([]byte, abi.ReportSize),
	}
	for _, evidence := range tests {
		if _, err := Parse(evidence); !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("Parse(%x) error = %v, want ErrInvalidEvidence", evidence, err)
		}
	}
}

func TestKDSGetterRejectsUntrustedURLs(t *testing.T) {
	getter := &boundedKDSGetter{client: http.DefaultClient}
	if _, err := getter.Get("http://kdsintf.amd.com/vcek/v1/Milan/crl"); err == nil {
		t.Fatal("non-HTTPS KDS URL was accepted")
	}
	if _, err := getter.Get("https://example.test/vcek/v1/Milan/crl"); err == nil {
		t.Fatal("non-AMD KDS host was accepted")
	}
	parsed, err := url.Parse("https://kdsintf.amd.com/vcek/v1/Milan/crl")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateKDSURL(parsed); err != nil {
		t.Fatalf("AMD KDS URL rejected: %v", err)
	}
}
