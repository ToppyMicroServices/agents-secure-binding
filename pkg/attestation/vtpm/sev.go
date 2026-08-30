// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package vtpm

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/proto"
)

const (
	certCacheDirectory = "/agents-secure-binding"
	arkAskBundleName   = "ask_ark.pem"
	vcekName           = "vcek.pem"
	SEVNonce           = 64
	sevSnpProductMilan = "Milan"
	sevSnpProductGenoa = "Genoa"
)

// getLeveledQuoteProvider returns a leveled quote provider for SEV-SNP.
func getLeveledQuoteProvider() (client.LeveledQuoteProvider, error) {
	return client.GetLeveledQuoteProvider()
}

// fetchSEVAttestation fetches a SEV-SNP attestation report.
func fetchSEVAttestation(reportDataSlice []byte, vmpl uint) ([]byte, error) {
	var reportData [SEVNonce]byte
	if len(reportDataSlice) != len(reportData) {
		return nil, fmt.Errorf("invalid SEV-SNP REPORT_DATA length: expected %d bytes, got %d", len(reportData), len(reportDataSlice))
	}
	copy(reportData[:], reportDataSlice)

	qp, err := getLeveledQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("could not get SEV-SNP quote provider: %w", err)
	}

	quoteProto, err := client.GetQuoteProtoAtLevel(qp, reportData, vmpl)
	if err != nil {
		return nil, fmt.Errorf("failed to get SEV-SNP quote: %w", err)
	}
	if quoteProto.GetProduct() == nil {
		return nil, fmt.Errorf("SEV-SNP quote is missing product information")
	}

	homePath, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve certificate cache home directory: %w", err)
	}
	vcekPath := path.Join(homePath, certCacheDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), vcekName)
	arkAskBundlePath := path.Join(homePath, certCacheDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), arkAskBundleName)

	vcekBytes, err := os.ReadFile(vcekPath)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read VCEK file: %v", err)
	}

	arkAskBundleBytes, err := os.ReadFile(arkAskBundlePath)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read ask/ark bundle file: %v", err)
	}

	certificateChain, err := decodeCachedSEVCertificateChain(vcekBytes, arkAskBundleBytes)
	if err != nil {
		return nil, err
	}
	quoteProto.CertificateChain = certificateChain

	result, err := proto.Marshal(quoteProto)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal quote proto: %v", err)
	}

	return result, nil
}

// decodeCachedSEVCertificateChain decodes the cache format written by
// FetchSEVCertificates: one VCEK PEM file and an ASK-then-ARK PEM bundle.
func decodeCachedSEVCertificateChain(vcekBytes, askArkBundleBytes []byte) (*sevsnp.CertificateChain, error) {
	vcekPEM, _ := pem.Decode(vcekBytes)
	if vcekPEM == nil {
		return nil, fmt.Errorf("cached VCEK is not valid PEM")
	}
	askPEM, rest := pem.Decode(askArkBundleBytes)
	if askPEM == nil {
		return nil, fmt.Errorf("cached ASK/ARK bundle is missing ASK PEM")
	}
	arkPEM, _ := pem.Decode(rest)
	if arkPEM == nil {
		return nil, fmt.Errorf("cached ASK/ARK bundle is missing ARK PEM")
	}
	return &sevsnp.CertificateChain{
		VcekCert: vcekPEM.Bytes,
		AskCert:  askPEM.Bytes,
		ArkCert:  arkPEM.Bytes,
	}, nil
}

// GetSEVProductName maps a product string to a SEV product name.
func GetSEVProductName(product string) sevsnp.SevProduct_SevProductName {
	switch product {
	case sevSnpProductMilan:
		return sevsnp.SevProduct_SEV_PRODUCT_MILAN
	case sevSnpProductGenoa:
		return sevsnp.SevProduct_SEV_PRODUCT_GENOA
	default:
		return sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN
	}
}

// derToPem converts DER-encoded certificate to PEM format.
func derToPem(der []byte) []byte {
	// Try to parse to make sure it's a certificate
	if _, err := x509.ParseCertificate(der); err != nil {
		// cert_chain endpoint already returns PEM; just pass through
		return der
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// FetchSEVCertificates fetches SEV-SNP certificates from KDS.
func FetchSEVCertificates(vmpl uint) error {
	var reportData [SEVNonce]byte

	qp, err := getLeveledQuoteProvider()
	if err != nil {
		return fmt.Errorf("could not get SEV-SNP quote provider: %w", err)
	}

	if _, err := rand.Read(reportData[:]); err != nil {
		return fmt.Errorf("failed to create SEV-SNP certificate-fetch challenge: %w", err)
	}

	quoteProto, err := client.GetQuoteProtoAtLevel(qp, reportData, vmpl) // for coverage
	if err != nil {
		return fmt.Errorf("failed to get SEV-SNP quote for certificate fetch: %w", err)
	}
	if quoteProto.GetProduct() == nil || quoteProto.GetReport() == nil {
		return fmt.Errorf("SEV-SNP quote is missing product or report information")
	}

	options := &verify.Options{
		CheckRevocations:    true,
		DisableCertFetching: false,
		Getter:              trust.DefaultHTTPSGetter(),
		Now:                 time.Now(),
		TrustedRoots:        nil,
		Product:             quoteProto.Product,
	}

	result, err := verify.GetAttestationFromReport(quoteProto.Report, options)
	if err != nil {
		return fmt.Errorf("fetch SEV-SNP certificates: %w", err)
	}
	if result.GetCertificateChain() == nil {
		return fmt.Errorf("fetched SEV-SNP attestation is missing its certificate chain")
	}

	homePath, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("resolve certificate cache home directory: %w", err)
	}

	vcekPath := path.Join(homePath, certCacheDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), vcekName)
	arkAskBundlePath := path.Join(homePath, certCacheDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), arkAskBundleName)

	vcekPem := derToPem(result.CertificateChain.VcekCert)
	askPem := derToPem(result.CertificateChain.AskCert)
	arkPem := derToPem(result.CertificateChain.ArkCert)

	arkAskBundlePem := append(askPem, arkPem...)

	vcekDir := filepath.Dir(vcekPath)
	if err := os.MkdirAll(vcekDir, 0o755); err != nil {
		return fmt.Errorf("could not create VCEK directory: %w", err)
	}
	askArkBundleDir := filepath.Dir(arkAskBundlePath)
	if err := os.MkdirAll(askArkBundleDir, 0o755); err != nil {
		return fmt.Errorf("could not create ASK/ARK bundle directory: %w", err)
	}

	if err := os.WriteFile(vcekPath, vcekPem, 0o644); err != nil {
		return fmt.Errorf("could not write VCEK file: %w", err)
	}

	if err := os.WriteFile(arkAskBundlePath, arkAskBundlePem, 0o644); err != nil {
		return fmt.Errorf("could not write ASK/ARK bundle file: %w", err)
	}

	return nil
}
