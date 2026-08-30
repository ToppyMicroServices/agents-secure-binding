// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package snp parses and verifies direct AMD SEV-SNP evidence independently
// from the ASB protocol implementation. ASB supplies the expected session
// REPORT_DATA and treats the returned error as the module appraisal result.
package snp

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/proto"
)

const (
	amdKDSHost               = "kdsintf.amd.com"
	defaultCollateralTimeout = 2 * time.Minute
	defaultMaxRetryDelay     = 30 * time.Second
	defaultHTTPTimeout       = 20 * time.Second
	maxCollateralBytes       = 16 << 20
)

var (
	// ErrInvalidEvidence means the input was neither a structurally valid
	// sevsnp.Attestation protobuf nor an AMD ABI report/certificate table.
	ErrInvalidEvidence = errors.New("snp module: invalid direct SNP evidence")
	// ErrInvalidConfig means the verifier or validator does not satisfy the
	// strict verification baseline enforced by this module.
	ErrInvalidConfig = errors.New("snp module: strict verification configuration is required")
	// ErrBinding means REPORT_DATA is absent, malformed, or does not match the
	// ASB session binding supplied by the caller.
	ErrBinding = errors.New("snp module: REPORT_DATA does not match ASB session binding")
	// ErrVerification means certificate, signature, or revocation verification
	// failed.
	ErrVerification = errors.New("snp module: certificate, signature, or revocation verification failed")
	// ErrValidation means the authenticated report did not satisfy local SNP
	// policy.
	ErrValidation = errors.New("snp module: report policy validation failed")
)

// Parse accepts the two direct SNP representations used at the module
// boundary: a sevsnp.Attestation protobuf, or an AMD ABI attestation report
// optionally followed by its certificate table. Parsing is structural only;
// callers must use Verify before trusting any field.
func Parse(evidence []byte) (*sevsnp.Attestation, error) {
	if len(evidence) == 0 {
		return nil, fmt.Errorf("%w: evidence is empty", ErrInvalidEvidence)
	}

	if len(evidence) >= abi.ReportSize {
		if err := abi.ValidateReportFormat(evidence[:abi.ReportSize]); err == nil {
			parsed, err := abi.ReportCertsToProto(evidence)
			if err != nil {
				return nil, fmt.Errorf("%w: malformed ABI certificate table: %v", ErrInvalidEvidence, err)
			}
			return parsed, nil
		}
	}

	var attestation sevsnp.Attestation
	if err := proto.Unmarshal(evidence, &attestation); err != nil {
		return nil, fmt.Errorf("%w: failed to parse ABI report or protobuf: %v", ErrInvalidEvidence, err)
	}
	if attestation.GetReport() == nil {
		return nil, fmt.Errorf("%w: protobuf is missing its report", ErrInvalidEvidence)
	}
	if err := validateReportShape(attestation.GetReport()); err != nil {
		return nil, fmt.Errorf("%w: malformed protobuf report: %v", ErrInvalidEvidence, err)
	}
	return &attestation, nil
}

// NewKDSGetter returns a context-aware, bounded AMD KDS getter. It permits
// only HTTPS requests to AMD's KDS host. Deployments using a reviewed local
// collateral service can provide their own getter instead.
func NewKDSGetter() trust.HTTPSGetter {
	client := &http.Client{
		Timeout: defaultHTTPTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if err := validateKDSURL(request.URL); err != nil {
				return fmt.Errorf("SNP collateral redirect rejected: %w", err)
			}
			return nil
		},
	}
	return &trust.RetryHTTPSGetter{
		Timeout:       defaultCollateralTimeout,
		MaxRetryDelay: defaultMaxRetryDelay,
		Getter:        &boundedKDSGetter{client: client},
	}
}

type boundedKDSGetter struct {
	client *http.Client
}

func (g *boundedKDSGetter) Get(rawURL string) ([]byte, error) {
	return g.GetContext(context.Background(), rawURL)
}

func (g *boundedKDSGetter) GetContext(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid SNP collateral URL: %w", err)
	}
	if err := validateKDSURL(parsed); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := g.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("failed to retrieve %s, status code received %d", parsed.Redacted(), response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCollateralBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCollateralBytes {
		return nil, fmt.Errorf("SNP collateral response exceeds %d bytes", maxCollateralBytes)
	}
	return body, nil
}

func validateKDSURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("SNP collateral URL must use HTTPS")
	}
	if !strings.EqualFold(parsed.Hostname(), amdKDSHost) {
		return fmt.Errorf("SNP collateral URL host must be %s", amdKDSHost)
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return fmt.Errorf("SNP collateral URL port must be 443")
	}
	return nil
}

// ValidateConfig checks the module's non-negotiable verification baseline. Revocation
// checking, an explicit collateral getter and product, disabled guest debug,
// and an exact VMPL are required.
func ValidateConfig(verification *verify.Options, validation *validate.Options) error {
	if verification == nil {
		return fmt.Errorf("%w: verification options are nil", ErrInvalidConfig)
	}
	if !verification.CheckRevocations {
		return fmt.Errorf("%w: CheckRevocations must be true", ErrInvalidConfig)
	}
	if verification.Getter == nil {
		return fmt.Errorf("%w: an explicit collateral getter is required", ErrInvalidConfig)
	}
	if verification.Product == nil || !knownProduct(verification.Product.GetName()) {
		return fmt.Errorf("%w: an explicit AMD product is required", ErrInvalidConfig)
	}
	for product, roots := range verification.TrustedRoots {
		for i, root := range roots {
			if root == nil || root.ProductCerts == nil || root.ProductCerts.Ark == nil || root.ProductCerts.Ask == nil {
				return fmt.Errorf("%w: trusted root %q[%d] must contain ARK and ASK certificates", ErrInvalidConfig, product, i)
			}
		}
	}
	if validation == nil {
		return fmt.Errorf("%w: validation options are nil", ErrInvalidConfig)
	}
	if validation.GuestPolicy.Debug {
		return fmt.Errorf("%w: guest debug mode must be disabled", ErrInvalidConfig)
	}
	if validation.VMPL == nil {
		return fmt.Errorf("%w: an exact VMPL is required", ErrInvalidConfig)
	}
	if *validation.VMPL < 0 || *validation.VMPL > 3 {
		return fmt.Errorf("%w: VMPL must be in the range 0-3", ErrInvalidConfig)
	}
	if err := validateOptionLengths(validation); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	for guid, option := range validation.CertTableOptions {
		if option == nil || option.Validate == nil {
			return fmt.Errorf("%w: certificate-table option %q requires a validator", ErrInvalidConfig, guid)
		}
	}
	return nil
}

// Verify parses evidence, authenticates the report and certificate chain,
// checks revocation, forces the caller's expected REPORT_DATA into a cloned
// validation policy, and validates all report fields. Caller-owned options are
// not mutated.
func Verify(
	ctx context.Context,
	evidence []byte,
	expectedReportData []byte,
	verification *verify.Options,
	validation *validate.Options,
) (*sevsnp.Attestation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidConfig)
	}
	if err := ValidateConfig(verification, validation); err != nil {
		return nil, err
	}
	if len(expectedReportData) != abi.ReportDataSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrBinding, abi.ReportDataSize, len(expectedReportData))
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}

	attestation, err := Parse(evidence)
	if err != nil {
		return nil, err
	}
	verificationCopy := cloneVerificationOptions(verification)
	validationCopy := cloneValidationOptions(validation)
	validationCopy.ReportData = append([]byte(nil), expectedReportData...)

	if err := verify.SnpAttestationContext(ctx, attestation, verificationCopy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerification, err)
	}
	if subtle.ConstantTimeCompare(attestation.GetReport().GetReportData(), expectedReportData) != 1 {
		return nil, ErrBinding
	}
	if err := validate.SnpAttestation(attestation, validationCopy); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	return attestation, nil
}

func validateReportShape(report *sevsnp.Report) error {
	raw, err := abi.ReportToAbiBytes(report)
	if err != nil {
		return err
	}
	return abi.ValidateReportFormat(raw)
}

func knownProduct(product sevsnp.SevProduct_SevProductName) bool {
	switch product {
	case sevsnp.SevProduct_SEV_PRODUCT_MILAN,
		sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		sevsnp.SevProduct_SEV_PRODUCT_TURIN:
		return true
	default:
		return false
	}
}

func validateOptionLengths(options *validate.Options) error {
	checks := []struct {
		name string
		want int
		got  []byte
	}{
		{name: "family ID", want: abi.FamilyIDSize, got: options.FamilyID},
		{name: "image ID", want: abi.ImageIDSize, got: options.ImageID},
		{name: "REPORT_DATA", want: abi.ReportDataSize, got: options.ReportData},
		{name: "measurement", want: abi.MeasurementSize, got: options.Measurement},
		{name: "HOST_DATA", want: abi.HostDataSize, got: options.HostData},
		{name: "report ID", want: abi.ReportIDSize, got: options.ReportID},
		{name: "report ID MA", want: abi.ReportIDMASize, got: options.ReportIDMA},
		{name: "chip ID", want: abi.ChipIDSize, got: options.ChipID},
	}
	for _, check := range checks {
		if check.got != nil && len(check.got) != check.want {
			return fmt.Errorf("%s must be %d bytes, got %d", check.name, check.want, len(check.got))
		}
	}
	return nil
}

func cloneVerificationOptions(source *verify.Options) *verify.Options {
	clone := *source
	if source.Product != nil {
		clone.Product = proto.Clone(source.Product).(*sevsnp.SevProduct)
	}
	if source.TrustedRoots != nil {
		clone.TrustedRoots = make(map[string][]*trust.AMDRootCerts, len(source.TrustedRoots))
		for product, roots := range source.TrustedRoots {
			clonedRoots := make([]*trust.AMDRootCerts, len(roots))
			for i, root := range roots {
				clonedRoots[i] = cloneRoot(root)
			}
			clone.TrustedRoots[product] = clonedRoots
		}
	}
	return &clone
}

func cloneRoot(source *trust.AMDRootCerts) *trust.AMDRootCerts {
	if source == nil {
		return nil
	}
	source.Mu.Lock()
	defer source.Mu.Unlock()
	clone := &trust.AMDRootCerts{
		Product:     source.Product,
		ProductLine: source.ProductLine,
		AskSev:      source.AskSev,
		ArkSev:      source.ArkSev,
		CRL:         source.CRL,
	}
	if source.ProductCerts != nil {
		clone.ProductCerts = &trust.ProductCerts{
			Ask:  source.ProductCerts.Ask,
			Asvk: source.ProductCerts.Asvk,
			Ark:  source.ProductCerts.Ark,
		}
	}
	return clone
}

func cloneValidationOptions(source *validate.Options) *validate.Options {
	clone := *source
	clone.ReportData = cloneBytes(source.ReportData)
	clone.HostData = cloneBytes(source.HostData)
	clone.ImageID = cloneBytes(source.ImageID)
	clone.FamilyID = cloneBytes(source.FamilyID)
	clone.ReportID = cloneBytes(source.ReportID)
	clone.ReportIDMA = cloneBytes(source.ReportIDMA)
	clone.Measurement = cloneBytes(source.Measurement)
	clone.ChipID = cloneBytes(source.ChipID)
	clone.TrustedAuthorKeyHashes = cloneByteSlices(source.TrustedAuthorKeyHashes)
	clone.TrustedIDKeyHashes = cloneByteSlices(source.TrustedIDKeyHashes)
	clone.TrustedAuthorKeys = append([]*x509.Certificate(nil), source.TrustedAuthorKeys...)
	clone.TrustedIDKeys = append([]*x509.Certificate(nil), source.TrustedIDKeys...)
	if source.PlatformInfo != nil {
		platformInfo := *source.PlatformInfo
		clone.PlatformInfo = &platformInfo
	}
	if source.VMPL != nil {
		vmpl := *source.VMPL
		clone.VMPL = &vmpl
	}
	if source.CertTableOptions != nil {
		clone.CertTableOptions = make(map[string]*validate.CertEntryOption, len(source.CertTableOptions))
		for guid, option := range source.CertTableOptions {
			if option == nil {
				clone.CertTableOptions[guid] = nil
				continue
			}
			optionCopy := *option
			clone.CertTableOptions[guid] = &optionCopy
		}
	}
	return &clone
}

func cloneBytes(source []byte) []byte {
	if source == nil {
		return nil
	}
	return append([]byte(nil), source...)
}

func cloneByteSlices(source [][]byte) [][]byte {
	if source == nil {
		return nil
	}
	clone := make([][]byte, len(source))
	for i := range source {
		clone[i] = cloneBytes(source[i])
	}
	return clone
}
