// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package tdx verifies Intel TDX QuoteV4 evidence independently from the ASB
// protocol implementation. ASB supplies the expected session REPORT_DATA and
// treats the returned error as the module appraisal result.
package tdx

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
	tdxverify "github.com/google/go-tdx-guest/verify"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
	"google.golang.org/protobuf/proto"
)

var (
	ErrPolicyRequired = errors.New("tdx module: strict verification policy is required")
	ErrInvalidQuote   = errors.New("tdx module: invalid QuoteV4 evidence")
	ErrBinding        = errors.New("tdx module: REPORT_DATA does not match ASB session binding")
	ErrVerification   = errors.New("tdx module: quote, certificate, collateral, or revocation verification failed")
	ErrValidation     = errors.New("tdx module: quote policy validation failed")
)

const (
	defaultCollateralTimeout  = 2 * time.Minute
	defaultMaxRetryDelay      = 30 * time.Second
	defaultHTTPRequestTimeout = 20 * time.Second
	maxCollateralBytes        = 16 << 20
	tdxDebugAttribute         = uint64(1)
	intelPCSAPIHost           = "api.trustedservices.intel.com"
	intelPCSCertificatesHost  = "certificates.trustedservices.intel.com"
)

// RuntimeOptions permits deterministic collateral injection in tests and
// deployments with a reviewed local collateral service. Nil uses a bounded
// HTTPS-only getter.
type RuntimeOptions struct {
	Getter tdxtrust.HTTPSGetter
	Now    time.Time
}

// ValidateConfig enforces the strict verification baseline before evidence is accepted.
func ValidateConfig(policy *checkconfig.Config) error {
	if policy == nil || policy.RootOfTrust == nil || policy.Policy == nil ||
		policy.Policy.HeaderPolicy == nil || policy.Policy.TdQuoteBodyPolicy == nil {
		return ErrPolicyRequired
	}
	if !policy.RootOfTrust.CheckCrl {
		return fmt.Errorf("%w: check_crl must be true", ErrPolicyRequired)
	}
	if !policy.RootOfTrust.GetCollateral {
		return fmt.Errorf("%w: get_collateral must be true", ErrPolicyRequired)
	}
	attributes := policy.Policy.TdQuoteBodyPolicy.TdAttributes
	if len(attributes) != abi.TdAttributesSize {
		return fmt.Errorf("%w: exact 8-byte td_attributes is required", ErrPolicyRequired)
	}
	if binary.LittleEndian.Uint64(attributes)&tdxDebugAttribute != 0 {
		return fmt.Errorf("%w: TD debug mode must be disabled", ErrPolicyRequired)
	}
	return nil
}

// ParseQuote parses raw evidence and rejects every format other than QuoteV4.
func ParseQuote(evidence []byte) (*tdxpb.QuoteV4, error) {
	quote, err := abi.QuoteToProto(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidQuote, err)
	}
	quoteV4, ok := quote.(*tdxpb.QuoteV4)
	if !ok || quoteV4.GetTdQuoteBody() == nil {
		return nil, fmt.Errorf("%w: unsupported quote type %T", ErrInvalidQuote, quote)
	}
	return quoteV4, nil
}

// Verify authenticates the quote and collateral, forces ASB's dynamic
// REPORT_DATA into the local validation policy, and rejects debug-enabled TDs.
func Verify(ctx context.Context, evidence, expectedReportData []byte, policy *checkconfig.Config, runtime *RuntimeOptions) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrPolicyRequired)
	}
	if err := ValidateConfig(policy); err != nil {
		return err
	}
	if len(expectedReportData) != abi.ReportDataSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrBinding, abi.ReportDataSize, len(expectedReportData))
	}
	quote, err := ParseQuote(evidence)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(quote.GetTdQuoteBody().GetReportData(), expectedReportData) != 1 {
		return ErrBinding
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrVerification, err)
	}

	policyCopy := proto.Clone(policy).(*checkconfig.Config)
	verification, err := tdxverify.RootOfTrustToOptions(policyCopy.RootOfTrust)
	if err != nil {
		return fmt.Errorf("%w: root of trust: %v", ErrPolicyRequired, err)
	}
	if runtime != nil && runtime.Getter != nil {
		verification.Getter = runtime.Getter
	} else {
		verification.Getter = newRetryHTTPSGetter(ctx)
	}
	if runtime != nil && !runtime.Now.IsZero() {
		verification.Now = runtime.Now
	} else {
		verification.Now = time.Now()
	}
	if err := tdxverify.TdxQuote(quote, verification); err != nil {
		return fmt.Errorf("%w: %v", ErrVerification, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrVerification, err)
	}

	validation, err := tdxvalidate.PolicyToOptions(policyCopy.Policy)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyRequired, err)
	}
	validation.TdQuoteBodyOptions.ReportData = append([]byte(nil), expectedReportData...)
	if err := tdxvalidate.TdxQuote(quote, validation); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	return nil
}

type retryHTTPSGetter struct {
	ctx           context.Context
	client        *http.Client
	timeout       time.Duration
	maxRetryDelay time.Duration
}

func newRetryHTTPSGetter(ctx context.Context) tdxtrust.HTTPSGetter {
	client := &http.Client{
		Timeout: defaultHTTPRequestTimeout,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			if err := validatePCSURL(request.URL); err != nil {
				return fmt.Errorf("TDX collateral redirect rejected: %w", err)
			}
			return nil
		},
	}
	return &retryHTTPSGetter{
		ctx:           ctx,
		client:        client,
		timeout:       defaultCollateralTimeout,
		maxRetryDelay: defaultMaxRetryDelay,
	}
}

func (g *retryHTTPSGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid TDX collateral URL: %w", err)
	}
	if err := validatePCSURL(parsed); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(g.ctx, g.timeout)
	defer cancel()
	delay := 2 * time.Second
	var lastErr error
	for {
		headers, body, err := g.getOnce(ctx, parsed)
		if err == nil {
			return headers, body, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("TDX collateral fetch failed: %w", errors.Join(lastErr, ctx.Err()))
		case <-time.After(delay):
		}
		delay *= 2
		if delay > g.maxRetryDelay {
			delay = g.maxRetryDelay
		}
	}
}

func validatePCSURL(parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("TDX collateral URL must use HTTPS")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != intelPCSAPIHost && host != intelPCSCertificatesHost {
		return fmt.Errorf("TDX collateral URL host is not an approved Intel PCS origin")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return fmt.Errorf("TDX collateral URL port must be 443")
	}
	return nil
}

func (g *retryHTTPSGetter) getOnce(ctx context.Context, parsed *url.URL) (map[string][]string, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := g.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, fmt.Errorf("failed to retrieve %s, status code received %d", parsed.Redacted(), response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCollateralBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxCollateralBytes {
		return nil, nil, fmt.Errorf("TDX collateral response exceeds %d bytes", maxCollateralBytes)
	}
	return response.Header, body, nil
}
