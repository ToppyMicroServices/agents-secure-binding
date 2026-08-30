// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package tdx

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/internal/errors"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	valdatetdx "github.com/google/go-tdx-guest/validate"
	verifytdx "github.com/google/go-tdx-guest/verify"
	trusttdx "github.com/google/go-tdx-guest/verify/trust"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"github.com/veraison/swid"
	"google.golang.org/protobuf/encoding/protojson"
)

var errOpenTDXDevice = errors.New("failed to open TDX device")

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

var (
	timeout            = time.Minute * 2
	maxTryDelay        = time.Second * 30
	httpRequestTimeout = time.Second * 20
)

const maxCollateralResponseBytes = 16 << 20

type boundedHTTPSGetter struct {
	client *http.Client
}

func (g *boundedHTTPSGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, nil, fmt.Errorf("TDX collateral URL must use HTTPS")
	}
	client := g.client
	if client == nil {
		client = &http.Client{Timeout: httpRequestTimeout}
	}
	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, fmt.Errorf("failed to retrieve %s, status code received %d", parsed.Redacted(), response.StatusCode)
	}
	limited := io.LimitReader(response.Body, maxCollateralResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, err
	}
	if len(body) > maxCollateralResponseBytes {
		return nil, nil, fmt.Errorf("TDX collateral response exceeds %d bytes", maxCollateralResponseBytes)
	}
	return response.Header, body, nil
}

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return v.TeeAttestation(teeNonce)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	if teeNonce == nil {
		return nil, errors.New("tee nonce is required for TDX attestation")
	}

	if len(teeNonce) != 64 {
		return nil, fmt.Errorf("invalid tee nonce length: expected 64 bytes, got %d bytes", len(teeNonce))
	}

	quoteprovider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, errors.Wrap(err, errOpenTDXDevice)
	}

	return quoteprovider.GetRawQuote([64]byte(teeNonce))
}

func (v provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	return nil, errors.New("vTPM attestation fetch is not supported")
}

func (v provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	return nil, errors.New("Azure attestation token is not supported")
}

type verifier struct {
	Policy *checkconfig.Config
}

func NewVerifier() attestation.Verifier {
	Policy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy:      &checkconfig.Policy{HeaderPolicy: &checkconfig.HeaderPolicy{}, TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{}},
	}

	return verifier{
		Policy: Policy,
	}
}

func NewVerifierWithPolicy(policy *checkconfig.Config) attestation.Verifier {
	if policy == nil {
		return NewVerifier()
	}
	return verifier{
		Policy: policy,
	}
}

func (v verifier) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	return VerifyAttestationWithPolicy(report, teeNonce, v.Policy)
}

// VerifyAttestationWithPolicy authenticates a raw TDX quote and validates its
// fields against an explicit local policy. expectedReportData is always forced
// into the validation options so a policy file cannot omit the ASB session
// binding check.
func VerifyAttestationWithPolicy(report []byte, expectedReportData []byte, policy *checkconfig.Config) error {
	if policy == nil || policy.RootOfTrust == nil || policy.Policy == nil {
		return fmt.Errorf("tdx policy is not provided")
	}
	if len(expectedReportData) != abi.ReportDataSize {
		return fmt.Errorf("invalid TDX REPORT_DATA length: expected %d bytes, got %d", abi.ReportDataSize, len(expectedReportData))
	}

	quote, err := abi.QuoteToProto(report)
	if err != nil {
		return fmt.Errorf("failed to parse TDX quote: %w", err)
	}

	sopts, err := verifytdx.RootOfTrustToOptions(policy.RootOfTrust)
	if err != nil {
		return fmt.Errorf("failed to configure TDX root of trust: %w", err)
	}

	sopts.Getter = &trusttdx.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &boundedHTTPSGetter{},
	}

	if err := verifytdx.TdxQuote(quote, sopts); err != nil {
		return fmt.Errorf("TDX cryptographic verification failed: %w", err)
	}

	opts, err := valdatetdx.PolicyToOptions(policy.Policy)
	if err != nil {
		return fmt.Errorf("failed to configure TDX validation policy: %w", err)
	}
	opts.TdQuoteBodyOptions.ReportData = append([]byte(nil), expectedReportData...)

	if err := valdatetdx.TdxQuote(quote, opts); err != nil {
		return fmt.Errorf("TDX policy validation failed: %w", err)
	}

	return nil
}

func (v verifier) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return errors.New("VTPM attestation verification is not supported")
}

func (v verifier) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	return v.VerifTeeAttestation(report, teeNonce)
}

func (v verifier) JSONToPolicy(path string) error {
	return ReadTDXAttestationPolicy(path, v.Policy)
}

// VerifyEAT verifies an EAT token and extracts the binary report for verification.
func (v verifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	// Decode EAT token
	claims, err := eat.Decode(eatToken, nil)
	if err != nil {
		return fmt.Errorf("failed to decode EAT token: %w", err)
	}

	// Verify the embedded binary report
	return v.VerifyAttestation(claims.RawReport, teeNonce, vTpmNonce)
}

func (v verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	if manifest == nil {
		return fmt.Errorf("CoRIM manifest is nil")
	}

	quote, err := abi.QuoteToProto(report)
	if err != nil {
		return fmt.Errorf("failed to parse TDX quote for CoRIM appraisal: %w", err)
	}
	quoteV4, ok := quote.(*tdxpb.QuoteV4)
	if !ok || quoteV4.GetTdQuoteBody() == nil {
		return fmt.Errorf("unsupported TDX quote format for CoRIM appraisal")
	}
	body := quoteV4.GetTdQuoteBody()
	referenceProfiles := 0

	// Iterate over CoMIDs tags looking for measurements
	for _, tag := range manifest.Tags {
		// Expecting a CoMID tag
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		// Parse CoMID from tag value
		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID from tag: %w", err)
		}

		// Match measurements in CoMID. A successful MRTD match is not enough:
		// every supplied keyed TDX constraint must be understood and match its
		// corresponding QuoteV4 field before the manifest is accepted.
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				referenceProfiles++
				if referenceProfiles > 1 {
					return fmt.Errorf("TDX CoRIM must contain exactly one reference-value profile")
				}
				if err := rv.Measurements.Valid(); err != nil {
					return fmt.Errorf("invalid CoRIM measurements for TDX: %w", err)
				}
				seen := make(map[uint64]struct{}, len(rv.Measurements))
				for _, m := range rv.Measurements {
					if err := appraiseTDXMeasurement(m, body, seen); err != nil {
						return err
					}
				}
				if _, ok := seen[corimgen.TDXMRTDMKey]; !ok {
					return fmt.Errorf("TDX CoRIM is missing the required MRTD measurement key %d", corimgen.TDXMRTDMKey)
				}
			}
		}
	}

	if referenceProfiles == 0 {
		return fmt.Errorf("TDX CoRIM is missing the required MRTD measurement key %d", corimgen.TDXMRTDMKey)
	}

	return nil
}

func appraiseTDXMeasurement(m comid.Measurement, body *tdxpb.TDQuoteBody, seen map[uint64]struct{}) error {
	if m.Key == nil {
		return fmt.Errorf("TDX CoRIM measurement key is required")
	}
	key, err := m.Key.GetKeyUint()
	if err != nil {
		return fmt.Errorf("TDX CoRIM measurement key must be an unsigned integer: %w", err)
	}
	if _, duplicate := seen[key]; duplicate {
		return fmt.Errorf("duplicate TDX CoRIM measurement key %d", key)
	}

	expected, field, ok := tdxQuoteFieldForMeasurementKey(body, key)
	if !ok {
		return fmt.Errorf("unknown TDX CoRIM measurement key %d", key)
	}
	if m.AuthorizedBy != nil {
		return fmt.Errorf("TDX CoRIM measurement key %d contains unsupported authorized-by metadata", key)
	}
	if hasUnsupportedTDXMeasurementValue(m.Val) {
		return fmt.Errorf("TDX CoRIM measurement key %d contains unsupported measurement values", key)
	}
	if m.Val.Digests == nil || len(*m.Val.Digests) != 1 {
		return fmt.Errorf("TDX CoRIM measurement key %d must contain exactly one digest", key)
	}

	digest := (*m.Val.Digests)[0]
	if digest.HashAlgID != swid.Sha384 {
		return fmt.Errorf("TDX CoRIM measurement key %d must use SHA-384", key)
	}
	if len(digest.HashValue) != abi.MrTdSize {
		return fmt.Errorf("TDX CoRIM measurement key %d must contain a 48-byte digest", key)
	}
	if len(expected) != abi.MrTdSize {
		return fmt.Errorf("TDX quote field %s has invalid length %d", field, len(expected))
	}
	if !bytes.Equal(digest.HashValue, expected) {
		return fmt.Errorf("TDX CoRIM %s measurement does not match the quote", field)
	}

	seen[key] = struct{}{}
	return nil
}

func tdxQuoteFieldForMeasurementKey(body *tdxpb.TDQuoteBody, key uint64) ([]byte, string, bool) {
	switch key {
	case corimgen.TDXMRTDMKey:
		return body.GetMrTd(), "MRTD", true
	case corimgen.TDXMRSEAMMKey:
		return body.GetMrSeam(), "MRSEAM", true
	}
	if key >= corimgen.TDXRTMR0MKey && key < corimgen.TDXRTMR0MKey+4 {
		index := int(key - corimgen.TDXRTMR0MKey)
		rtmrs := body.GetRtmrs()
		if index >= len(rtmrs) {
			return nil, fmt.Sprintf("RTMR%d", index), true
		}
		return rtmrs[index], fmt.Sprintf("RTMR%d", index), true
	}
	return nil, "", false
}

func hasUnsupportedTDXMeasurementValue(value comid.Mval) bool {
	return value.Ver != nil ||
		value.SVN != nil ||
		value.Flags != nil ||
		value.RawValue != nil ||
		value.RawValueMask != nil ||
		value.MACAddr != nil ||
		value.IPAddr != nil ||
		value.SerialNumber != nil ||
		value.UEID != nil ||
		value.UUID != nil ||
		value.IntegrityRegisters != nil ||
		value.GetExtensions() != nil
}

func ReadTDXAttestationPolicy(policyPath string, policy *checkconfig.Config) error {
	policyByte, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}

	if err := protojson.Unmarshal(policyByte, policy); err != nil {
		return err
	}

	return nil
}
