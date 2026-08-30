// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	tdxtestdata "github.com/google/go-tdx-guest/testing/testdata"
	tdxvalidate "github.com/google/go-tdx-guest/validate"
	tdxverify "github.com/google/go-tdx-guest/verify"
)

type rejectingGetter struct{}

func (rejectingGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	return nil, nil, fmt.Errorf("offline: %s", rawURL)
}

type validatingFixtureGetter struct {
	requested []string
}

func (g *validatingFixtureGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if err := validatePCSURL(parsed); err != nil {
		return nil, nil, err
	}
	g.requested = append(g.requested, rawURL)
	return tdxtesting.TestGetter.Get(rawURL)
}

func productionTestPolicy() *checkconfig.Config {
	return &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{CheckCrl: true, GetCollateral: true},
		Policy: &checkconfig.Policy{
			HeaderPolicy: &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{
				TdAttributes: make([]byte, abi.TdAttributesSize),
			},
		},
	}
}

func TestParseQuoteAndRejectBindingMismatch(t *testing.T) {
	quote, err := ParseQuote(tdxtestdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), quote.GetTdQuoteBody().GetReportData()...)
	expected[0] ^= 0xff
	err = Verify(context.Background(), tdxtestdata.RawQuote, expected, productionTestPolicy(), &RuntimeOptions{Getter: rejectingGetter{}})
	if !errors.Is(err, ErrBinding) {
		t.Fatalf("Verify() error = %v, want ErrBinding", err)
	}
}

func TestValidateConfigFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*checkconfig.Config)
	}{
		{name: "nil", mutate: func(*checkconfig.Config) {}},
		{name: "no CRL", mutate: func(p *checkconfig.Config) { p.RootOfTrust.CheckCrl = false }},
		{name: "no collateral", mutate: func(p *checkconfig.Config) { p.RootOfTrust.GetCollateral = false }},
		{name: "no attributes", mutate: func(p *checkconfig.Config) { p.Policy.TdQuoteBodyPolicy.TdAttributes = nil }},
		{name: "debug", mutate: func(p *checkconfig.Config) { p.Policy.TdQuoteBodyPolicy.TdAttributes[0] = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "nil" {
				if !errors.Is(ValidateConfig(nil), ErrPolicyRequired) {
					t.Fatal("nil policy was accepted")
				}
				return
			}
			policy := productionTestPolicy()
			tc.mutate(policy)
			if !errors.Is(ValidateConfig(policy), ErrPolicyRequired) {
				t.Fatalf("ValidateConfig() accepted %s", tc.name)
			}
		})
	}
}

func TestVerifyReachesCryptographicCollateralStage(t *testing.T) {
	quote, err := ParseQuote(tdxtestdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	expected := quote.GetTdQuoteBody().GetReportData()
	err = Verify(context.Background(), tdxtestdata.RawQuote, expected, productionTestPolicy(), &RuntimeOptions{Getter: rejectingGetter{}})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify() error = %v, want ErrVerification", err)
	}
}

func TestPinnedQuotePassesCryptographicAndLocalPolicyStages(t *testing.T) {
	quote, err := ParseQuote(tdxtestdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	fixtureTime := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	if err := tdxverify.TdxQuote(quote, &tdxverify.Options{
		CheckRevocations: false,
		GetCollateral:    false,
		Now:              fixtureTime,
	}); err != nil {
		t.Fatalf("fixture quote cryptographic verification failed: %v", err)
	}

	policy := productionTestPolicy()
	policy.Policy.TdQuoteBodyPolicy.TdAttributes = append([]byte(nil), quote.GetTdQuoteBody().GetTdAttributes()...)
	validation, err := tdxvalidate.PolicyToOptions(policy.Policy)
	if err != nil {
		t.Fatal(err)
	}
	validation.TdQuoteBodyOptions.ReportData = append([]byte(nil), quote.GetTdQuoteBody().GetReportData()...)
	if err := tdxvalidate.TdxQuote(quote, validation); err != nil {
		t.Fatalf("fixture quote local-policy validation failed: %v", err)
	}
}

func TestPinnedCollateralFailsAtTCBMatchRatherThanTransport(t *testing.T) {
	quote, err := ParseQuote(tdxtestdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	fixtureTime := time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	policy := productionTestPolicy()
	policy.Policy.TdQuoteBodyPolicy.TdAttributes = append([]byte(nil), quote.GetTdQuoteBody().GetTdAttributes()...)
	getter := &validatingFixtureGetter{}
	err = Verify(
		context.Background(),
		tdxtestdata.RawQuote,
		quote.GetTdQuoteBody().GetReportData(),
		policy,
		&RuntimeOptions{Getter: getter, Now: fixtureTime},
	)
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "no matching TCB") {
		t.Fatalf("Verify() error = %v, want deterministic TCB mismatch", err)
	}
	wantURLs := map[string]bool{
		"https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity":                     false,
		"https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000":          false,
		"https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der": false,
		"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der":                          false,
	}
	for _, rawURL := range getter.requested {
		if _, ok := wantURLs[rawURL]; !ok {
			t.Fatalf("unexpected collateral URL %q", rawURL)
		}
		wantURLs[rawURL] = true
	}
	for rawURL, requested := range wantURLs {
		if !requested {
			t.Errorf("collateral URL was not requested: %s", rawURL)
		}
	}
}

func TestValidatePCSURLRestrictions(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "PCS API", rawURL: "https://api.trustedservices.intel.com/tdx/certification/v4/tcb"},
		{name: "root CRL", rawURL: "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"},
		{name: "PCS API explicit HTTPS port", rawURL: "https://api.trustedservices.intel.com:443/tdx/certification/v4/tcb"},
		{name: "non HTTPS", rawURL: "http://api.trustedservices.intel.com/tdx/certification/v4/tcb", wantErr: true},
		{name: "arbitrary host", rawURL: "https://example.test/collateral", wantErr: true},
		{name: "PCS lookalike", rawURL: "https://api.trustedservices.intel.com.example.test/collateral", wantErr: true},
		{name: "certificate lookalike", rawURL: "https://certificates.trustedservices.intel.com.example.test/collateral", wantErr: true},
		{name: "PCS API wrong port", rawURL: "https://api.trustedservices.intel.com:444/collateral", wantErr: true},
		{name: "certificate host wrong port", rawURL: "https://certificates.trustedservices.intel.com:444/IntelSGXRootCA.der", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePCSURL(mustURL(t, tc.rawURL))
			if (err != nil) != tc.wantErr {
				t.Fatalf("validatePCSURL(%q) error = %v, wantErr %v", tc.rawURL, err, tc.wantErr)
			}
		})
	}
}

func TestRetryGetterAppliesURLRestrictionsBeforeNetwork(t *testing.T) {
	getter := newRetryHTTPSGetter(context.Background())
	for _, rawURL := range []string{
		"http://api.trustedservices.intel.com/tdx/certification/v4/tcb",
		"https://example.test/collateral",
		"https://api.trustedservices.intel.com.example.test/collateral",
		"https://certificates.trustedservices.intel.com:444/IntelSGXRootCA.der",
	} {
		if _, _, err := getter.Get(rawURL); err == nil {
			t.Errorf("retry getter accepted disallowed URL %q", rawURL)
		}
	}
}

func TestRetryGetterRevalidatesRedirects(t *testing.T) {
	getter, ok := newRetryHTTPSGetter(context.Background()).(*retryHTTPSGetter)
	if !ok {
		t.Fatal("newRetryHTTPSGetter returned an unexpected implementation")
	}
	for _, tc := range []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "Intel root CRL", rawURL: "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"},
		{name: "external host", rawURL: "https://example.test/collateral", wantErr: true},
		{name: "HTTPS downgrade", rawURL: "http://api.trustedservices.intel.com/collateral", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, tc.rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = getter.client.CheckRedirect(request, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckRedirect(%q) error = %v, wantErr %v", tc.rawURL, err, tc.wantErr)
			}
		})
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
