// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"context"
	"errors"
	"fmt"
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
	err = Verify(
		context.Background(),
		tdxtestdata.RawQuote,
		quote.GetTdQuoteBody().GetReportData(),
		policy,
		&RuntimeOptions{Getter: tdxtesting.TestGetter, Now: fixtureTime},
	)
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "no matching TCB") {
		t.Fatalf("Verify() error = %v, want deterministic TCB mismatch", err)
	}
}

func TestRetryGetterRejectsNonHTTPS(t *testing.T) {
	getter := newRetryHTTPSGetter(context.Background())
	if _, _, err := getter.Get("http://example.test/collateral"); err == nil {
		t.Fatal("non-HTTPS collateral URL was accepted")
	}
	if _, _, err := getter.Get("https://example.test/collateral"); err == nil {
		t.Fatal("non-Intel collateral host was accepted")
	}
	if err := validatePCSURL(mustURL(t, "https://api.trustedservices.intel.com/tdx/certification/v4/tcb")); err != nil {
		t.Fatalf("Intel PCS URL rejected: %v", err)
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
