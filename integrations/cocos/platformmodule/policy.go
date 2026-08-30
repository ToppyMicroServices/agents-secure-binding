// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package platformmodule

import (
	"fmt"
	"os"
	"strings"

	snpmodule "github.com/ToppyMicroServices/agents-secure-binding/modules/attestation/snp"
	sevcheck "github.com/google/go-sev-guest/proto/check"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	tdxcheck "github.com/google/go-tdx-guest/proto/checkconfig"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// LoadSNPPlatformPolicy loads the go-sev-guest check.Config JSON used for
// signature, revocation, TCB, debug, VMPL, and other report validation.
func LoadSNPPlatformPolicy(path string) (*sevverify.Options, *sevvalidate.Options, error) {
	var policy sevcheck.Config
	if err := readPlatformPolicy(path, &policy); err != nil {
		return nil, nil, fmt.Errorf("load SNP platform policy: %w", err)
	}
	if policy.RootOfTrust == nil || policy.Policy == nil {
		return nil, nil, fmt.Errorf("load SNP platform policy: root_of_trust and policy are required")
	}
	if policy.RootOfTrust.CheckCrl && policy.RootOfTrust.DisallowNetwork {
		return nil, nil, fmt.Errorf("load SNP platform policy: check_crl and disallow_network cannot both be true")
	}
	verification, err := sevverify.RootOfTrustToOptions(policy.RootOfTrust)
	if err != nil {
		return nil, nil, fmt.Errorf("load SNP root of trust: %w", err)
	}
	verification.Product = policy.Policy.Product
	verification.Getter = snpmodule.NewKDSGetter()
	validation, err := sevvalidate.PolicyToOptions(policy.Policy)
	if err != nil {
		return nil, nil, fmt.Errorf("load SNP validation policy: %w", err)
	}
	return verification, validation, nil
}

// LoadTDXPlatformPolicy loads the go-tdx-guest checkconfig.Config JSON used
// for quote, PCS collateral, TCB, debug, and report-field validation.
func LoadTDXPlatformPolicy(path string) (*tdxcheck.Config, error) {
	var policy tdxcheck.Config
	if err := readPlatformPolicy(path, &policy); err != nil {
		return nil, fmt.Errorf("load TDX platform policy: %w", err)
	}
	return &policy, nil
}

func readPlatformPolicy(path string, destination proto.Message) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("platform policy path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("platform policy is not a regular file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(payload, destination); err != nil {
		return err
	}
	return nil
}
