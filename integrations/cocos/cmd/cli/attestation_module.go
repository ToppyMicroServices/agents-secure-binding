// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/integrations/cocos/platformmodule"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
)

type attestationModuleConfig struct {
	Name                     string
	PlatformPolicyPath       string
	EATVerificationKeyPath   string
	CoRIMVerificationKeyPath string
	ExpectedEATIssuer        string
}

func loadAttestationVerifierConfig(module attestationModuleConfig, corimPolicyPath string) (platformmodule.VerifierConfig, error) {
	platform := platformmodule.Platform(strings.TrimSpace(module.Name))
	if !supportedLocalPlatform(platform) {
		return platformmodule.VerifierConfig{}, fmt.Errorf("%w: %q", platformmodule.ErrUnsupportedPlatform, platform)
	}
	verificationKey, err := eat.LoadVerificationKey(strings.TrimSpace(module.EATVerificationKeyPath))
	if err != nil {
		return platformmodule.VerifierConfig{}, fmt.Errorf("load EAT verification key: %w", err)
	}
	config := platformmodule.VerifierConfig{
		Platform:           platform,
		PolicyPath:         strings.TrimSpace(corimPolicyPath),
		EATVerificationKey: verificationKey,
		ExpectedIssuer:     strings.TrimSpace(module.ExpectedEATIssuer),
	}
	if path := strings.TrimSpace(module.CoRIMVerificationKeyPath); path != "" {
		corimKey, err := eat.LoadVerificationKey(path)
		if err != nil {
			return platformmodule.VerifierConfig{}, fmt.Errorf("load CoRIM verification key: %w", err)
		}
		config.CoRIMVerificationKey = corimKey
	}

	switch platform {
	case platformmodule.PlatformSNP:
		verification, validation, err := platformmodule.LoadSNPPlatformPolicy(module.PlatformPolicyPath)
		if err != nil {
			return platformmodule.VerifierConfig{}, err
		}
		config.SNPVerificationOptions = verification
		config.SNPValidationOptions = validation
	case platformmodule.PlatformTDX:
		policy, err := platformmodule.LoadTDXPlatformPolicy(module.PlatformPolicyPath)
		if err != nil {
			return platformmodule.VerifierConfig{}, err
		}
		config.TDXPolicy = policy
	}

	return config, nil
}

func supportedLocalPlatform(platform platformmodule.Platform) bool {
	switch platform {
	case platformmodule.PlatformSNP, platformmodule.PlatformTDX:
		return true
	default:
		return false
	}
}
