// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/eat"
)

func configuredEATSigningKey(path string) (*ecdsa.PrivateKey, error) {
	if path = strings.TrimSpace(path); path != "" {
		return eat.LoadSigningKey(path)
	}
	return eat.GenerateSigningKey()
}
