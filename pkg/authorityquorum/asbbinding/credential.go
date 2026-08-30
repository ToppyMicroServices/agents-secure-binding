// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package asbbinding

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
)

const principalDigestDomain = "ASB-AUTHORITY-QUORUM-PRINCIPAL-v1"

type verificationKeyCapture struct {
	keyID  string
	digest string
}

func captureVerificationKey(options clients.JWTVerifyOptions) (clients.JWTVerifyOptions, *verificationKeyCapture) {
	capture := &verificationKeyCapture{}
	if options.KeyFunc == nil {
		return options, capture
	}
	original := options.KeyFunc
	options.KeyFunc = func(keyID string) (interface{}, error) {
		key, err := original(keyID)
		if err != nil {
			return nil, err
		}
		digest, err := VerificationKeyDigest(key)
		if err != nil {
			return nil, err
		}
		if capture.keyID != "" && (capture.keyID != keyID || capture.digest != digest) {
			return nil, errors.New("authorityquorum asbbinding: verification key changed during verification")
		}
		capture.keyID, capture.digest = keyID, digest
		return key, nil
	}
	return options, capture
}

func (c *verificationKeyCapture) finish(options clients.JWTVerifyOptions, keyID string) (string, error) {
	if options.KeyFunc != nil {
		if c == nil || c.keyID != keyID || !validCredentialDigest(c.digest) {
			return "", errors.New("authorityquorum asbbinding: verification key was not captured")
		}
		return c.digest, nil
	}
	for _, localKey := range options.LocalKeys {
		if strings.TrimSpace(localKey.KeyID) != keyID {
			continue
		}
		digest, err := VerificationKeyDigest(localKey.Key)
		if err != nil {
			return "", err
		}
		return digest, nil
	}
	return "", errors.New("authorityquorum asbbinding: verified key is not locally available")
}

// VerificationKeyDigest returns the credential fingerprint used by
// StaticAuthorityResolver. Pass the same verification-key object configured in
// clients.JWTVerifyOptions; private keys are reduced to their public key.
func VerificationKeyDigest(key interface{}) (string, error) {
	var kind string
	var material []byte
	switch typed := key.(type) {
	case []byte:
		if len(typed) == 0 {
			return "", errors.New("authorityquorum asbbinding: empty symmetric verification key")
		}
		kind = "symmetric"
		material = typed
	default:
		if signer, ok := key.(crypto.Signer); ok {
			key = signer.Public()
		}
		encoded, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", fmt.Errorf("authorityquorum asbbinding: fingerprint verification key: %w", err)
		}
		kind = "spki"
		material = encoded
	}
	return stableDigest("ASB-AUTHORITY-QUORUM-CREDENTIAL-v1", []byte(kind), material), nil
}

func verifiedPrincipalDigest(grantIssuer, actorID string) string {
	return stableDigest(principalDigestDomain, []byte(grantIssuer), []byte(actorID))
}

func stableDigest(domain string, values ...[]byte) string {
	var buffer bytes.Buffer
	buffer.WriteString(domain)
	buffer.WriteByte(0)
	for _, value := range values {
		_ = binary.Write(&buffer, binary.BigEndian, uint32(len(value)))
		buffer.Write(value)
	}
	digest := sha256.Sum256(buffer.Bytes())
	return "sha256:" + hex.EncodeToString(digest[:])
}
