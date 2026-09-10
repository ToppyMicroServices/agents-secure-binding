// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay"
	relayasb "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/humanrelay/asbbinding"
	taskasb "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/taskcoord/asbbinding"
	"github.com/golang-jwt/jwt/v5"
)

const (
	debugAudience        = "asb:debug-simple"
	debugManagerKeyID    = "debug-manager-key"
	debugActorKeyID      = "debug-actor-key"
	debugManagerKey      = "debug-simple-manager-key-not-for-production"
	debugActorKey        = "debug-simple-actor-key-not-for-production"
	humanAuthorityIssuer = "debug-human-operation-authority"
	humanGatewayIssuer   = "debug-human-gateway"
	relayAuthorityIssuer = "debug-agent-relay-authority"
	relayGatewayIssuer   = "debug-agent-gateway"
)

type signedEvidence struct {
	grantJWT          string
	sessionBindingJWT string
	options           clients.SessionIdentityJWTOptions
}

func newHumanEvidence(
	now time.Time,
	digest taskasb.Digest,
	authorizationID string,
	proofID string,
	nonce string,
) (taskasb.Evidence, error) {
	signed, err := newSignedEvidence(
		now,
		humanAuthorityIssuer,
		humanGatewayIssuer,
		humanGatewayID,
		taskasb.AuthorizationDetail(digest),
		taskasb.RequestContextSHA256(digest),
		authorizationID,
		proofID,
		nonce,
	)
	if err != nil {
		return taskasb.Evidence{}, err
	}
	return taskasb.Evidence{
		GrantJWT:          signed.grantJWT,
		SessionBindingJWT: signed.sessionBindingJWT,
		Options:           signed.options,
		AcceptedUntil:     now.Add(90 * time.Second),
	}, nil
}

func newRelayEvidence(
	now time.Time,
	digest humanrelay.Digest,
	authorizationID string,
	proofID string,
	nonce string,
) (relayasb.Evidence, error) {
	signed, err := newSignedEvidence(
		now,
		relayAuthorityIssuer,
		relayGatewayIssuer,
		plannerActorID,
		relayasb.AuthorizationDetail(digest),
		relayasb.RequestContextSHA256(digest),
		authorizationID,
		proofID,
		nonce,
	)
	if err != nil {
		return relayasb.Evidence{}, err
	}
	return relayasb.Evidence{
		GrantJWT:          signed.grantJWT,
		SessionBindingJWT: signed.sessionBindingJWT,
		Options:           signed.options,
		AcceptedUntil:     now.Add(90 * time.Second),
	}, nil
}

func newSignedEvidence(
	now time.Time,
	authorityIssuer string,
	sessionIssuer string,
	actorID string,
	authorizationDetail string,
	requestContextHash string,
	authorizationID string,
	proofID string,
	nonce string,
) (signedEvidence, error) {
	managerKey := []byte(debugManagerKey)
	actorKey := []byte(debugActorKey)
	grant, err := signDebugJWT(debugManagerKeyID, managerKey, jwt.MapClaims{
		"iss":                   authorityIssuer,
		"sub":                   actorID,
		"aud":                   debugAudience,
		"jti":                   authorizationID,
		"iat":                   now.Add(-2 * time.Minute).Unix(),
		"exp":                   now.Add(5 * time.Minute).Unix(),
		"profile_type":          clients.TokenTypeIdentityGrant,
		"profile_version":       clients.ProfileVersion,
		"cnf":                   map[string]any{"kid": debugActorKeyID},
		"authorization_details": []string{authorizationDetail},
	})
	if err != nil {
		return signedEvidence{}, err
	}
	binding := identitypolicy.Binding{
		LeafPublicKeySHA256:  digestHex("debug-simple-leaf-public-key"),
		TLSExporterSHA256:    digestHex("debug-simple-tls-exporter"),
		RequestContextSHA256: requestContextHash,
		Nonce:                nonce,
	}
	statement, err := signDebugJWT(debugActorKeyID, actorKey, jwt.MapClaims{
		"iss":                    sessionIssuer,
		"aud":                    debugAudience,
		"jti":                    proofID,
		"iat":                    now.Add(-time.Minute).Unix(),
		"exp":                    now.Add(2 * time.Minute).Unix(),
		"profile_type":           clients.TokenTypeSessionBinding,
		"profile_version":        clients.ProfileVersion,
		"grant_hash":             clients.IdentityGrantHash(grant),
		"leaf_public_key_sha256": binding.LeafPublicKeySHA256,
		"tls_exporter_sha256":    binding.TLSExporterSHA256,
		"request_context_sha256": binding.RequestContextSHA256,
		"nonce":                  nonce,
	})
	if err != nil {
		return signedEvidence{}, err
	}
	return signedEvidence{
		grantJWT:          grant,
		sessionBindingJWT: statement,
		options: clients.SessionIdentityJWTOptions{
			Grant: clients.JWTVerifyOptions{
				ExpectedIssuer:   authorityIssuer,
				ExpectedAudience: debugAudience,
				ValidMethods:     []string{"HS256"},
				LocalKeys:        []clients.LocalKey{{KeyID: debugManagerKeyID, Key: managerKey}},
			},
			SessionBinding: clients.JWTVerifyOptions{
				ExpectedIssuer:   sessionIssuer,
				ExpectedAudience: debugAudience,
				ValidMethods:     []string{"HS256"},
				LocalKeys:        []clients.LocalKey{{KeyID: debugActorKeyID, Key: actorKey}},
			},
			ExpectedBinding: binding,
			ReplayCache: identitypolicy.NewMemoryReplayCacheWithClock(
				func() time.Time { return now },
			),
		},
	}, nil
}

func signDebugJWT(keyID string, key []byte, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = keyID
	return token.SignedString(key)
}
