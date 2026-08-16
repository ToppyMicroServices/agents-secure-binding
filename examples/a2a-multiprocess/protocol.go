// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/ea"
	eaattestation "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/eaattestation"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/golang-jwt/jwt/v5"
)

func canonicalRequestContext(request a2aSendMessageRequest) ([]byte, error) {
	copyRequest := request
	copyRequest.Message.Metadata = make(map[string]json.RawMessage)
	for key, value := range request.Message.Metadata {
		if key == securityBindingExtension || key == attestationResultExtension {
			continue
		}
		copyRequest.Message.Metadata[key] = append(json.RawMessage(nil), value...)
	}
	if len(copyRequest.Message.Metadata) == 0 {
		copyRequest.Message.Metadata = nil
	}
	payload, err := json.Marshal(copyRequest)
	if err != nil {
		return nil, fmt.Errorf("canonicalize A2A request: %w", err)
	}
	contextValue := make([]byte, 0, len(payload)+32)
	contextValue = append(contextValue, "A2A/1.0\nPOST\n/message:send\n"...)
	return append(contextValue, payload...), nil
}

func deriveAcceptedBinding(state *tls.ConnectionState, contextValue []byte, leaf *x509.Certificate) (identitypolicy.Binding, []byte, error) {
	base, err := atls.IdentityBindingFromConnectionState(state, &ea.ValidationResult{
		Context: contextValue,
		Chain:   []*x509.Certificate{leaf},
	})
	if err != nil {
		return identitypolicy.Binding{}, nil, fmt.Errorf("derive accepted identity binding: %w", err)
	}
	_, _, binder, err := eaattestation.ComputeBinding(state, eaattestation.ExporterLabelAttestation, contextValue, leaf)
	if err != nil {
		return identitypolicy.Binding{}, nil, fmt.Errorf("derive attestation binder: %w", err)
	}
	base.AttestationBinderSHA256 = sha256String(binder)
	return base, binder, nil
}

func parseAttestationResult(token string, key any) (*attestationResultClaims, error) {
	claims := &attestationResultClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["kid"] != demoVerifierKeyID {
			return nil, fmt.Errorf("unexpected attestation result signer")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}), jwt.WithIssuer(demoVerifierIssuer), jwt.WithAudience(demoAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("verify attestation result: %w", err)
	}
	if claims.ProfileType != "sbaip.attestation-result" || claims.Subject != demoAgentIssuer || claims.ID == "" {
		return nil, fmt.Errorf("unexpected attestation result profile")
	}
	return claims, nil
}

func receiverPolicy() identitypolicy.Policy {
	return identitypolicy.Policy{
		Mode: identitypolicy.ModeRequired, SetMode: identitypolicy.SetModeExact,
		Require: identitypolicy.Requirements{L3: true, L4: true, L5: true, L6: true},
		Expected: identitypolicy.Values{
			Service: demoService, Deployment: demoDeployment, Workload: demoWorkload,
			Agent: demoAgentIssuer, TaskID: demoTaskID, IntentRef: demoIntent,
			CapabilityRef: demoCapability, Scopes: []string{demoReadScope}, Resources: []string{demoResource},
		},
	}
}

func classifyVerificationError(err error) string {
	if errors.Is(err, identitypolicy.ErrReplayDetected) {
		return "replay-detected"
	}
	if errors.Is(err, jwt.ErrTokenInvalidAudience) {
		return "audience-mismatch"
	}
	var validationErrs identitypolicy.ValidationErrors
	if errors.As(err, &validationErrs) {
		if validationErrs.Has("binding", identitypolicy.FieldTLSExporterHash, identitypolicy.ErrMismatch) ||
			validationErrs.Has("binding", identitypolicy.FieldLeafPublicKeyHash, identitypolicy.ErrMismatch) ||
			validationErrs.Has("binding", identitypolicy.FieldRequestContextHash, identitypolicy.ErrMismatch) ||
			validationErrs.Has("binding", identitypolicy.FieldAttestationBinderHash, identitypolicy.ErrMismatch) {
			return "session-binding-mismatch"
		}
		for _, layer := range []string{identitypolicy.LayerL3, identitypolicy.LayerL4, identitypolicy.LayerL5, identitypolicy.LayerL6} {
			if len(validationErrs.ByLayer(layer)) > 0 {
				return "policy-mismatch"
			}
		}
	}
	return "profile-rejected"
}

func hasExactExtensions(values []string) bool {
	if len(values) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	return seen[securityBindingExtension] && seen[attestationResultExtension]
}

func taskOperationAndResource(message a2aMessage) (string, string, error) {
	if len(message.Parts) != 1 {
		return "", "", fmt.Errorf("exactly one task part is required")
	}
	operation := strings.TrimSpace(message.Parts[0].Metadata["operation"])
	resource := strings.TrimSpace(message.Parts[0].Metadata["resource"])
	if operation == "" || resource == "" {
		return "", "", fmt.Errorf("task operation and resource metadata are required")
	}
	return operation, resource, nil
}
