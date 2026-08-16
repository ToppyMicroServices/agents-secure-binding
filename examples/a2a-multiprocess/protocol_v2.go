// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/identitypolicy"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/atls/sbaipv2"
	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/clients"
	"github.com/golang-jwt/jwt/v5"
)

type challengeRequestV2 struct{}

type challengeResponseV2 struct {
	VerifierNonce string `json:"verifier_nonce"`
	AttemptID     string `json:"attempt_id,omitempty"`
	ExpiresAt     int64  `json:"expires_at"`
}

type securityBindingObjectV2 struct {
	Type                       string `json:"sbo_type"`
	Version                    int    `json:"sbo_version"`
	Audience                   string `json:"aud"`
	ID                         string `json:"jti"`
	IssuedAt                   int64  `json:"iat"`
	ExpiresAt                  int64  `json:"exp"`
	Mode                       string `json:"mode"`
	GrantFormat                string `json:"identity_grant_format"`
	Grant                      string `json:"identity_grant"`
	GrantSHA256                string `json:"identity_grant_sha256"`
	BindingFormat              string `json:"session_binding_format"`
	Binding                    string `json:"session_binding"`
	BindingSHA256              string `json:"session_binding_sha256"`
	EndpointRole               string `json:"endpoint_role"`
	InteractionType            string `json:"interaction_type"`
	AcceptedEndpointSPKISHA256 string `json:"accepted_endpoint_spki_sha256"`
	TLSExporterSHA256          string `json:"tls_exporter_sha256"`
	BindingContextSHA256       string `json:"binding_context_sha256"`
	AttestationBinderSHA256    string `json:"attestation_binder_sha256"`
	VerifierNonce              string `json:"verifier_nonce"`
	AttemptID                  string `json:"attempt_id,omitempty"`
}

type requestContextsV2 struct {
	Task      []byte
	Target    []byte
	Resource  string
	Operation string
}

func canonicalRequestContextsV2(request a2aSendMessageRequest) (requestContextsV2, error) {
	operation, resource, err := taskOperationAndResourceV2(request.Message)
	if err != nil {
		return requestContextsV2{}, err
	}
	if request.Configuration == nil || len(request.Configuration.AcceptedOutputModes) == 0 {
		return requestContextsV2{}, fmt.Errorf("accepted output modes are required")
	}
	if len(request.Message.Parts) != 1 {
		return requestContextsV2{}, fmt.Errorf("exactly one task part is required")
	}
	for name, value := range map[string]string{
		"message_id": request.Message.MessageID, "context_id": request.Message.ContextID,
		"task_id": request.Message.TaskID, "role": request.Message.Role,
		"part_media_type": request.Message.Parts[0].MediaType,
		"resource":        resource, "operation": operation,
	} {
		if err := validateContextStringV2(value); err != nil {
			return requestContextsV2{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	outputModes, err := encodeCanonicalListV2(request.Configuration.AcceptedOutputModes)
	if err != nil {
		return requestContextsV2{}, fmt.Errorf("accepted output modes: %w", err)
	}
	selectedExtensions, err := encodeCanonicalListV2(request.Message.Extensions)
	if err != nil {
		return requestContextsV2{}, fmt.Errorf("selected extensions: %w", err)
	}

	textHash := sha256.Sum256([]byte(request.Message.Parts[0].Text))
	task := append([]byte(nil), []byte("ASB-A2A-TASK-v2\x00")...)
	for _, item := range []struct {
		name  string
		value []byte
	}{
		{"a2a_version", []byte(a2aVersion)},
		{"method", []byte(http.MethodPost)},
		{"path", []byte("/message:send")},
		{"message_id", []byte(request.Message.MessageID)},
		{"context_id", []byte(request.Message.ContextID)},
		{"task_id", []byte(request.Message.TaskID)},
		{"role", []byte(request.Message.Role)},
		{"accepted_output_modes", outputModes},
		{"part_media_type", []byte(request.Message.Parts[0].MediaType)},
		{"part_text_sha256", textHash[:]},
		{"selected_extensions", selectedExtensions},
	} {
		var fieldErr error
		task, fieldErr = appendFieldV2(task, item.name, item.value)
		if fieldErr != nil {
			return requestContextsV2{}, fieldErr
		}
	}

	target := append([]byte(nil), []byte("ASB-A2A-TARGET-v2\x00")...)
	target, err = appendFieldV2(target, "resource", []byte(resource))
	if err != nil {
		return requestContextsV2{}, err
	}
	target, err = appendFieldV2(target, "operation", []byte(operation))
	if err != nil {
		return requestContextsV2{}, err
	}
	return requestContextsV2{Task: task, Target: target, Resource: resource, Operation: operation}, nil
}

func appendFieldV2(dst []byte, name string, value []byte) ([]byte, error) {
	if len(name) > int(^uint16(0)) || uint64(len(value)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("A2A v2 context field is too large")
	}
	var sizes [6]byte
	binary.BigEndian.PutUint16(sizes[:2], uint16(len(name)))
	binary.BigEndian.PutUint32(sizes[2:], uint32(len(value)))
	dst = append(dst, sizes[:2]...)
	dst = append(dst, name...)
	dst = append(dst, sizes[2:]...)
	dst = append(dst, value...)
	return dst, nil
}

func encodeCanonicalListV2(values []string) ([]byte, error) {
	if uint64(len(values)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("list contains too many values")
	}
	ordered := append([]string(nil), values...)
	for _, value := range ordered {
		if err := validateContextStringV2(value); err != nil {
			return nil, err
		}
		if uint64(len(value)) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("list value is too large")
		}
	}
	sort.Strings(ordered)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(ordered)))
	out := append([]byte(nil), count[:]...)
	for index, value := range ordered {
		if index > 0 && value == ordered[index-1] {
			return nil, fmt.Errorf("duplicate list value %q", value)
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		out = append(out, length[:]...)
		out = append(out, value...)
	}
	return out, nil
}

func deriveAcceptedBindingV2(state *tls.ConnectionState, contexts requestContextsV2, grantToken, verifierNonce, attemptID string, leaf *x509.Certificate) (identitypolicy.BindingV2, []byte, error) {
	return deriveAcceptedBindingV2At(state, contexts, grantToken, verifierNonce, attemptID, leaf, time.Now().UTC())
}

func deriveAcceptedBindingV2At(state *tls.ConnectionState, contexts requestContextsV2, grantToken, verifierNonce, attemptID string, leaf *x509.Certificate, now time.Time) (identitypolicy.BindingV2, []byte, error) {
	if err := validateTLSSessionAtV2(state, now); err != nil {
		return identitypolicy.BindingV2{}, nil, err
	}
	if leaf == nil {
		return identitypolicy.BindingV2{}, nil, fmt.Errorf("accepted endpoint certificate is missing")
	}
	if err := validateCertificateAtV2(leaf, now); err != nil {
		return identitypolicy.BindingV2{}, nil, err
	}
	nonce, err := decodeNonceV2(verifierNonce, 32)
	if err != nil {
		return identitypolicy.BindingV2{}, nil, err
	}
	var attempt []byte
	if attemptID != "" {
		attempt, err = decodeNonceV2(attemptID, 16)
		if err != nil {
			return identitypolicy.BindingV2{}, nil, fmt.Errorf("attempt ID: %w", err)
		}
	}
	grantHash := clients.IdentityGrantDigest(grantToken)
	contextValue, err := sbaipv2.EncodeContext(sbaipv2.ContextInputs{
		EndpointRole: v2EndpointRole, InteractionType: v2InteractionType,
		ProtocolID: v2ProtocolID, Audience: demoAudience, GrantHash: grantHash,
		TaskContext: contexts.Task, TargetContext: contexts.Target,
		VerifierNonce: nonce, AttemptID: attempt,
	})
	if err != nil {
		return identitypolicy.BindingV2{}, nil, fmt.Errorf("encode draft-06 binding context: %w", err)
	}
	ekm, err := state.ExportKeyingMaterial(v2ExporterLabel, contextValue, 32)
	if err != nil {
		return identitypolicy.BindingV2{}, nil, fmt.Errorf("derive draft-06 TLS exporter: %w", err)
	}
	leafSPKI := leaf.RawSubjectPublicKeyInfo
	if len(leafSPKI) == 0 {
		leafSPKI, err = x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return identitypolicy.BindingV2{}, nil, fmt.Errorf("encode accepted endpoint public key: %w", err)
		}
	}
	hashes, err := sbaipv2.DeriveHashes(contextValue, leafSPKI, ekm)
	if err != nil {
		return identitypolicy.BindingV2{}, nil, fmt.Errorf("derive draft-06 binding hashes: %w", err)
	}
	binder, err := sbaipv2.AttestationBindingInput(leafSPKI, ekm)
	if err != nil {
		return identitypolicy.BindingV2{}, nil, fmt.Errorf("derive draft-06 attestation binder: %w", err)
	}
	return identitypolicy.BindingV2{
		EndpointRole: v2EndpointRole, InteractionType: v2InteractionType,
		AcceptedEndpointSPKISHA256: hashStringV2(hashes.AcceptedEndpointSPKISHA256),
		TLSExporterSHA256:          hashStringV2(hashes.TLSExporterSHA256),
		BindingContextSHA256:       hashStringV2(hashes.BindingContextSHA256),
		AttestationBinderSHA256:    hashStringV2(hashes.AttestationBinderSHA256),
		VerifierNonce:              verifierNonce, AttemptID: attemptID,
	}, binder, nil
}

func validateTLSSessionV2(state *tls.ConnectionState) error {
	return validateTLSSessionAtV2(state, time.Now().UTC())
}

func validateTLSSessionAtV2(state *tls.ConnectionState, now time.Time) error {
	if state == nil || !state.HandshakeComplete || state.Version != tls.VersionTLS13 {
		return fmt.Errorf("a completed TLS 1.3 session is required")
	}
	if state.DidResume {
		return fmt.Errorf("resumed TLS sessions are not accepted by this profile")
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return fmt.Errorf("the current peer certificate must be verified")
	}
	if err := validateCertificateAtV2(state.PeerCertificates[0], now); err != nil {
		return err
	}
	return nil
}

func validateCertificateAtV2(certificate *x509.Certificate, now time.Time) error {
	if certificate == nil || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return fmt.Errorf("the current peer certificate is outside its validity interval")
	}
	return nil
}

func channelTagV2At(state *tls.ConnectionState, now time.Time) (string, error) {
	if err := validateTLSSessionAtV2(state, now); err != nil {
		return "", err
	}
	value, err := state.ExportKeyingMaterial(v2ChallengeExporterLabel, nil, 32)
	if err != nil {
		return "", fmt.Errorf("derive challenge channel tag: %w", err)
	}
	return hashBytesV2(value), nil
}

func hashStringV2(value [32]byte) string {
	return "sha256:" + hex.EncodeToString(value[:])
}

func hashBytesV2(value []byte) string {
	sum := sha256.Sum256(value)
	return hashStringV2(sum)
}

func decodeNonceV2(value string, exactBytes int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != exactBytes || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("value must be canonical base64url encoding of exactly %d bytes", exactBytes)
	}
	return decoded, nil
}

func decodeStrictA2ARequestV2(raw []byte) (a2aSendMessageRequest, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return a2aSendMessageRequest{}, fmt.Errorf("request must be non-empty UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeStrictJSONValueV2(decoder); err != nil {
		return a2aSendMessageRequest{}, err
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return a2aSendMessageRequest{}, fmt.Errorf("request contains trailing JSON")
	}
	if err := validateExactA2AMemberNamesV2(raw); err != nil {
		return a2aSendMessageRequest{}, err
	}

	var request a2aSendMessageRequest
	typed := json.NewDecoder(bytes.NewReader(raw))
	typed.DisallowUnknownFields()
	if err := typed.Decode(&request); err != nil || typed.Decode(&struct{}{}) != io.EOF {
		return a2aSendMessageRequest{}, fmt.Errorf("request is outside the supported A2A Send Message subset")
	}
	if err := validateA2ARequestShapeV2(request); err != nil {
		return a2aSendMessageRequest{}, err
	}
	return request, nil
}

func validateExactA2AMemberNamesV2(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	if err := requireExactMemberSetV2(root, "message", "configuration"); err != nil {
		return err
	}
	var message map[string]json.RawMessage
	if err := json.Unmarshal(root["message"], &message); err != nil {
		return fmt.Errorf("message must be an object")
	}
	if err := requireExactMemberSetV2(message, "messageId", "contextId", "taskId", "role", "parts", "metadata", "extensions"); err != nil {
		return err
	}
	var configuration map[string]json.RawMessage
	if err := json.Unmarshal(root["configuration"], &configuration); err != nil {
		return fmt.Errorf("configuration must be an object")
	}
	if err := requireExactMemberSetV2(configuration, "acceptedOutputModes"); err != nil {
		return err
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(message["metadata"], &metadata); err != nil {
		return fmt.Errorf("message metadata must be an object")
	}
	if err := requireExactMemberSetV2(metadata, securityBindingExtensionV2, attestationResultExtensionV2); err != nil {
		return err
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(message["parts"], &parts); err != nil || len(parts) != 1 {
		return fmt.Errorf("message parts must contain exactly one object")
	}
	var part map[string]json.RawMessage
	if err := json.Unmarshal(parts[0], &part); err != nil {
		return fmt.Errorf("message part must be an object")
	}
	if err := requireExactMemberSetV2(part, "text", "metadata", "mediaType"); err != nil {
		return err
	}
	var partMetadata map[string]json.RawMessage
	if err := json.Unmarshal(part["metadata"], &partMetadata); err != nil {
		return fmt.Errorf("part metadata must be an object")
	}
	return requireExactMemberSetV2(partMetadata, "operation", "resource")
}

func requireExactMemberSetV2(values map[string]json.RawMessage, names ...string) error {
	if len(values) != len(names) {
		return fmt.Errorf("JSON object has unsupported or missing members")
	}
	for _, name := range names {
		if _, ok := values[name]; !ok {
			return fmt.Errorf("JSON object is missing exact member %q", name)
		}
	}
	return nil
}

func consumeStrictJSONValueV2(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if value, ok := token.(string); ok && strings.ContainsRune(value, '\uFFFD') {
		return fmt.Errorf("replacement character is not accepted")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok || strings.ContainsRune(name, '\uFFFD') {
				return fmt.Errorf("invalid JSON member name")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", name)
			}
			seen[name] = struct{}{}
			if err := consumeStrictJSONValueV2(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeStrictJSONValueV2(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	return nil
}

func validateA2ARequestShapeV2(request a2aSendMessageRequest) error {
	if request.Message.MessageID == "" || request.Message.TaskID == "" || request.Message.ContextID == "" || request.Message.Role == "" {
		return fmt.Errorf("message identifiers and role are required")
	}
	if !hasExactExtensionsV2(request.Message.Extensions) {
		return fmt.Errorf("exact draft-06 security extensions are required")
	}
	if len(request.Message.Metadata) != 2 {
		return fmt.Errorf("only the two draft-06 extension payloads are supported")
	}
	if _, ok := request.Message.Metadata[securityBindingExtensionV2]; !ok {
		return fmt.Errorf("draft-06 Security Binding Object is missing")
	}
	if _, ok := request.Message.Metadata[attestationResultExtensionV2]; !ok {
		return fmt.Errorf("draft-06 attestation result is missing")
	}
	if request.Configuration == nil || len(request.Configuration.AcceptedOutputModes) != 1 || request.Configuration.AcceptedOutputModes[0] != "text/plain" {
		return fmt.Errorf("only text/plain output is supported")
	}
	if len(request.Message.Parts) != 1 || request.Message.Parts[0].MediaType != "text/plain" || request.Message.Parts[0].Text == "" {
		return fmt.Errorf("exactly one non-empty text/plain part is required")
	}
	if len(request.Message.Parts[0].Metadata) != 2 {
		return fmt.Errorf("only resource and operation part metadata are supported")
	}
	_, err := canonicalRequestContextsV2(request)
	return err
}

func hasExactExtensionsV2(values []string) bool {
	if len(values) != 2 || values[0] == values[1] {
		return false
	}
	seen := map[string]bool{values[0]: true, values[1]: true}
	return seen[securityBindingExtensionV2] && seen[attestationResultExtensionV2]
}

func taskOperationAndResourceV2(message a2aMessage) (string, string, error) {
	if len(message.Parts) != 1 || len(message.Parts[0].Metadata) != 2 {
		return "", "", fmt.Errorf("exactly one task part with resource and operation is required")
	}
	operation, operationOK := message.Parts[0].Metadata["operation"]
	resource, resourceOK := message.Parts[0].Metadata["resource"]
	if !operationOK || !resourceOK || operation == "" || resource == "" {
		return "", "", fmt.Errorf("task operation and resource are required")
	}
	if strings.TrimSpace(operation) != operation || strings.TrimSpace(resource) != resource {
		return "", "", fmt.Errorf("task operation and resource must use their exact raw values")
	}
	return operation, resource, nil
}

func validateContextStringV2(value string) error {
	if value == "" || !utf8.ValidString(value) || strings.ContainsRune(value, '\uFFFD') {
		return fmt.Errorf("value must be non-empty UTF-8 without U+FFFD")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("control characters are not accepted")
		}
	}
	return nil
}

func rejectTransportIndirectionV2(r *http.Request) error {
	if r == nil {
		return fmt.Errorf("request is unavailable")
	}
	if r.Header.Get("Early-Data") != "" {
		return fmt.Errorf("early data is not accepted")
	}
	for _, header := range []string{"Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		if r.Header.Get(header) != "" {
			return fmt.Errorf("gateway-terminated requests are outside this profile")
		}
	}
	return nil
}

func requireNoEarlyDataV2(earlyData bool) error {
	if earlyData {
		return fmt.Errorf("TLS early data is not accepted")
	}
	return nil
}

func decodeSBOV2(raw json.RawMessage) (securityBindingObjectV2, error) {
	if len(raw) == 0 {
		return securityBindingObjectV2{}, fmt.Errorf("Security Binding Object is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var sbo securityBindingObjectV2
	if err := decoder.Decode(&sbo); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return securityBindingObjectV2{}, fmt.Errorf("Security Binding Object is outside the draft-06 profile")
	}
	return sbo, nil
}

func validateSBOV2(sbo securityBindingObjectV2, expected identitypolicy.BindingV2, challengeExpiresAt, now time.Time) error {
	if sbo.Type != "sbaip.security-binding" || sbo.Version != 2 || sbo.Audience != demoAudience || sbo.ID == "" ||
		sbo.Mode != "identity-grant+jws-session-binding" || sbo.GrantFormat != jwtFormat || sbo.BindingFormat != jwtFormat ||
		sbo.Grant == "" || sbo.Binding == "" || sbo.EndpointRole != v2EndpointRole || sbo.InteractionType != v2InteractionType {
		return fmt.Errorf("Security Binding Object contract mismatch")
	}
	if sbo.IssuedAt <= 0 || sbo.ExpiresAt <= sbo.IssuedAt || now.Unix() >= sbo.ExpiresAt || sbo.IssuedAt > now.Add(30*time.Second).Unix() {
		return fmt.Errorf("Security Binding Object is expired or not yet valid")
	}
	if err := validateChallengeBoundExpiryV2(sbo.ExpiresAt, challengeExpiresAt); err != nil {
		return err
	}
	if sbo.GrantSHA256 != sha256String([]byte(sbo.Grant)) || sbo.BindingSHA256 != sha256String([]byte(sbo.Binding)) {
		return fmt.Errorf("Security Binding Object token hash mismatch")
	}
	if sbo.AcceptedEndpointSPKISHA256 != expected.AcceptedEndpointSPKISHA256 ||
		sbo.TLSExporterSHA256 != expected.TLSExporterSHA256 ||
		sbo.BindingContextSHA256 != expected.BindingContextSHA256 ||
		sbo.AttestationBinderSHA256 != expected.AttestationBinderSHA256 ||
		sbo.VerifierNonce != expected.VerifierNonce || sbo.AttemptID != expected.AttemptID {
		return fmt.Errorf("Security Binding Object accepted binding mismatch")
	}
	return nil
}

func validateChallengeBoundExpiryV2(expiresAtUnix int64, challengeExpiresAt time.Time) error {
	if challengeExpiresAt.IsZero() || expiresAtUnix != challengeExpiresAt.Unix() {
		return fmt.Errorf("proof lifetime must equal the authenticated challenge lifetime")
	}
	return nil
}

func parseAttestationResultV2(token string, key any, now time.Time) (*attestationResultClaims, error) {
	claims := &attestationResultClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodES256 || token.Header["kid"] != demoVerifierKeyID || token.Header["typ"] != "JWT" || len(token.Header) != 3 {
			return nil, fmt.Errorf("unexpected attestation result protected header")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}), jwt.WithIssuer(demoVerifierIssuer), jwt.WithAudience(demoAudience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("verify draft-06 attestation result: %w", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != demoAudience || claims.Subject != demoAgentIssuer || claims.ID == "" || claims.IssuedAt == nil || claims.ExpiresAt == nil ||
		claims.ProfileType != v2AttestationProfile || claims.ProfileVersion != v2AttestationVersion || claims.AppraisalPolicyID != v2AppraisalPolicyID {
		return nil, fmt.Errorf("unexpected draft-06 attestation result profile")
	}
	return claims, nil
}
