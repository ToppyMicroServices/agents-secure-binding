// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/a2asecuritytest"
)

const (
	multiHostDeploymentSchemaV1 = "urn:asb:a2a-multihost-deployment:v1"
	multiHostTrustSchemaV1      = "urn:asb:a2a-multihost-trust:v1"
	multiHostEvidenceSchemaV1   = "urn:asb:a2a-multihost-run-evidence:v1"
	multiHostEvidenceScopeV1    = "asb-reference-configured-origins-run"
	multiHostTrustFile          = "multihost-trust.json"
	maxMultiHostDocumentBytes   = 64 << 10
)

var multiHostIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var multiHostServerRoles = []string{"manager", "attester", "verifier", "replay", demoAudience}

// multiHostDeploymentV1 is an operator-supplied topology. It contains only
// public origins and local listen addresses; credentials stay in role bundles.
type multiHostDeploymentV1 struct {
	Schema         string                         `json:"schema"`
	DeploymentID   string                         `json:"deployment_id"`
	BindingProfile string                         `json:"binding_profile"`
	Attestation    multiHostAttestationV1         `json:"attestation"`
	Endpoints      map[string]multiHostEndpointV1 `json:"endpoints"`
}

type multiHostAttestationV1 struct {
	Mode     string `json:"mode"`
	Platform string `json:"platform"`
}

type multiHostEndpointV1 struct {
	URL    string `json:"url"`
	Listen string `json:"listen"`
}

type multiHostTrustManifestV1 struct {
	Schema              string                    `json:"schema"`
	DeploymentID        string                    `json:"deployment_id"`
	BindingProfile      string                    `json:"binding_profile"`
	CreatedAt           time.Time                 `json:"created_at"`
	CACertificateSHA256 string                    `json:"ca_certificate_sha256"`
	Roles               []multiHostRoleTrustV1    `json:"roles"`
	SigningKeys         []multiHostSigningTrustV1 `json:"signing_keys"`
}

type multiHostRoleTrustV1 struct {
	Role              string   `json:"role"`
	Endpoint          string   `json:"endpoint,omitempty"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	SPKISHA256        string   `json:"spki_sha256"`
	DNSNames          []string `json:"dns_names,omitempty"`
	IPAddresses       []string `json:"ip_addresses,omitempty"`
}

type multiHostSigningTrustV1 struct {
	Use        string `json:"use"`
	KeyID      string `json:"key_id"`
	SPKISHA256 string `json:"spki_sha256"`
}

type multiHostRunEvidenceV1 struct {
	Schema                 string                 `json:"schema"`
	ClaimScope             string                 `json:"claim_scope"`
	DeploymentID           string                 `json:"deployment_id"`
	GeneratedAt            time.Time              `json:"generated_at"`
	Tool                   a2asecuritytest.Tool   `json:"tool"`
	Profile                string                 `json:"profile"`
	RunID                  string                 `json:"run_id"`
	Status                 a2asecuritytest.Status `json:"status"`
	EndpointOrigins        map[string]string      `json:"endpoint_origins"`
	DeploymentConfigSHA256 string                 `json:"deployment_config_sha256"`
	TrustManifestSHA256    string                 `json:"trust_manifest_sha256"`
	ReportSHA256           string                 `json:"report_sha256"`
	Limitations            []string               `json:"limitations"`
}

func loadMultiHostDeployment(path string) (multiHostDeploymentV1, error) {
	var deployment multiHostDeploymentV1
	if _, err := decodeStrictMultiHostFile(path, &deployment); err != nil {
		return deployment, fmt.Errorf("load multi-host deployment: %w", err)
	}
	if err := deployment.validate(); err != nil {
		return deployment, fmt.Errorf("validate multi-host deployment: %w", err)
	}
	return deployment, nil
}

func (d *multiHostDeploymentV1) validate() error {
	if d == nil || d.Schema != multiHostDeploymentSchemaV1 {
		return fmt.Errorf("schema must be %q", multiHostDeploymentSchemaV1)
	}
	if !multiHostIDPattern.MatchString(d.DeploymentID) {
		return fmt.Errorf("deployment_id is outside the supported identifier form")
	}
	if d.BindingProfile != bindingProfileV1 && d.BindingProfile != bindingProfileDraft06V2 {
		return fmt.Errorf("unsupported binding_profile %q", d.BindingProfile)
	}
	d.Attestation.Mode = strings.ToLower(d.Attestation.Mode)
	d.Attestation.Platform = strings.ToLower(d.Attestation.Platform)
	if d.Attestation.Mode != modeSimulation && d.Attestation.Mode != modeHardware {
		return fmt.Errorf("attestation mode must be simulation or hardware")
	}
	if d.Attestation.Platform == "" {
		d.Attestation.Platform = platformAuto
	}
	if d.Attestation.Mode == modeSimulation && d.Attestation.Platform != platformAuto {
		return fmt.Errorf("simulation attestation platform must be auto")
	}
	if d.Attestation.Mode == modeHardware && d.Attestation.Platform != platformAuto && d.Attestation.Platform != platformSNP && d.Attestation.Platform != platformTDX {
		return fmt.Errorf("unsupported hardware attestation platform %q", d.Attestation.Platform)
	}
	if len(d.Endpoints) != len(multiHostServerRoles) {
		return fmt.Errorf("endpoints must contain exactly manager, attester, verifier, replay, and agent-b")
	}
	seenOrigins := make(map[string]string, len(d.Endpoints))
	for _, role := range multiHostServerRoles {
		endpoint, ok := d.Endpoints[role]
		if !ok {
			return fmt.Errorf("endpoint %q is required", role)
		}
		origin, err := validateMultiHostOrigin(endpoint.URL)
		if err != nil {
			return fmt.Errorf("%s URL: %w", role, err)
		}
		if other, exists := seenOrigins[origin]; exists {
			return fmt.Errorf("%s and %s use the same origin", other, role)
		}
		seenOrigins[origin] = role
		if err := validateMultiHostListen(endpoint.Listen); err != nil {
			return fmt.Errorf("%s listen: %w", role, err)
		}
		endpoint.URL = origin
		d.Endpoints[role] = endpoint
	}
	for role := range d.Endpoints {
		if !containsString(multiHostServerRoles, role) {
			return fmt.Errorf("unsupported endpoint role %q", role)
		}
	}
	return nil
}

func validateMultiHostOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("must be an absolute HTTPS origin without user information")
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("must not contain a path, query, or fragment")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" || hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return "", fmt.Errorf("loopback hostnames are not accepted")
	}
	if address := net.ParseIP(hostname); address != nil && !address.IsGlobalUnicast() {
		return "", fmt.Errorf("endpoint IP must be a non-loopback unicast address")
	}
	if address := net.ParseIP(hostname); address == nil && !validDNSName(hostname) {
		return "", fmt.Errorf("hostname is not a valid DNS name or IP address")
	}
	port := parsed.Port()
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return "", fmt.Errorf("port is invalid")
		}
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return "https://" + host, nil
}

func validateMultiHostListen(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return fmt.Errorf("must be an explicit host:port address")
	}
	numericPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || numericPort == 0 {
		return fmt.Errorf("port is invalid")
	}
	if address := net.ParseIP(host); address != nil && address.IsLoopback() {
		return fmt.Errorf("loopback listen addresses are not accepted")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("loopback listen addresses are not accepted")
	}
	if address := net.ParseIP(host); address == nil && !validDNSName(strings.ToLower(host)) {
		return fmt.Errorf("listen host is not a valid DNS name or IP address")
	}
	return nil
}

func validDNSName(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return false
			}
		}
	}
	return true
}

func applyMultiHostDeployment(opts options, deployment multiHostDeploymentV1) options {
	opts.bindingProfile = deployment.BindingProfile
	opts.attestationMode = deployment.Attestation.Mode
	opts.attestationPlatform = deployment.Attestation.Platform
	opts.managerURL = deployment.Endpoints["manager"].URL
	opts.attesterURL = deployment.Endpoints["attester"].URL
	opts.verifierURL = deployment.Endpoints["verifier"].URL
	opts.replayURL = deployment.Endpoints["replay"].URL
	opts.agentBURL = deployment.Endpoints[demoAudience].URL
	opts.publicURL = deployment.Endpoints[demoAudience].URL
	if endpoint, ok := deployment.Endpoints[opts.role]; ok {
		opts.listen = endpoint.Listen
	}
	if deployment.Attestation.Mode == modeSimulation && opts.role == demoAudience {
		opts.allowSimulation = true
	}
	return opts
}

func effectiveTrustManifestPath(opts options) string {
	if opts.trustManifest != "" {
		return opts.trustManifest
	}
	return filepath.Join(opts.stateDir, multiHostTrustFile)
}

func decodeStrictMultiHostFile(path string, target any) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxMultiHostDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > maxMultiHostDocumentBytes || !utf8.Valid(raw) {
		return nil, fmt.Errorf("JSON must be non-empty UTF-8 and at most %d bytes", maxMultiHostDocumentBytes)
	}
	scanner := json.NewDecoder(bytes.NewReader(raw))
	scanner.UseNumber()
	if err := consumeStrictJSONValueV2(scanner); err != nil {
		return nil, err
	}
	if token, err := scanner.Token(); err != io.EOF || token != nil {
		return nil, fmt.Errorf("JSON contains trailing data")
	}
	if err := validateExactMultiHostMembers(raw, target); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("JSON contains trailing data")
	}
	return raw, nil
}

func validateExactMultiHostMembers(raw []byte, target any) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	switch target.(type) {
	case *multiHostDeploymentV1:
		if err := requireMultiHostMembers(root, []string{"schema", "deployment_id", "binding_profile", "attestation", "endpoints"}, nil); err != nil {
			return err
		}
		var attestation map[string]json.RawMessage
		if err := json.Unmarshal(root["attestation"], &attestation); err != nil {
			return fmt.Errorf("attestation must be an object")
		}
		if err := requireMultiHostMembers(attestation, []string{"mode", "platform"}, nil); err != nil {
			return err
		}
		var endpoints map[string]json.RawMessage
		if err := json.Unmarshal(root["endpoints"], &endpoints); err != nil {
			return fmt.Errorf("endpoints must be an object")
		}
		if err := requireMultiHostMembers(endpoints, multiHostServerRoles, nil); err != nil {
			return err
		}
		for role, rawEndpoint := range endpoints {
			var endpoint map[string]json.RawMessage
			if err := json.Unmarshal(rawEndpoint, &endpoint); err != nil {
				return fmt.Errorf("endpoint %q must be an object", role)
			}
			if err := requireMultiHostMembers(endpoint, []string{"url", "listen"}, nil); err != nil {
				return fmt.Errorf("endpoint %q: %w", role, err)
			}
		}
	case *multiHostTrustManifestV1:
		if err := requireMultiHostMembers(root, []string{"schema", "deployment_id", "binding_profile", "created_at", "ca_certificate_sha256", "roles", "signing_keys"}, nil); err != nil {
			return err
		}
		var roles []map[string]json.RawMessage
		if err := json.Unmarshal(root["roles"], &roles); err != nil {
			return fmt.Errorf("roles must be an array of objects")
		}
		for _, role := range roles {
			if err := requireMultiHostMembers(role, []string{"role", "certificate_sha256", "spki_sha256"}, []string{"endpoint", "dns_names", "ip_addresses"}); err != nil {
				return fmt.Errorf("role trust entry: %w", err)
			}
		}
		var keys []map[string]json.RawMessage
		if err := json.Unmarshal(root["signing_keys"], &keys); err != nil {
			return fmt.Errorf("signing_keys must be an array of objects")
		}
		for _, key := range keys {
			if err := requireMultiHostMembers(key, []string{"use", "key_id", "spki_sha256"}, nil); err != nil {
				return fmt.Errorf("signing key trust entry: %w", err)
			}
		}
	case *multiHostRunEvidenceV1:
		if err := requireMultiHostMembers(root, []string{
			"schema", "claim_scope", "deployment_id", "generated_at", "tool", "profile", "run_id", "status",
			"endpoint_origins", "deployment_config_sha256", "trust_manifest_sha256", "report_sha256", "limitations",
		}, nil); err != nil {
			return err
		}
		var tool map[string]json.RawMessage
		if err := json.Unmarshal(root["tool"], &tool); err != nil {
			return fmt.Errorf("tool must be an object")
		}
		if err := requireMultiHostMembers(tool, []string{"name", "version", "commit"}, nil); err != nil {
			return fmt.Errorf("tool: %w", err)
		}
		var origins map[string]json.RawMessage
		if err := json.Unmarshal(root["endpoint_origins"], &origins); err != nil {
			return fmt.Errorf("endpoint_origins must be an object")
		}
		return requireMultiHostMembers(origins, multiHostServerRoles, nil)
	}
	return nil
}

func requireMultiHostMembers(values map[string]json.RawMessage, required, optional []string) error {
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, name := range required {
		allowed[name] = struct{}{}
		if _, ok := values[name]; !ok {
			return fmt.Errorf("JSON object is missing exact member %q", name)
		}
	}
	for _, name := range optional {
		allowed[name] = struct{}{}
	}
	for name := range values {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("JSON object has unsupported exact member %q", name)
		}
	}
	return nil
}

func buildMultiHostTrustManifest(stateDir string, deployment multiHostDeploymentV1, createdAt time.Time) (multiHostTrustManifestV1, error) {
	caRaw, err := os.ReadFile(filepath.Join(roleDirectory(stateDir, "agent-a"), caFile))
	if err != nil {
		return multiHostTrustManifestV1{}, fmt.Errorf("read trust anchor: %w", err)
	}
	ca, err := firstCertificateFromPEM(caRaw)
	if err != nil {
		return multiHostTrustManifestV1{}, err
	}
	manifest := multiHostTrustManifestV1{
		Schema: multiHostTrustSchemaV1, DeploymentID: deployment.DeploymentID,
		BindingProfile: deployment.BindingProfile, CreatedAt: createdAt.UTC(),
		CACertificateSHA256: digestWithPrefix(ca.Raw),
	}
	roles := append([]string{"agent-a"}, multiHostServerRoles...)
	sort.Strings(roles)
	for _, role := range roles {
		raw, err := os.ReadFile(filepath.Join(roleDirectory(stateDir, role), tlsCertFile))
		if err != nil {
			return multiHostTrustManifestV1{}, fmt.Errorf("read %s certificate: %w", role, err)
		}
		certificate, err := firstCertificateFromPEM(raw)
		if err != nil {
			return multiHostTrustManifestV1{}, fmt.Errorf("parse %s certificate: %w", role, err)
		}
		spki := certificate.RawSubjectPublicKeyInfo
		entry := multiHostRoleTrustV1{
			Role: role, CertificateSHA256: digestWithPrefix(certificate.Raw), SPKISHA256: digestWithPrefix(spki),
			DNSNames: append([]string(nil), certificate.DNSNames...),
		}
		if endpoint, ok := deployment.Endpoints[role]; ok {
			entry.Endpoint = endpoint.URL
		}
		for _, address := range certificate.IPAddresses {
			entry.IPAddresses = append(entry.IPAddresses, address.String())
		}
		manifest.Roles = append(manifest.Roles, entry)
	}
	keys := []struct {
		use, keyID, path string
	}{
		{"agent-a-session-binding", demoAgentKeyID, filepath.Join(roleDirectory(stateDir, demoAudience), agentPublicFile)},
		{"manager-authority-grant", demoManagerKeyID, filepath.Join(roleDirectory(stateDir, demoAudience), managerPublicFile)},
		{"verifier-attestation-result", demoVerifierKeyID, filepath.Join(roleDirectory(stateDir, demoAudience), verifierPublicFile)},
		{"simulation-evidence", demoAttesterKeyID, filepath.Join(roleDirectory(stateDir, "verifier"), simPublicFile)},
	}
	for _, item := range keys {
		key, err := loadPublicKey(item.path)
		if err != nil {
			return multiHostTrustManifestV1{}, err
		}
		spki, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return multiHostTrustManifestV1{}, fmt.Errorf("encode %s public key: %w", item.use, err)
		}
		manifest.SigningKeys = append(manifest.SigningKeys, multiHostSigningTrustV1{Use: item.use, KeyID: item.keyID, SPKISHA256: digestWithPrefix(spki)})
	}
	return manifest, nil
}

func validateMultiHostTrustManifest(manifest multiHostTrustManifestV1, deployment multiHostDeploymentV1) error {
	if manifest.Schema != multiHostTrustSchemaV1 || manifest.DeploymentID != deployment.DeploymentID || manifest.BindingProfile != deployment.BindingProfile {
		return fmt.Errorf("trust manifest does not match the deployment")
	}
	if manifest.CreatedAt.IsZero() || !validSHA256Digest(manifest.CACertificateSHA256) {
		return fmt.Errorf("trust manifest header is invalid")
	}
	if len(manifest.Roles) != len(multiHostServerRoles)+1 || len(manifest.SigningKeys) != 4 {
		return fmt.Errorf("trust manifest has an incomplete role or signing-key set")
	}
	seenRoles := make(map[string]struct{}, len(manifest.Roles))
	for _, role := range manifest.Roles {
		if role.Role != "agent-a" && !containsString(multiHostServerRoles, role.Role) {
			return fmt.Errorf("trust manifest contains unsupported role %q", role.Role)
		}
		if _, exists := seenRoles[role.Role]; exists {
			return fmt.Errorf("trust manifest repeats role %q", role.Role)
		}
		seenRoles[role.Role] = struct{}{}
		if !validSHA256Digest(role.CertificateSHA256) || !validSHA256Digest(role.SPKISHA256) {
			return fmt.Errorf("trust manifest role %q has an invalid digest", role.Role)
		}
		if endpoint, ok := deployment.Endpoints[role.Role]; ok {
			if role.Endpoint != endpoint.URL {
				return fmt.Errorf("trust manifest endpoint %q does not match deployment", role.Role)
			}
			parsed, _ := url.Parse(endpoint.URL)
			hostname := parsed.Hostname()
			if address := net.ParseIP(hostname); address != nil {
				if !containsString(role.IPAddresses, address.String()) {
					return fmt.Errorf("trust manifest certificate for %q omits endpoint IP", role.Role)
				}
			} else if !containsString(role.DNSNames, hostname) {
				return fmt.Errorf("trust manifest certificate for %q omits endpoint DNS name", role.Role)
			}
		}
	}
	requiredUses := map[string]string{
		"agent-a-session-binding":     demoAgentKeyID,
		"manager-authority-grant":     demoManagerKeyID,
		"verifier-attestation-result": demoVerifierKeyID,
		"simulation-evidence":         demoAttesterKeyID,
	}
	seenUses := make(map[string]struct{}, len(manifest.SigningKeys))
	for _, key := range manifest.SigningKeys {
		if key.Use == "" || key.KeyID == "" || !validSHA256Digest(key.SPKISHA256) {
			return fmt.Errorf("trust manifest contains an invalid signing key")
		}
		if _, exists := seenUses[key.Use]; exists {
			return fmt.Errorf("trust manifest repeats signing-key use %q", key.Use)
		}
		if expectedKeyID, ok := requiredUses[key.Use]; !ok || key.KeyID != expectedKeyID {
			return fmt.Errorf("trust manifest contains unsupported signing-key use or ID")
		}
		seenUses[key.Use] = struct{}{}
	}
	return nil
}

func verifyLocalAgentATrust(stateDir string, manifest multiHostTrustManifestV1) error {
	caRaw, err := os.ReadFile(filepath.Join(roleDirectory(stateDir, "agent-a"), caFile))
	if err != nil {
		return fmt.Errorf("read Agent A trust anchor: %w", err)
	}
	ca, err := firstCertificateFromPEM(caRaw)
	if err != nil {
		return err
	}
	if digestWithPrefix(ca.Raw) != manifest.CACertificateSHA256 {
		return fmt.Errorf("Agent A trust anchor does not match the trust manifest")
	}
	raw, err := os.ReadFile(filepath.Join(roleDirectory(stateDir, "agent-a"), tlsCertFile))
	if err != nil {
		return fmt.Errorf("read Agent A certificate: %w", err)
	}
	certificate, err := firstCertificateFromPEM(raw)
	if err != nil {
		return err
	}
	for _, role := range manifest.Roles {
		if role.Role == "agent-a" {
			if role.CertificateSHA256 != digestWithPrefix(certificate.Raw) || role.SPKISHA256 != digestWithPrefix(certificate.RawSubjectPublicKeyInfo) {
				return fmt.Errorf("Agent A certificate does not match the trust manifest")
			}
			return nil
		}
	}
	return fmt.Errorf("trust manifest omits Agent A")
}

func writeMultiHostRunEvidence(opts options, reportPayload []byte, report a2asecuritytest.Report) error {
	if opts.deploymentConfig == "" || opts.deploymentEvidence == "" {
		return fmt.Errorf("deployment config and evidence path are required")
	}
	deploymentRaw, err := decodeStrictMultiHostFile(opts.deploymentConfig, &multiHostDeploymentV1{})
	if err != nil {
		return fmt.Errorf("read deployment evidence input: %w", err)
	}
	deployment, err := loadMultiHostDeployment(opts.deploymentConfig)
	if err != nil {
		return err
	}
	trustPath := effectiveTrustManifestPath(opts)
	var manifest multiHostTrustManifestV1
	trustRaw, err := decodeStrictMultiHostFile(trustPath, &manifest)
	if err != nil {
		return fmt.Errorf("load multi-host trust manifest: %w", err)
	}
	if err := validateMultiHostTrustManifest(manifest, deployment); err != nil {
		return err
	}
	if err := verifyLocalAgentATrust(opts.stateDir, manifest); err != nil {
		return err
	}
	if report.Mode != a2asecuritytest.ModeTarget {
		return fmt.Errorf("multi-host evidence requires a target-mode report")
	}
	for _, input := range []string{opts.deploymentConfig, trustPath, opts.reportFile} {
		if input != "" && sameCleanPath(opts.deploymentEvidence, input) {
			return fmt.Errorf("deployment evidence path must not replace an input artifact")
		}
	}
	origins := make(map[string]string, len(multiHostServerRoles))
	for _, role := range multiHostServerRoles {
		origins[role] = deployment.Endpoints[role].URL
	}
	evidence := multiHostRunEvidenceV1{
		Schema:       multiHostEvidenceSchemaV1,
		ClaimScope:   multiHostEvidenceScopeV1,
		DeploymentID: deployment.DeploymentID,
		GeneratedAt:  time.Now().UTC(), Tool: report.Tool, Profile: report.Profile,
		RunID: report.RunID, Status: report.Status, EndpointOrigins: origins,
		DeploymentConfigSHA256: digestWithPrefix(deploymentRaw),
		TrustManifestSHA256:    digestWithPrefix(trustRaw),
		ReportSHA256:           digestWithPrefix(reportPayload),
		Limitations: []string{
			"configured origins do not prove physical host separation",
			"this is not independent-vendor or full A2A conformance evidence",
			"this run does not demonstrate coordinated multi-replica acceptance",
		},
	}
	if err := validateMultiHostRunEvidence(evidence); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return fmt.Errorf("encode multi-host run evidence: %w", err)
	}
	payload = append(payload, '\n')
	if err := writeReportAtomically(opts.deploymentEvidence, payload); err != nil {
		return fmt.Errorf("write multi-host run evidence: %w", err)
	}
	return nil
}

func verifyMultiHostRunEvidence(opts options, out outputWriter) error {
	if opts.deploymentConfig == "" || opts.trustManifest == "" || opts.reportFile == "" || opts.deploymentEvidence == "" {
		return fmt.Errorf("verify-evidence requires deployment config, trust manifest, report, and deployment evidence paths")
	}
	deploymentRaw, err := decodeStrictMultiHostFile(opts.deploymentConfig, &multiHostDeploymentV1{})
	if err != nil {
		return fmt.Errorf("read deployment evidence input: %w", err)
	}
	deployment, err := loadMultiHostDeployment(opts.deploymentConfig)
	if err != nil {
		return err
	}
	var manifest multiHostTrustManifestV1
	trustRaw, err := decodeStrictMultiHostFile(opts.trustManifest, &manifest)
	if err != nil {
		return fmt.Errorf("load multi-host trust manifest: %w", err)
	}
	if err := validateMultiHostTrustManifest(manifest, deployment); err != nil {
		return err
	}
	reportRaw, err := readBoundedMultiHostArtifact(opts.reportFile, a2asecuritytest.MaxReportBytes)
	if err != nil {
		return fmt.Errorf("read A2A test report: %w", err)
	}
	report, err := a2asecuritytest.DecodeReport(bytes.NewReader(reportRaw))
	if err != nil {
		return fmt.Errorf("decode A2A test report: %w", err)
	}
	var evidence multiHostRunEvidenceV1
	if _, err := decodeStrictMultiHostFile(opts.deploymentEvidence, &evidence); err != nil {
		return fmt.Errorf("load multi-host run evidence: %w", err)
	}
	if err := validateMultiHostRunEvidence(evidence); err != nil {
		return err
	}
	if evidence.DeploymentID != deployment.DeploymentID || evidence.Profile != report.Profile || evidence.RunID != report.RunID || evidence.Status != report.Status || evidence.Tool != report.Tool {
		return fmt.Errorf("multi-host evidence identity does not match its input artifacts")
	}
	if report.Mode != a2asecuritytest.ModeTarget || evidence.GeneratedAt.Before(report.FinishedAt) {
		return fmt.Errorf("multi-host evidence does not describe a completed target-mode report")
	}
	for _, role := range multiHostServerRoles {
		if evidence.EndpointOrigins[role] != deployment.Endpoints[role].URL {
			return fmt.Errorf("multi-host evidence endpoint %q does not match deployment", role)
		}
	}
	if evidence.DeploymentConfigSHA256 != digestWithPrefix(deploymentRaw) || evidence.TrustManifestSHA256 != digestWithPrefix(trustRaw) || evidence.ReportSHA256 != digestWithPrefix(reportRaw) {
		return fmt.Errorf("multi-host evidence artifact digest mismatch")
	}
	_, err = fmt.Fprintf(out, "verified multi-host evidence deployment=%s run=%s status=%s\n", evidence.DeploymentID, evidence.RunID, evidence.Status)
	if err != nil {
		return fmt.Errorf("write evidence verification result: %w", err)
	}
	return nil
}

func readBoundedMultiHostArtifact(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("artifact must be non-empty and at most %d bytes", maximum)
	}
	return raw, nil
}

func validateMultiHostRunEvidence(evidence multiHostRunEvidenceV1) error {
	if evidence.Schema != multiHostEvidenceSchemaV1 || evidence.ClaimScope != multiHostEvidenceScopeV1 {
		return fmt.Errorf("multi-host run evidence has an invalid scope")
	}
	if !multiHostIDPattern.MatchString(evidence.DeploymentID) || evidence.GeneratedAt.IsZero() || evidence.RunID == "" || evidence.Profile == "" {
		return fmt.Errorf("multi-host run evidence has an invalid identity")
	}
	if evidence.Tool.Name == "" || evidence.Tool.Version == "" || evidence.Tool.Commit == "" {
		return fmt.Errorf("multi-host run evidence has an invalid tool identity")
	}
	if evidence.Status != a2asecuritytest.StatusPass && evidence.Status != a2asecuritytest.StatusFail && evidence.Status != a2asecuritytest.StatusIndeterminate && evidence.Status != a2asecuritytest.StatusError {
		return fmt.Errorf("multi-host run evidence has an invalid status")
	}
	if len(evidence.EndpointOrigins) != len(multiHostServerRoles) || len(evidence.Limitations) != 3 {
		return fmt.Errorf("multi-host run evidence is incomplete")
	}
	requiredLimitations := []string{
		"configured origins do not prove physical host separation",
		"this is not independent-vendor or full A2A conformance evidence",
		"this run does not demonstrate coordinated multi-replica acceptance",
	}
	for _, limitation := range requiredLimitations {
		if !containsString(evidence.Limitations, limitation) {
			return fmt.Errorf("multi-host run evidence omits a required limitation")
		}
	}
	seenOrigins := make(map[string]string, len(multiHostServerRoles))
	for _, role := range multiHostServerRoles {
		origin, ok := evidence.EndpointOrigins[role]
		if !ok {
			return fmt.Errorf("multi-host run evidence omits %s", role)
		}
		if _, err := validateMultiHostOrigin(origin); err != nil {
			return fmt.Errorf("multi-host run evidence %s origin: %w", role, err)
		}
		if other, exists := seenOrigins[origin]; exists {
			return fmt.Errorf("multi-host run evidence repeats the %s origin for %s", other, role)
		}
		seenOrigins[origin] = role
	}
	for _, digest := range []string{evidence.DeploymentConfigSHA256, evidence.TrustManifestSHA256, evidence.ReportSHA256} {
		if !validSHA256Digest(digest) {
			return fmt.Errorf("multi-host run evidence contains an invalid digest")
		}
	}
	return nil
}

func sameCleanPath(first, second string) bool {
	firstAbsolute, firstErr := filepath.Abs(first)
	secondAbsolute, secondErr := filepath.Abs(second)
	return firstErr == nil && secondErr == nil && filepath.Clean(firstAbsolute) == filepath.Clean(secondAbsolute)
}

func firstCertificateFromPEM(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return certificate, nil
}

func digestWithPrefix(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size && value == "sha256:"+hex.EncodeToString(decoded)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
