// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
)

const (
	a2aVersion                 = "1.0"
	a2aMediaType               = "application/a2a+json"
	problemMediaType           = "application/problem+json"
	securityBindingExtension   = "urn:agents-secure-binding:security-binding:v1"
	attestationResultExtension = "urn:agents-secure-binding:attestation-result:v1"

	demoAudience       = "agent-b"
	demoManagerIssuer  = "demo-manager"
	demoAgentIssuer    = "agent-a"
	demoVerifierIssuer = "demo-attestation-verifier"
	demoAttesterIssuer = "demo-attester"
	demoManagerKeyID   = "demo-manager-key"
	demoAgentKeyID     = "demo-agent-a-key"
	demoVerifierKeyID  = "demo-verifier-key"
	demoAttesterKeyID  = "demo-attester-key"

	demoTaskID      = "task-demo-1"
	demoContextID   = "context-demo-1"
	demoService     = "task-executor"
	demoDeployment  = "multiprocess-demo"
	demoWorkload    = "coordinator"
	demoIntent      = "urn:example:intent:summarize"
	demoCapability  = "urn:example:capability:summarize"
	demoReadScope   = "documents:read"
	demoResource    = "urn:example:document:demo"
	demoOperation   = "summarize"
	demoMeasurement = "asb-simulation-measurement-v1"

	modeSimulation    = "simulation"
	modeHardware      = "hardware"
	platformAuto      = "auto"
	platformSNP       = "SNP"
	platformTDX       = "TDX"
	platformSimulated = "SIMULATED"

	maxBodySize = 256 * 1024
)

type grantRequest struct {
	TaskID    string `json:"taskId"`
	ContextID string `json:"contextId"`
}

type grantResponse struct {
	IdentityGrant string `json:"identityGrant"`
}

type evidenceRequest struct {
	ReportData string `json:"reportData"`
}

type evidenceResponse struct {
	Format   string `json:"format"`
	Platform string `json:"platform"`
	Evidence string `json:"evidence"`
}

type appraisalRequest struct {
	Binder   string           `json:"binder"`
	Evidence evidenceResponse `json:"evidence"`
}

type appraisalResponse struct {
	AttestationResult string `json:"attestationResult"`
}

type replayRequest struct {
	Key        string `json:"key"`
	TTLSeconds int64  `json:"ttlSeconds"`
}

type replayResponse struct {
	Inserted bool `json:"inserted"`
}

type a2aSendMessageRequest struct {
	Message       a2aMessage        `json:"message"`
	Configuration *a2aConfiguration `json:"configuration,omitempty"`
}

type a2aConfiguration struct {
	AcceptedOutputModes []string `json:"acceptedOutputModes,omitempty"`
}

type a2aMessage struct {
	MessageID  string                     `json:"messageId"`
	ContextID  string                     `json:"contextId,omitempty"`
	TaskID     string                     `json:"taskId,omitempty"`
	Role       string                     `json:"role"`
	Parts      []a2aPart                  `json:"parts"`
	Metadata   map[string]json.RawMessage `json:"metadata,omitempty"`
	Extensions []string                   `json:"extensions,omitempty"`
}

type a2aPart struct {
	Text      string            `json:"text,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	MediaType string            `json:"mediaType,omitempty"`
}

type securityBindingObject struct {
	Type                 string `json:"sbo_type"`
	Version              int    `json:"sbo_version"`
	Audience             string `json:"aud"`
	ID                   string `json:"jti"`
	IssuedAt             int64  `json:"iat"`
	ExpiresAt            int64  `json:"exp"`
	Mode                 string `json:"mode"`
	GrantFormat          string `json:"identity_grant_format"`
	Grant                string `json:"identity_grant"`
	GrantSHA256          string `json:"identity_grant_sha256"`
	BindingFormat        string `json:"session_binding_format"`
	Binding              string `json:"session_binding"`
	BindingSHA256        string `json:"session_binding_sha256"`
	RequestContextSHA256 string `json:"request_context_sha256"`
	TLSExporterSHA256    string `json:"tls_exporter_sha256"`
	Nonce                string `json:"nonce"`
}

type a2aTaskResponse struct {
	Task a2aTask `json:"task"`
}

type a2aTask struct {
	ID        string        `json:"id"`
	ContextID string        `json:"contextId"`
	Status    a2aTaskStatus `json:"status"`
	Artifacts []a2aArtifact `json:"artifacts,omitempty"`
}

type a2aTaskStatus struct {
	State     string `json:"state"`
	Timestamp string `json:"timestamp,omitempty"`
}

type a2aArtifact struct {
	ArtifactID string    `json:"artifactId"`
	Name       string    `json:"name,omitempty"`
	Parts      []a2aPart `json:"parts"`
}

type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type attestationResultClaims struct {
	jwt.RegisteredClaims
	ProfileType       string `json:"profile_type"`
	Platform          string `json:"platform"`
	Simulation        bool   `json:"simulation"`
	BinderSHA256      string `json:"binder_sha256"`
	EvidenceSHA256    string `json:"evidence_sha256"`
	MeasurementSHA256 string `json:"measurement_sha256"`
}

type simulatedEvidenceClaims struct {
	jwt.RegisteredClaims
	ProfileType      string `json:"profile_type"`
	Platform         string `json:"platform"`
	ReportDataSHA256 string `json:"report_data_sha256"`
	Measurement      string `json:"measurement"`
}
