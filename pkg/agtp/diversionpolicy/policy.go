// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Package diversionpolicy is an experimental reference adapter for static
// semantic-diversion policy checks. It is intentionally not a routing engine.
//
// Direct-Agent runtime verification does not depend on this package. Callers
// that use it are responsible for supplying verifier-local expected policy;
// peer-provided AGTP or gateway metadata must not become expected policy.
package diversionpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/policydecision"
)

var (
	ErrMissingPolicy        = errors.New("diversionpolicy: missing policy")
	ErrMissingPolicyID      = errors.New("diversionpolicy: missing policy id")
	ErrMissingRule          = errors.New("diversionpolicy: missing rule")
	ErrMissingTarget        = errors.New("diversionpolicy: missing target")
	ErrMissingReasonCode    = errors.New("diversionpolicy: missing reason code")
	ErrMissingAuditField    = errors.New("diversionpolicy: missing audit field")
	ErrUnsupportedVersion   = errors.New("diversionpolicy: unsupported version")
	ErrInvalidMode          = errors.New("diversionpolicy: invalid mode")
	ErrInvalidVisibility    = errors.New("diversionpolicy: invalid visibility")
	ErrNoMatchingRule       = errors.New("diversionpolicy: no matching rule")
	ErrHiddenNotAllowed     = errors.New("diversionpolicy: hidden diversion not allowed")
	ErrClientNoticeRequired = errors.New("diversionpolicy: client notice required")
	ErrDenied               = errors.New("diversionpolicy: diversion denied")
	ErrUnsafeValue          = errors.New("diversionpolicy: unsafe value")
)

const (
	Version = "1"

	ModeRequired = "required"

	VisibilityClientVisible Visibility = "client_visible"
	VisibilityHidden        Visibility = "hidden"
)

const (
	AuditFieldPolicyID       = "policy_id"
	AuditFieldOriginalTarget = "original_target"
	AuditFieldDivertedTarget = "diverted_target"
	AuditFieldTrigger        = "trigger"
	AuditFieldReasonCode     = "reason_code"
	AuditFieldRuleID         = "rule_id"
	AuditFieldVisibility     = "visibility"
)

// Visibility says whether a diversion is visible to the client.
type Visibility string

// Target identifies the semantic endpoint selected by the profile.
type Target struct {
	Service     string `json:"service,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
	Deployment  string `json:"deployment,omitempty"`
	Environment string `json:"environment,omitempty"`
	Agent       string `json:"agent,omitempty"`
}

// Policy is a static diversion policy. It must be supplied by local
// configuration or a trusted policy authority, not by the AGTP peer.
type Policy struct {
	PolicyID    string   `json:"policy_id"`
	Version     string   `json:"version"`
	Mode        string   `json:"mode"`
	AuditFields []string `json:"audit_fields"`
	Rules       []Rule   `json:"rules"`
}

// Rule allows or denies one exact static diversion.
type Rule struct {
	RuleID              string     `json:"rule_id"`
	OriginalTarget      Target     `json:"original_target"`
	DivertedTarget      Target     `json:"diverted_target"`
	Visibility          Visibility `json:"visibility"`
	Trigger             string     `json:"trigger"`
	ReasonCode          string     `json:"reason_code"`
	Allowed             bool       `json:"allowed"`
	RequireClientNotice bool       `json:"require_client_notice"`
}

// Request is the diversion decision requested by the caller.
type Request struct {
	OriginalTarget Target
	DivertedTarget Target
	Visibility     Visibility
	Trigger        string
	ReasonCode     string
	ClientNotified bool
}

// Decision records the outcome plus the audit material callers should log.
type Decision struct {
	Outcome policydecision.Outcome
	Audit   AuditRecord
}

// AuditRecord is deliberately small and stable so callers can preserve the
// security-relevant decision fields without logging arbitrary peer metadata.
type AuditRecord struct {
	PolicyID       string                 `json:"policy_id"`
	RuleID         string                 `json:"rule_id,omitempty"`
	OriginalTarget Target                 `json:"original_target"`
	DivertedTarget Target                 `json:"diverted_target"`
	Visibility     Visibility             `json:"visibility"`
	Trigger        string                 `json:"trigger"`
	ReasonCode     string                 `json:"reason_code"`
	Outcome        policydecision.Outcome `json:"outcome"`
}

// LoadJSON decodes a static diversion policy from JSON.
func LoadJSON(r io.Reader) (Policy, error) {
	var policy Policy
	if err := json.NewDecoder(r).Decode(&policy); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// Evaluate checks one requested diversion against this static policy.
func (p Policy) Evaluate(req Request) (Decision, error) {
	if err := p.Validate(); err != nil {
		return Decision{Outcome: policydecision.Indeterminate}, err
	}
	if err := validateRequest(req); err != nil {
		return Decision{Outcome: policydecision.Indeterminate}, err
	}

	if req.Visibility == VisibilityHidden && !p.hasHiddenRuleFor(req) {
		return Decision{Outcome: policydecision.Deny, Audit: auditForRequest(p.PolicyID, "", req, policydecision.Deny)}, ErrHiddenNotAllowed
	}

	for _, rule := range p.Rules {
		if !rule.matches(req) {
			continue
		}
		audit := AuditRecord{
			PolicyID:       p.PolicyID,
			RuleID:         rule.RuleID,
			OriginalTarget: req.OriginalTarget,
			DivertedTarget: req.DivertedTarget,
			Visibility:     req.Visibility,
			Trigger:        req.Trigger,
			ReasonCode:     req.ReasonCode,
		}
		if rule.RequireClientNotice && !req.ClientNotified {
			audit.Outcome = policydecision.Deny
			return Decision{Outcome: policydecision.Deny, Audit: audit}, ErrClientNoticeRequired
		}
		if !rule.Allowed {
			audit.Outcome = policydecision.Deny
			return Decision{Outcome: policydecision.Deny, Audit: audit}, ErrDenied
		}
		audit.Outcome = policydecision.Permit
		return Decision{Outcome: policydecision.Permit, Audit: audit}, nil
	}

	return Decision{Outcome: policydecision.NotApplicable, Audit: auditForRequest(p.PolicyID, "", req, policydecision.NotApplicable)}, ErrNoMatchingRule
}

// Validate checks policy shape and fail-closed requirements.
func (p Policy) Validate() error {
	var errs []error
	if p.PolicyID == "" {
		errs = append(errs, ErrMissingPolicyID)
	} else if err := validateValue(p.PolicyID); err != nil {
		errs = append(errs, fmt.Errorf("%w: policy_id", err))
	}
	if p.Version != Version {
		errs = append(errs, ErrUnsupportedVersion)
	}
	if p.Mode != ModeRequired {
		errs = append(errs, ErrInvalidMode)
	}
	if err := validateAuditFields(p.AuditFields); err != nil {
		errs = append(errs, err)
	}
	if len(p.Rules) == 0 {
		errs = append(errs, ErrMissingRule)
	}
	for i, rule := range p.Rules {
		if err := rule.validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %d: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

func (p Policy) hasHiddenRuleFor(req Request) bool {
	for _, rule := range p.Rules {
		if rule.Visibility == VisibilityHidden && rule.matches(req) {
			return true
		}
	}
	return false
}

func (r Rule) validate() error {
	var errs []error
	if r.RuleID == "" {
		errs = append(errs, ErrMissingRule)
	} else if err := validateValue(r.RuleID); err != nil {
		errs = append(errs, fmt.Errorf("%w: rule_id", err))
	}
	if err := validateTarget(r.OriginalTarget); err != nil {
		errs = append(errs, fmt.Errorf("original_target: %w", err))
	}
	if err := validateTarget(r.DivertedTarget); err != nil {
		errs = append(errs, fmt.Errorf("diverted_target: %w", err))
	}
	if err := validateVisibility(r.Visibility); err != nil {
		errs = append(errs, err)
	}
	if err := validateValue(r.Trigger); err != nil {
		errs = append(errs, fmt.Errorf("%w: trigger", err))
	}
	if r.ReasonCode == "" {
		errs = append(errs, ErrMissingReasonCode)
	} else if err := validateValue(r.ReasonCode); err != nil {
		errs = append(errs, fmt.Errorf("%w: reason_code", err))
	}
	if r.Visibility == VisibilityHidden && r.RequireClientNotice {
		errs = append(errs, ErrInvalidVisibility)
	}
	return errors.Join(errs...)
}

func (r Rule) matches(req Request) bool {
	return r.OriginalTarget == req.OriginalTarget &&
		r.DivertedTarget == req.DivertedTarget &&
		r.Visibility == req.Visibility &&
		r.Trigger == req.Trigger &&
		r.ReasonCode == req.ReasonCode
}

func validateRequest(req Request) error {
	var errs []error
	if err := validateTarget(req.OriginalTarget); err != nil {
		errs = append(errs, fmt.Errorf("original_target: %w", err))
	}
	if err := validateTarget(req.DivertedTarget); err != nil {
		errs = append(errs, fmt.Errorf("diverted_target: %w", err))
	}
	if err := validateVisibility(req.Visibility); err != nil {
		errs = append(errs, err)
	}
	if err := validateValue(req.Trigger); err != nil {
		errs = append(errs, fmt.Errorf("%w: trigger", err))
	}
	if req.ReasonCode == "" {
		errs = append(errs, ErrMissingReasonCode)
	} else if err := validateValue(req.ReasonCode); err != nil {
		errs = append(errs, fmt.Errorf("%w: reason_code", err))
	}
	return errors.Join(errs...)
}

func validateTarget(target Target) error {
	if target == (Target{}) {
		return ErrMissingTarget
	}
	for name, value := range map[string]string{
		"service":     target.Service,
		"tenant":      target.Tenant,
		"deployment":  target.Deployment,
		"environment": target.Environment,
		"agent":       target.Agent,
	} {
		if value == "" {
			continue
		}
		if err := validateValue(value); err != nil {
			return fmt.Errorf("%w: %s", err, name)
		}
	}
	return nil
}

func validateVisibility(visibility Visibility) error {
	switch visibility {
	case VisibilityClientVisible, VisibilityHidden:
		return nil
	default:
		return ErrInvalidVisibility
	}
}

func validateAuditFields(fields []string) error {
	required := map[string]bool{
		AuditFieldPolicyID:       false,
		AuditFieldOriginalTarget: false,
		AuditFieldDivertedTarget: false,
		AuditFieldTrigger:        false,
		AuditFieldReasonCode:     false,
	}
	for _, field := range fields {
		if err := validateValue(field); err != nil {
			return fmt.Errorf("%w: audit_fields", err)
		}
		if _, ok := required[field]; ok {
			required[field] = true
		}
	}
	for field, present := range required {
		if !present {
			return fmt.Errorf("%w: %s", ErrMissingAuditField, field)
		}
	}
	return nil
}

func validateValue(value string) error {
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
		return ErrUnsafeValue
	}
	if len(value) > 512 || !utf8.ValidString(value) {
		return ErrUnsafeValue
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return ErrUnsafeValue
		}
	}
	return nil
}

func auditForRequest(policyID, ruleID string, req Request, outcome policydecision.Outcome) AuditRecord {
	return AuditRecord{
		PolicyID:       policyID,
		RuleID:         ruleID,
		OriginalTarget: req.OriginalTarget,
		DivertedTarget: req.DivertedTarget,
		Visibility:     req.Visibility,
		Trigger:        req.Trigger,
		ReasonCode:     req.ReasonCode,
		Outcome:        outcome,
	}
}
