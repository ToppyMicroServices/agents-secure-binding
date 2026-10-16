// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package diversionpolicy

import (
	"errors"
	"strings"
	"testing"
)

func TestEvaluateAcceptsClientVisibleDiversion(t *testing.T) {
	policy := testPolicy()
	request := testRequest()

	decision, err := policy.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Allowed || !decision.Audit.Allowed {
		t.Fatal("Evaluate() decision is not allowed")
	}
	if decision.Audit.PolicyID != policy.PolicyID {
		t.Fatalf("audit policy id = %q, want %q", decision.Audit.PolicyID, policy.PolicyID)
	}
	if decision.Audit.OriginalTarget != request.OriginalTarget {
		t.Fatalf("audit original target = %#v, want %#v", decision.Audit.OriginalTarget, request.OriginalTarget)
	}
	if decision.Audit.DivertedTarget != request.DivertedTarget {
		t.Fatalf("audit diverted target = %#v, want %#v", decision.Audit.DivertedTarget, request.DivertedTarget)
	}
	if decision.Audit.Trigger != request.Trigger || decision.Audit.ReasonCode != request.ReasonCode {
		t.Fatalf("audit trigger/reason = %q/%q", decision.Audit.Trigger, decision.Audit.ReasonCode)
	}
}

func TestEvaluateRejectsHiddenDiversionWithoutExplicitRule(t *testing.T) {
	policy := testPolicy()
	request := testRequest()
	request.Visibility = VisibilityHidden

	decision, err := policy.Evaluate(request)
	if !errors.Is(err, ErrHiddenNotAllowed) {
		t.Fatalf("Evaluate() error = %v, want %v", err, ErrHiddenNotAllowed)
	}
	if decision.Allowed {
		t.Fatal("Evaluate() allowed hidden diversion without explicit rule")
	}
	if decision.Audit.PolicyID != policy.PolicyID {
		t.Fatalf("audit policy id = %q, want %q", decision.Audit.PolicyID, policy.PolicyID)
	}
}

func TestEvaluateRejectsWrongDivertedTarget(t *testing.T) {
	policy := testPolicy()
	request := testRequest()
	request.DivertedTarget.Deployment = "prod-us"

	_, err := policy.Evaluate(request)
	if !errors.Is(err, ErrNoMatchingRule) {
		t.Fatalf("Evaluate() error = %v, want %v", err, ErrNoMatchingRule)
	}
}

func TestEvaluateRejectsDeniedRuleAndPreservesAudit(t *testing.T) {
	policy := testPolicy()
	policy.Rules[0].Allowed = false
	request := testRequest()

	decision, err := policy.Evaluate(request)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Evaluate() error = %v, want %v", err, ErrDenied)
	}
	if decision.Allowed {
		t.Fatal("Evaluate() allowed denied rule")
	}
	if decision.Audit.RuleID != policy.Rules[0].RuleID {
		t.Fatalf("audit rule id = %q, want %q", decision.Audit.RuleID, policy.Rules[0].RuleID)
	}
	if decision.Audit.ReasonCode != request.ReasonCode {
		t.Fatalf("audit reason = %q, want %q", decision.Audit.ReasonCode, request.ReasonCode)
	}
}

func TestEvaluateRejectsClientVisibleDiversionWithoutNotice(t *testing.T) {
	policy := testPolicy()
	request := testRequest()
	request.ClientNotified = false

	decision, err := policy.Evaluate(request)
	if !errors.Is(err, ErrClientNoticeRequired) {
		t.Fatalf("Evaluate() error = %v, want %v", err, ErrClientNoticeRequired)
	}
	if decision.Allowed || decision.Audit.Allowed {
		t.Fatalf("Evaluate() recorded permission without required notice: %#v", decision)
	}
	if decision.Audit.RuleID != policy.Rules[0].RuleID {
		t.Fatalf("audit rule id = %q, want %q", decision.Audit.RuleID, policy.Rules[0].RuleID)
	}
}

func TestValidateRejectsMissingAuditField(t *testing.T) {
	policy := testPolicy()
	policy.AuditFields = []string{
		AuditFieldPolicyID,
		AuditFieldOriginalTarget,
		AuditFieldDivertedTarget,
		AuditFieldTrigger,
	}

	err := policy.Validate()
	if !errors.Is(err, ErrMissingAuditField) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrMissingAuditField)
	}
}

func TestValidateRejectsUnsupportedVersion(t *testing.T) {
	policy := testPolicy()
	policy.Version = "2"

	err := policy.Validate()
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Validate() error = %v, want %v", err, ErrUnsupportedVersion)
	}
}

func TestLoadJSON(t *testing.T) {
	policy, err := LoadJSON(strings.NewReader(`{
		"policy_id": "diversion-policy-prod",
		"version": "1",
		"mode": "required",
		"audit_fields": ["policy_id", "original_target", "diverted_target", "trigger", "reason_code"],
		"rules": [{
			"rule_id": "visible-failover",
			"original_target": {"service": "payments", "tenant": "tenant-a", "deployment": "prod-eu"},
			"diverted_target": {"service": "payments", "tenant": "tenant-a", "deployment": "prod-eu-backup"},
			"visibility": "client_visible",
			"trigger": "regional-failover",
			"reason_code": "maintenance",
			"allowed": true,
			"require_client_notice": true
		}]
	}`))
	if err != nil {
		t.Fatalf("LoadJSON() error = %v", err)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func testPolicy() Policy {
	return Policy{
		PolicyID: "diversion-policy-prod",
		Version:  Version,
		Mode:     ModeRequired,
		AuditFields: []string{
			AuditFieldPolicyID,
			AuditFieldOriginalTarget,
			AuditFieldDivertedTarget,
			AuditFieldTrigger,
			AuditFieldReasonCode,
		},
		Rules: []Rule{
			{
				RuleID: "visible-failover",
				OriginalTarget: Target{
					Service:    "payments",
					Tenant:     "tenant-a",
					Deployment: "prod-eu",
				},
				DivertedTarget: Target{
					Service:    "payments",
					Tenant:     "tenant-a",
					Deployment: "prod-eu-backup",
				},
				Visibility:          VisibilityClientVisible,
				Trigger:             "regional-failover",
				ReasonCode:          "maintenance",
				Allowed:             true,
				RequireClientNotice: true,
			},
		},
	}
}

func testRequest() Request {
	return Request{
		OriginalTarget: Target{
			Service:    "payments",
			Tenant:     "tenant-a",
			Deployment: "prod-eu",
		},
		DivertedTarget: Target{
			Service:    "payments",
			Tenant:     "tenant-a",
			Deployment: "prod-eu-backup",
		},
		Visibility:     VisibilityClientVisible,
		Trigger:        "regional-failover",
		ReasonCode:     "maintenance",
		ClientNotified: true,
	}
}
