# Static Diversion Policy

This profile defines a static diversion policy. It lives above routing,
discovery, and transport behavior.

## Goal

Semantic diversion is broader than a wrong service or tenant. A valid channel,
session, peer, or token can still be bound to the wrong semantic target,
context, delegation, capability, or authority boundary.

The static diversion policy covers the D3 part of that family: service, tenant,
deployment, environment, and agent target changes. It gives deployments a
fail-closed way to say which diversions are allowed, which are denied, and which
fields must be preserved for audit.

## Non-Goals

- dynamic routing;
- service discovery;
- load balancing;
- generic authorization policy;
- AGTP core message syntax.

## Policy Source

The verifier must load this policy from local configuration or a trusted policy
authority. It must not accept a policy supplied by the peer for the current
session.

## Required Behavior

- missing policy fails closed when diversion policy is required;
- unsupported policy version fails closed;
- missing `policy_id` fails closed;
- missing `reason_code` fails closed;
- missing required audit fields fails closed;
- policy miss fails closed;
- denied diversion fails closed;
- hidden diversion requires an explicit hidden-diversion rule;
- client-visible diversion can require proof that the client was notified.

## Required Audit Fields

A valid policy must require at least these fields:

- `policy_id`;
- `original_target`;
- `diverted_target`;
- `trigger`;
- `reason_code`.

The implementation may also preserve additional fields such as `rule_id` and
`visibility`.

## Canonical JSON Shape

The Go implementation reads JSON with this shape:

```json
{
  "policy_id": "diversion-policy-prod",
  "version": "1",
  "mode": "required",
  "audit_fields": [
    "policy_id",
    "original_target",
    "diverted_target",
    "trigger",
    "reason_code"
  ],
  "rules": [
    {
      "rule_id": "visible-failover",
      "original_target": {
        "service": "payments",
        "tenant": "tenant-a",
        "deployment": "prod-eu"
      },
      "diverted_target": {
        "service": "payments",
        "tenant": "tenant-a",
        "deployment": "prod-eu-backup"
      },
      "visibility": "client_visible",
      "trigger": "regional-failover",
      "reason_code": "maintenance",
      "allowed": true,
      "require_client_notice": true
    }
  ]
}
```

## YAML Equivalent

YAML may be used by deployment tooling, but this repository's Go package only
parses JSON to avoid adding a dependency.

```yaml
policy_id: diversion-policy-prod
version: "1"
mode: required
audit_fields:
  - policy_id
  - original_target
  - diverted_target
  - trigger
  - reason_code
rules:
  - rule_id: visible-failover
    original_target:
      service: payments
      tenant: tenant-a
      deployment: prod-eu
    diverted_target:
      service: payments
      tenant: tenant-a
      deployment: prod-eu-backup
    visibility: client_visible
    trigger: regional-failover
    reason_code: maintenance
    allowed: true
    require_client_notice: true
```

## Visibility

`client_visible` means the diversion is intended to be visible to the relying
client. A rule can require client notice before acceptance.

`hidden` means the diversion is not visible to the client. Hidden diversion is
rejected unless the static policy contains an explicit hidden rule for the same
original target, diverted target, trigger, and reason code.

## Implementation

The package `pkg/agtp/diversionpolicy` implements the static evaluator. It
returns `Decision.Outcome`, an audit record for valid inputs, and the existing
typed error. A matching allowed rule with all requirements met returns
`Permit` without an error. An explicit denial, missing client notice, or hidden
diversion without an explicit rule returns `Deny` with an error. An ordinary
policy miss returns `NotApplicable` with `ErrNoMatchingRule`. An invalid policy
or request returns `Indeterminate` with a validation error and no audit record.

Only `Permit` without an error authorizes a diversion. `NotApplicable` still
fails closed in required mode. `Indeterminate` means policy evaluation failed;
it does not describe the outcome of a dispatched operation.
