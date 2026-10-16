# Decision semantics review — 2026-10-16

This review covers the local Human approval change based on
`2e5a8136b183a748d7aed58e85c9f12c4c76f8fc`, plus the related checks below.
It is a focused source and regression-test review, not a repository-wide
security assessment or live-provider qualification.

## What is shared

The four Human answers are `APPROVE`, `DECLINE`, `NOT_APPLICABLE`, and
`UNDETERMINED`. Only `APPROVE` can authorize the proposed local change.
The other answers record different reasons for withholding permission.
They are known answers, even when the person cannot decide.

Other components do not all expose these four values. A cryptographic check
returns success or an error; a task assignment records acceptance of
responsibility; a quorum counts verified approvals. Their relevant shared
property is that a failed required check or absent authority does not grant
permission. Skipping an optional check does not establish the property it
would have verified.

An execution result is a separate concern. `OUTCOME_UNKNOWN`, `UNKNOWN`, or
`INDETERMINATE` after dispatch means an effect may have happened. It requires
status lookup or reconciliation, not a new authorization or a blind retry.

## Checked components

| Component | Decision contract and observed behavior |
| --- | --- |
| [Local Human approval](local-human-approval.md#four-human-decisions) | Four explicit answers. Non-approval results finish the proposal without changing the setting. Human `UNDETERMINED` is separate from request `OUTCOME_UNKNOWN`. |
| [Identity policy](../pkg/atls/identitypolicy/policy_v2.go) | Required missing or mismatched values return validation errors. If D7 is not required, effective authorization is empty; peer-provided authority is not copied. Required creator-isolation evidence fails when unavailable. |
| [Least privilege](../pkg/leastprivilege/authorization.go) | Returns a capability only after verification and mandate checks. `AllowAutomatic=false` returns `ErrHumanRequired`; an optimal solution alone grants no permission. [Durable execution](../pkg/leastprivilege/durable_execution.go) keeps `UNKNOWN` separate and does not redispatch unresolved operations. |
| [Diversion policy](../pkg/agtp/diversionpolicy/policy.go) | Explicit allow, deny, no matching rule, and invalid/missing requirements use a Boolean decision plus typed errors. Only a matching allowed rule with all requirements met yields permission. The audit inconsistency below was repaired. |
| [Task Coordination](../pkg/taskcoord/model.go) | Uses responsibility states such as `ACCEPTED` and `DECLINED`, not the four Human answers. [Action binding](../pkg/taskcoord/actionbinding/binding.go) requires `ACCEPTED`; unknown operations and other states cannot start execution. |
| [Authority quorum](../pkg/authorityquorum/memory_store.go) | Counts verified affirmative approvals only. Missing, expired, revoked, or insufficient approvals return errors. It does not store separate deny/out-of-scope/undetermined votes. |
| [Model runtime](../pkg/llmruntime/model.go) | Missing or mismatched model/bundle/LoRA pins, unavailable retrieval, unsupported adapters, and unverified external APIs return errors. Integrity success identifies approved bytes; it does not by itself prove benign model behavior. |
| [Required attestation](../pkg/atls/eaattestation/verify.go) | Empty required evidence and a missing verifier are errors. Optional evidence collection is a separate API with the legacy exception below. |
| [Action lifecycle](../pkg/actionlifecycle/model.go) and [operation journal](../pkg/operationjournal/journal.go) | `INDETERMINATE` is an unresolved execution outcome, not a Human judgment or permission. It cannot be treated as a known success or as permission to execute again. |
| [A2A test reports](../pkg/a2asecuritytest/validation.go) | Test evidence uses `PASS`, `FAIL`, `INDETERMINATE`, and `ERROR`. No HTTP response cannot validate as `PASS` or `FAIL`; aggregate uncertainty is not a passing result. These are test statuses, not authorization answers. |

## Repaired audit inconsistency

A diversion rule requiring client notice correctly rejected a request without
that notice, but its audit copied the rule's `Allowed=true`. A runtime probe
returned `decision_allowed=false`, `audit_allowed=true`, and
`ErrClientNoticeRequired`.

The audit now remains false until every required check passes. The same probe
returns false for both flags. Regression tests check the rejected case and
the successful case. The request was already blocked before this repair;
the change corrects the audit record, with no API shape change.

## Boundaries

The [protected-change sample](../examples/protected-change-consumer/README.md)
rejects verification failures before applying a change. Its current in-memory
store only reports failures before an effect, so its HTTP 409 response is
consistent with that store. Replacing it with an external store that can lose
a response after commit would require a separate unknown-outcome contract and
reconciliation. The sample does not establish that external behavior.

Evidence collection is also separate from verification. The legacy
`EmptyProvider` can return an empty Azure token without an error in the NoCC
configuration. That response is not verified attestation or permission.
An optional or simulated evidence source must not be described as a successful
required hardware check.

## Validation

The Human UI/API/CLI checks and browser results are recorded in
[the local approval validation log](local-human-approval-validation.md#four-human-decisions--2026-10-16).

The following additional local tests passed:

```text
go test ./pkg/agtp/diversionpolicy -count=1
go test -count=1 ./pkg/authorityquorum ./pkg/taskcoord ./pkg/taskcoord/actionbinding ./pkg/actionlifecycle ./examples/protected-change-consumer
go test -count=1 ./pkg/a2asecuritytest ./pkg/operationjournal
go test ./pkg/llmruntime ./pkg/atls/eaattestation ./pkg/atls/ea ./pkg/production -count=1
```

Twelve focused tests also passed across `leastprivilege`,
`leastprivilege/asbbinding`, and `identitypolicy`, covering missing Human
authorization, invalid candidates, budget/cancellation failures, absent D7
authority, missing isolation evidence, replay-state failures, and unresolved
execution outcomes.

Six focused A2A model/evidence tests passed. The Python loader/protocol suite
(`python3 -I -B pkg/llmruntime/transformers_server_test.py`) passed 18/18 on
repeat; its first run had a transient `BrokenPipeError` in the unavailable
adapter-endpoint test. No code was changed for that rerun. Scoped
golangci-lint 2.11.1 passed for the diversion-policy repair.

These checks used local fixtures. No new model was downloaded, opt-in real
Safetensors inference was not enabled, and no live SNP/TDX or external-provider
evidence was qualified by this review.
