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
| [Local Human approval](local-human-approval.md#four-human-decisions) | Four explicit Human answers. Non-approval results finish the proposal without changing the setting. Its actor/command policy also returns four distinct authorization outcomes; only `Permit` allows a command. Human `UNDETERMINED` is separate from request `OUTCOME_UNKNOWN`. |
| [Identity policy](../pkg/atls/identitypolicy/policy_v2.go) | Required missing or mismatched values return validation errors. If D7 is not required, effective authorization is empty; peer-provided authority is not copied. Required creator-isolation evidence fails when unavailable. |
| [Least privilege](../pkg/leastprivilege/authorization.go) | Returns a capability only after verification and mandate checks. `AllowAutomatic=false` returns `ErrHumanRequired`; an optimal solution alone grants no permission. [Durable execution](../pkg/leastprivilege/durable_execution.go) keeps `UNKNOWN` separate and does not redispatch unresolved operations. |
| [Diversion policy](../pkg/agtp/diversionpolicy/policy.go) | The current evaluator returns `Permit`, `Deny`, `Indeterminate`, or `NotApplicable` with typed errors. Only `Permit` without an error authorizes diversion. The earlier Boolean audit repair is described below. |
| [Task Coordination](../pkg/taskcoord/model.go) | Uses responsibility states such as `ACCEPTED` and `DECLINED`, not the four Human answers. The [Human delegation policy adapter](../pkg/taskcoord/asbbinding/profile.go) returns four policy outcomes; only `Permit` with a matching verified delegation can advance the assignment. [Action binding](../pkg/taskcoord/actionbinding/binding.go) requires `ACCEPTED`; unknown operations and other states cannot start execution. |
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

At the time of that repair, the audit remained false until every required
check passed, and the same probe returned false for both flags. Regression
tests checked the rejected and successful cases. The request was already
blocked before this repair, which did not change the API shape at that time.
The current API uses `Decision.Outcome` and `Audit.Outcome` instead.

## Boundaries

The [protected-change sample](../examples/protected-change-consumer/README.md)
rejects verification failures before applying a change. Its current in-memory
store only reports failures before an effect, so its HTTP 409 response is
consistent with that store. Replacing it with an external store that can lose
a response after commit would require a separate unknown-outcome contract and
reconciliation. The sample does not establish that external behavior.

Evidence collection is also separate from verification. The initial review
found that legacy `EmptyProvider.AzureAttestationToken` returned empty bytes
without an error. The follow-up below corrects that collection contract.
An optional or simulated evidence source is not a successful required hardware
check.

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

## Empty collection follow-up — 2026-10-16

The legacy Azure collector now returns an error when no attester is configured.
CC-agent responses, configured MAA token responses, and all three legacy gRPC
client methods reject nil or empty results. Provider/RPC errors still take
precedence over any partial payload. The service rejects empty provider output
before returning raw evidence, an Azure token, or an encoded EAT.

The Azure handler was also named `GetAzureToken`, while the generated server
dispatches `FetchAzureToken`. Thus the earlier empty-success observation
described a direct method call; the actual Azure RPC returned `Unimplemented`.
The handler now implements the existing proto method. An in-memory gRPC test
uses generated clients and server registration to cover the real dispatch.
The protobuf and public client signatures are unchanged.

This change preserves existing nonempty sample behavior: embedded vTPM sample
bytes remain available, and the `UNSPECIFIED` EAT path remains labeled `NoCC`.
An empty embedded sample is rejected. The CC-agent's nonempty Azure evidence
fallback is also preserved. None of these collection results establishes
hardware authenticity, freshness, or a verified Azure token; callers still
need evidence validation.

Local validation passed for all five changed Go packages:

```sh
go test -race -count=1 ./cmd/attestation-service ./pkg/attestation ./pkg/attestation/azure ./pkg/attestation/ccaa ./pkg/clients/grpc/attestation
go vet ./cmd/attestation-service ./pkg/attestation ./pkg/attestation/azure ./pkg/attestation/ccaa ./pkg/clients/grpc/attestation
golangci-lint run ./cmd/attestation-service ./pkg/attestation ./pkg/attestation/azure ./pkg/attestation/ccaa ./pkg/clients/grpc/attestation
```

The regression cases cover nil responses, nil and empty payloads, upstream
errors with partial payloads, exact preservation of nonempty results, and the
existing sample paths. They include generated gRPC dispatch and Unix-socket
client calls. Lint reported zero issues, and `git diff --check` passed.
These checks used local fixtures; no live hardware or external MAA service
was tested.

## Nonempty and sample evidence follow-up — 2026-10-17

The required verification paths were checked at base commit `0d7b8359`.
The nonempty malformed and sample inputs below were already rejected. An
additional connection test found that a valid Finished-only empty authenticator
bypassed the required attestation policy. This follow-up repairs that path and
adds regression coverage for both findings.

| Path | Added regression coverage |
| --- | --- |
| [Core payload verification](../pkg/atls/eaattestation/verification_test.go) | Real TLS binding with verifier doubles: every supplied statement needs its own verifier; rejection propagates and returns no partially verified payload. Positive controls cover accepted evidence and accepted results. |
| [SNP/TDX compatibility verifier](../integrations/cocos/platformmodule/sample_evidence_test.go) | Rejects malformed EAT, unsigned sample claims, trusted signed NoCC/vTPM/sample claims, and sample bytes relabeled as SNP or TDX. Inputs include the actual embedded fixture, the service's 96-byte NoCC layout, and representative CC sample JSON. |
| [Required exported authenticator](../integrations/cocos/platformmodule/required_evidence_test.go) | Real TLS/EA signatures and binder with the concrete SNP verifier: valid signed SNP test evidence succeeds; malformed EAT, signed NoCC, and a trusted EAT wrapping a forged SNP signature return no validation result. |
| [Required connection](../pkg/atls/internal_transport/required_attestation_test.go) | A valid TLS peer sends a Finished-only empty authenticator with identity policy disabled. Required attestation must reject it without returning a connection; optional attestation preserves the empty-response behavior. |
| [Production bridge and profile](../pkg/production/required_evidence_test.go) | Concrete MAA token verification rejects nonempty opaque/sample input, unsigned JWTs, damaged signatures, forged trusted key IDs, and NoCC claims. Required profile verification rejects altered signatures/payloads and disallowed sample measurements, returns no accepted identity, and does not commit replay state. |

The embedded fixture can parse as an SNP ABI report. When relabeled as SNP,
it fails cryptographic authentication; rejection is not attributed to a
parser error or an unavailable network. A valid signed SNP fixture succeeds
under the same local trust and measurement policy. The NoCC sample includes
the correct report data and nonce, showing that copied session values alone
do not qualify it as hardware evidence.

These tests distinguish the outer EAT signature from verification of its raw
hardware report. Legacy `VerifyWithCoRIM` helpers compare measurements; that
operation alone is not cryptographic evidence verification. The compatibility
path exercises the SNP/TDX module before measurement appraisal. The production
profile separately trusts a configured verifier's signed appraisal and an
explicit measurement allowlist.

Before the repair, the required connection regression returned a non-nil
connection and no error. The EA-level regression also returned `Empty: true`
without error when evidence, results, or both verifiers were configured. The
Finished-only branch now returns `ErrMissingAttestation` when attestation is
required, after validating Finished and consuming the request context. Optional
empty responses retain their existing meaning; invalid Finished messages still
fail their cryptographic check.

Local validation passed:

```sh
go test -race -count=1 ./pkg/atls/eaattestation ./pkg/production ./integrations/cocos/platformmodule
go test -race -count=1 ./pkg/atls/ea ./pkg/atls/eaattestation
go test -race -count=1 ./pkg/atls/internal_transport
go test -race -count=1 ./integrations/cocos/platformmodule
go vet ./pkg/atls/ea ./pkg/atls/eaattestation ./pkg/atls/internal_transport ./pkg/production ./integrations/cocos/platformmodule
golangci-lint run ./pkg/atls/ea ./pkg/atls/eaattestation ./pkg/atls/internal_transport ./pkg/production ./integrations/cocos/platformmodule
sh scripts/check-asb-core-boundary.sh
```

The EA, transport, and composed platform suites passed after the Finished-only
repair. Lint version 2.11.1 reported zero issues, and `git diff --check` passed.

The first CI attempt caught the new test's direct CBOR import still classified
as indirect in the Cocos module. That metadata was corrected without changing
dependency versions. From `integrations/cocos`, `GOWORK=off go mod tidy -diff`,
`GOWORK=off go mod verify`, `GOWORK=off go test -race -count=1 ./platformmodule`,
and `GOWORK=off go vet ./platformmodule` then passed.

The package suites also retain existing successful and explicit software-only
cases. Evidence is offline with generated test trust roots. The CC JSON is a
representative fixture, not a live agent response. These additions do not
qualify live SNP/TDX hardware, Azure, or a full successful TDX appraisal, and
cannot establish safety for an arbitrary custom verifier or a policy that
explicitly authorizes sample measurements.
