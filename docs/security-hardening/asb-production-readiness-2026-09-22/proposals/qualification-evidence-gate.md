# Security Hardening Proposal: Evidence-producing environment qualification

## Decision

Choose the mechanism that turns a source revision and target environment into a bounded,
reviewable qualification result without treating local tests as deployment assurance.

## Executive Recommendation

Option 1, **repository qualification bundle**, runs a declared profile on a target and emits a
machine-readable manifest, logs, hashes, and pass/fail status. Option 2, **independent lab track**,
adds isolated custody and review for claims that require external confidence. I recommend
Option 1 for every selected profile now. Option 2 should be required only for a published
certification or customer assurance level that names independent validation.

## Evidence

I inspected the current validation and completion documents. They carefully limit their claims,
which is the right starting point. The missing part is a common artifact format and gate that
binds those checks to the target environment.

| Evidence | Finding or document | What it establishes |
| --- | --- | --- |
| `ASB-HARD-006` | Developer Preview validation boundary | Current evidence excludes several OS, browser, disk-loss, renewal, HA, and live SNP/TDX properties. |

Sources: `docs/local-human-approval-validation.md` and `docs/asb-completion-plan.md`.

## Current Design And Failure Mode

The repository has local and hosted checks, but the remaining properties depend on filesystem,
service manager, browser, firmware, attestation collateral, network, and operator configuration.
A green generic workflow cannot establish them. The structural gap is an absent binding between
the declared deployment profile, immutable inputs, target facts, mandatory exercises, and the
resulting claim.

## Desired Invariants

- Every qualification result names the source commit, dirty-state policy, binary and config
  digests, target OS/kernel/firmware facts, profile, test versions, and timestamps.
- Missing, skipped, or unavailable mandatory checks fail the profile result.
- Raw secrets, attestation tokens, private keys, and customer data do not enter the bundle.
- A claim is limited to the profile and target that produced the evidence.
- Environment, configuration, or policy drift names a requalification trigger.

## Constraints And Non-Goals

The harness cannot create access to Windows, macOS, confidential-compute hardware, browsers,
managed databases, or paid providers. It records checks run there. A repository-generated bundle
is not automatically an independent certification.

## Before Architecture

[Before architecture](../diagrams/qualification-evidence-gate-before.mmd) shows the current gap:
source checks reach a preview result while real environment properties remain outside the
artifact boundary.

## Options

### Option 1: Repository qualification bundle

Define profile manifests such as `local-preview`, `linux-service`, `windows-runner`, `snp`, and
`tdx`. A harness rejects dirty or mismatched inputs according to profile policy, captures
allowlisted environment facts, runs mandatory exercises, and writes `qa-report.json`, command
logs, hashes, and a redacted evidence index. Each check reports pass, fail, or unavailable;
unavailable mandatory checks make the profile fail. The bundle can be signed by the operator or
CI identity after generation.

This makes present evidence reviewable and prevents a cross-build from being mislabeled as a
runtime check. It does not make the operator independent. Rollback removes the profile claim;
raw test scripts and existing CI can continue while the bundle stabilizes.

[Option 1 architecture](../diagrams/qualification-evidence-gate-bundle-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Test identity | workflow or notes | immutable manifest and target facts | narrows claim to evidence | schema and collection code |
| Missing checks | prose caveat | machine failure for mandatory checks | prevents accidental promotion | more red workflows until environments exist |
| Evidence | scattered logs | hashed, redacted bundle | supports review and replay | artifact storage and secret scanning |

### Option 2: Independent lab track

Run the same immutable candidate and profile policy in an environment controlled by an
independent internal team or external lab. Preserve chain of custody, review the bundle, and
issue a time-bounded result. Configuration, firmware, OS, collateral, or threat-model drift
triggers requalification.

This option is appropriate when the claim itself includes independent validation. It costs more,
slows iteration, and requires a stable acceptance policy. It should not block ordinary preview
engineering. Rollback withdraws or expires the qualification claim; it does not change the
software artifact.

[Option 2 architecture](../diagrams/qualification-evidence-gate-lab-after.mmd)

| Change | Before | After | Security consequence | Cost |
| --- | --- | --- | --- | --- |
| Custody | project/operator | independent environment and review | reduces self-attestation risk | scheduling and financial cost |
| Claim lifetime | informal/current | scoped and time-bounded | makes drift visible | renewal process |
| Acceptance | evolving tests | published stable policy | comparable results | policy-change governance |

## Comparison

| Dimension | Option 1 | Option 2 |
| --- | --- | --- |
| Security | strong evidence binding; operator remains trusted | adds custody and review separation |
| Performance | qualification runtime only | same tests plus transfer and review latency |
| Memory | logs and evidence bundle | duplicate retained bundle and review records |
| Reliability | automated and repeatable where targets exist | target and lab scheduling can delay releases |
| Operability | profile manifests, runners, redaction, artifact retention | contracts, custody, reviewer, expiration, requalification |
| Migration | can wrap existing tests incrementally | requires stable profile and immutable release candidate |

## Recommendation

I recommend Option 1 as the repository standard and an explicit `unqualified` result for every
profile without a real target run. Use Option 2 only when a release or customer claim requires
independent assurance. The absence of target access is a reason to preserve the boundary, not to
weaken the gate.

## Evidence Coverage And Residual Risk

| Evidence | Coverage | Residual risk |
| --- | --- | --- |
| `ASB-HARD-006` — preview validation boundary | Option 1 makes the boundary machine-readable; Option 2 adds independent review | test omissions, environmental drift, and secret-redaction defects remain possible |

A passed bundle proves only the declared exercises on the recorded target. It does not prove the
absence of vulnerabilities or general safety.

## Migration And Rollout

Start with the existing local Human approval tests and Linux service checks. Produce bundles in
advisory mode, validate redaction, then make mandatory profiles fail when a check is unavailable.
Add Windows and macOS runtime targets, followed by live SNP/TDX profiles only when those runners
exist. Old free-form validation notes remain historical evidence and must not be rewritten as
bundle results.

## Validation Plan

Test schema validation, deterministic hashing, dirty-tree rejection, secret-pattern rejection,
truncated-log handling, missing mandatory checks, and bundle verification on a separate host.
Exercise each supported target and independently recompute every artifact hash. Measure bundle
size and runtime against configured CI limits.

## Implementation Work Packages

- Define profile and `qa-report.json` schemas with claim and redaction rules.
- Implement the harness, immutable input checks, artifact hashing, and verifier.
- Wrap current local, systemd, Windows process-tree, backup/restore, browser, and attestation
  exercises as profile checks.
- Add target runners, evidence retention, signing, review, and requalification triggers.

## Open Questions

- Which exact profiles are release-blocking?
- Which OS, browser, filesystem, SNP/TDX platform, and managed service targets are selected?
- Who signs and reviews the qualification bundle?
- What event or age expires a qualification result?
