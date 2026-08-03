# Agents Secure Binding

Agents Secure Binding is a verifier-side acceptance profile and implementation
repository for binding an Agent identity to the session, context, attestation
facts, and local policy under which it is accepted.

A verifier accepts an Agent only when a verified authority grant,
holder-of-key proof, accepted TLS or exported-authenticator session, freshness
and replay state, any required attestation result, and verifier-local policy
all describe the same intended interaction.

The primary failure class is context diversion: accepting cryptographically
valid material for a different service, tenant, Agent, task, delegation, or
authority boundary than the verifier intended.

Release `v1.0.0` defines a supported verifier product surface for the
Direct-Agent v1 profile. It adds one complete deployment composition covering
role-separated trust keys, revocation, signed attestation results, TLS-protected
distributed replay, and a concrete protected-change consumer. See
[`docs/API_COMPATIBILITY.md`](docs/API_COMPATIBILITY.md) and
[`docs/production-deployment-profile.md`](docs/production-deployment-profile.md).

## Acceptance Contract

The verifier evaluates one ordered contract:

1. Authenticate the authority grant and its policy scope.
2. Verify holder-of-key proof over the exact grant and accepted session.
3. Check freshness, nonce, and replay state.
4. Bind any required attestation result to the same session.
5. Compare authenticated observed values with verifier-local expected policy.
6. Commit one-shot replay state before returning the accepted identity.

The core implementation is centered on `pkg/clients`, `pkg/atls`, and
`pkg/atls/identitypolicy`. `pkg/agtp` contains reference adapters for JWT/JWS,
CWT/COSE, and gateway-route policy experiments.

## Repository Map

- `docs/SSOT.md`: normative repository source for profile behavior, dimensions,
  verification order, and compatibility notes.
- `docs/threat-model.md`: explanatory relay, replay, diversion, wrong-Agent,
  gateway-route, downgrade, and privacy threat model.
- `docs/draft06-a2a-profile.md`: experimental, non-normative draft-06-inspired
  v2 profile for the multiprocess A2A demonstration.
- `docs/live-red-team-report.md`: current live-style red-team evidence and
  evaluation boundaries.
- `docs/API_COMPATIBILITY.md`: supported v1 API and compatibility policy.
- `docs/production-deployment-profile.md`: fixed production choices for trust,
  revocation, attestation, distributed replay, and exact action binding.
- `formal/`: ProVerif and TLA+ models, recorded results, and
  model-to-implementation traceability.
- `pkg/clients`, `pkg/atls`, and `pkg/atls/identitypolicy`: Direct-Agent
  acceptance implementation.
- `pkg/production`: supported fail-closed composition and Redis/Valkey replay
  adapter.
- `examples/protected-change-consumer`: independent HTTPS application consumer
  and E2E negative tests; it is not Split-Knowledge.
- `PUBLICATION_TODO.md`: publication blockers, inherited runtime risk
  classification, module identity choice, and CI/red-team checkpoint status.

## Profile Overview

The core invariant is simple: a verifier must not return a
profile-authenticated Agent identity unless the verified grant, proof, accepted
session, freshness state, replay state, any required attestation result, and
local policy identify the same intended interaction.

This profile uses D0 through D6 as acceptance dimensions for policy separation
and diagnostics.

| Dimension | Verification target | Main failure class |
| --- | --- | --- |
| D0 | Live TLS or exported-authenticator session | MITM or session confusion |
| D1 | Attested platform validity, when required | Fake, malformed, stale, or untrusted evidence |
| D2 | Attestation or authenticator-to-session binding | Relay, replay, or borrowed evidence |
| D3 | Service, tenant, deployment, or environment | Wrong service or tenant; context diversion |
| D4 | Workload, process, or Agent | Same-host wrong-Agent confusion |
| D5 | Task, thread, context, or delegation | Wrong task or delegation; context diversion |
| D6 | Authorization or capability policy | Confused deputy or privilege escalation |

D0 through D2 are authentication and binding dimensions. D3 through D6 are
verifier-local policy dimensions. Peer-provided metadata can be observed input;
it is not expected policy.

The separate experimental A2A v2 profile splits target selection into D6 and
effective authorization into D7. It does not change the existing v1 dimension
mapping, API, or wire format.

A concrete binding profile must still define its profile identifier, protocol
identifier, TLS exporter label, canonical audience form, `grant_hash` bytes,
session-proof encoding, request-context construction, nonce and replay rules,
attestation requirement, D3 through D6 expected-value source, and diagnostic
error classes.

Decision-sensitive values such as `intent_ref`, `capability_ref`, and
`ontology_id` must already be canonical before acceptance. Receivers compare
them deterministically and do not repair peer-provided aliases, display labels,
URI variants, natural-language phrases, or model interpretations in the final
acceptance path.

## Evaluation Evidence

The release evidence covers:

- focused local checks and unit-level coverage;
- positive and negative profile vectors;
- relay, replay, wrong-context, wrong-Agent, downgrade, stale-evidence,
  measurement-mismatch, and binding-parameter confusion checks;
- dependency-free live-style harnesses for local TLS exporter binding, HTTP/2
  and gRPC connection reuse, TLS resumption replay rejection, QUIC/TLS
  early-data pre-binding rejection, malformed token corpora, bounded fuzz smoke
  for compact JWT/JWS parsing, and deterministic acceptance invariants;
- route-assertion policy tests and a local HTTP route-assertion harness for the
  documented gateway boundary.
- a production composition with current trust/revocation snapshots, signed
  attestation-result policy, and TLS-only Redis/Valkey SETNX replay;
- an independent protected-change HTTPS consumer that rejects a changed
  action, wrong TLS session, replay, revoked grant, attestation mismatch, and
  replay-store outage; and
- a 20-client TLS replay-store race that requires exactly one SETNX winner.

For accepted TLS sessions, the AGTP observed-identity path derives
`tls_exporter_sha256` from the accepted `tls.ConnectionState`. Fixed exporter
bytes are used only in synthetic unit fixtures.

The latest recorded signed implementation checkpoint is commit
`9684c3d08785bad344cf32cdd812eefd892caccf`; GitHub reports its signature as
verified. GitHub Actions `CI` run `30782322021`, `Security Red Team` run
`30782322016`, and `Proto Consistency` run `30782322014` completed successfully
on 2026-08-03 UTC.

See `docs/live-red-team-report.md` for the evidence matrix.

## Agent-to-Agent Demonstration

Run the multiprocess A2A 1.0 demonstration:

```sh
go run ./examples/a2a-multiprocess
```

It separates Manager, Attester, Verifier, durable Replay Store, Agent A, and
Agent B into operating-system processes. The same binary has a Docker Compose
topology and an optional fail-closed SNP/TDX hardware mode. See the
[multiprocess demonstration guide](examples/a2a-multiprocess/README.md) for the
protocol subset, trust boundaries, Docker command, hardware prerequisites, and
negative scenarios. The guide also shows how to select the separate
draft-06-inspired v2 profile; the no-flag behavior remains v1.

The smaller software-only binding demonstration remains available:

```sh
go run ./examples/a2a
```

The demo creates ephemeral keys and certificates, opens a mutually
authenticated TLS 1.3 connection, derives the live TLS exporter and canonical
request-context binding, and sends a task with a Manager-signed grant and an
Agent-signed Session Binding Statement. Agent B applies its own expected policy
and replay state before accepting the task.

The same run shows fail-closed rejection of scope escalation, a request for a
resource outside the authenticated grant, a wrong audience, a binding borrowed
from another TLS session, and reuse of an accepted binding. It is a
software-only localhost demonstration; it does not perform hardware attestation
or define an application-protocol message format.

## Formal Assurance

The repository includes two complementary formal models:

- `formal/proverif/binding_acceptance.pv` checks signing-key secrecy,
  correspondence from acceptance to an authority-issued grant and exact Agent
  binding, and injective Agent-binding correspondence. ProVerif 2.05 reported
  all five selected queries as true.
- `formal/tla/DurableGate.tla` checks a generic durable-state target contract
  for replay, revocation, leases, audit delivery, restart, failure handling,
  and logical time. TLC generated 7,692,655 states and found 1,555,674 distinct
  states without an invariant violation in the recorded finite configuration.

`formal/MODEL_MAP.md` identifies the current implementation surface for the
binding model and the remaining implementation boundary for the durable-state
model.

## Implementation Provenance

This repository contains derived runtime, attestation, legacy `pkg/atls`,
manager, agent, HAL, proxy, OCI, and helper code from
[ultravioletrs/cocos](https://github.com/ultravioletrs/cocos), plus
profile-specific documentation, tests, vectors, and security-profile helpers
for Agents Secure Binding.

The repository keeps the Apache-2.0 license and retained upstream notices. See
`ATTRIBUTION.md`.

Repository identity note: the public repository name and Go module path are
both `github.com/thinksyncs/agents-secure-binding`.

## Verification Commands

Local implementation checks:

```sh
go test ./pkg/atls/identitypolicy
go test ./pkg/clients ./pkg/clients/http ./pkg/clients/grpc
```

Reference-adapter checks:

```sh
go test ./pkg/agtp ./pkg/agtp/gatewayroute
```

Focused Direct-Agent red-team check:

```sh
GOTOOLCHAIN=go1.26.0+auto go test -v -race -count=1 \
  ./pkg/atls/identitypolicy \
  ./pkg/clients
```

Product security gate:

```sh
make product-security-gate
```

Focused production profile and consumer integration:

```sh
go test -race -count=1 \
  ./pkg/production \
  ./examples/protected-change-consumer
```

## Security Reporting

Report suspected vulnerabilities through GitHub private vulnerability reporting
for this repository. Do not open a public issue with exploit details. See
`SECURITY.md`.

## Authorship and Review

This repository is maintained by ToppyMicroServices OÜ. Published
specifications, tests, and releases are reviewed and accepted by the
maintainer.

## License

This repository currently keeps the original Apache-2.0 license and retained
upstream notices. See `ATTRIBUTION.md`.

## Caveats and Scope Boundaries

- The core verifier-side acceptance profile is frozen for review. The current
  standards-facing baseline should change only for submission errors,
  reviewer-requested fixes, factual corrections, broken references, or
  requirements ambiguity.
- This repository is a non-normative implementation and evidence repository
  for experimental Direct-Agent binding profiles. It is not an IETF
  consensus document and does not define a TLS handshake or extension,
  attestation evidence format, identity provider, holder-side presentation
  format, registry, control plane, gateway, or application protocol.
- TLS 1.3, certificate-path validation, exporter computation, and key-schedule
  security remain the responsibility of the deployment TLS stack. Attestation
  formats and appraisal policy remain the responsibility of the selected
  binding and deployment profiles.
- Gateway-routed runtime wiring is outside the current Direct-Agent
  implementation. Wallets can provide presentation or signing functions, but
  are not trust roots or sources of verifier-local expected policy.
- The release evaluation is evidence for the tested fail-closed verifier behavior,
  not a formal proof or validation of every deployment. Broader application
  0-RTT behavior, production gRPC pooling, runtime gateway wiring, longer
  fuzz/property campaigns, and hardware-backed confidential-VM attestation
  replay remain outside the recorded evaluation.
- The ProVerif model uses symbolic cryptography and does not prove TLS, X.509,
  JWT parsing, certificate handling, or equivalence with compiled Go code. The
  TLA+ result is bounded evidence for a generic target state machine. The
  production profile implements trust/revocation snapshots, signed attestation
  results, and shared replay commits, but not the model's complete lease,
  audit-outbox, application outcome, or logical-time contract.
- `pkg/atls` and `pkg/agtp` are legacy compatibility names and do not define the
  protocol trust model. Cocos is implementation provenance rather than the
  normative scope of the profile.
- Some client and red-team tests open local loopback listeners and may require
  a less restricted test environment.
