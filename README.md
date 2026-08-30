# Agents Secure Binding

**Verified interaction for independently operated AI Agents.**

Agents Secure Binding (ASB) lets Agent runtimes exchange LLM-generated messages
through a verified boundary. The receiver authenticates the sending Agent,
binds the exact request to the accepted session, checks its authority and
replay state, and only then releases the request to a local model or tool.

The LLM is not the security principal. It generates content; ASB decides which
Agent sent it, what that Agent may do, and whether the interaction is fresh and
intended. Model choice remains separate from identity and authority.

ASB is also the verifier-side acceptance profile and Go implementation behind
that boundary. A verifier accepts an Agent only when its grant, proof, session,
attestation facts, and local policy describe the same interaction.

The primary failure class is context diversion: accepting cryptographically
valid material for a different service, tenant, Agent, task, delegation, or
authority boundary than the verifier intended.

Release `v1.1.1` is the latest release in the supported v1 verifier product
line for the Direct-Agent v1 profile. It provides distinct attested and
software-only
production compositions covering role-separated trust keys, revocation, exact
TLS/action binding, TLS-protected distributed replay, and a concrete
non-Split-Knowledge protected-change consumer. See
[`docs/API_COMPATIBILITY.md`](docs/API_COMPATIBILITY.md) and
[`docs/production-deployment-profile.md`](docs/production-deployment-profile.md).

Release `v2.0.0-rc.1` is a prerelease for the breaking Go module migration and
the platform-neutral attestation boundary. The direct SNP and TDX modules and
the Cocos integration remain experimental. Live hardware qualification is
incomplete, and this prerelease does not make a production-readiness claim for
them. See [`docs/attestation-module-boundary.md`](docs/attestation-module-boundary.md).

## Mac and Local Debug Run

For a short local run on macOS, use the dedicated target. The explicit binary
form is equivalent:

```sh
make mac-debug-a2a

# Equivalent explicit form:
make a2a-test
./build/asb-a2a-test --debug-simple
```

With no workflow override, `--debug-simple` runs the existing eight-scenario
security-test suite through loopback-only role endpoints. It retains mutual
TLS, exact session and request binding, signed attestation-result verification,
and one-shot replay handling. The Attester evidence is signed by a demo key and
clearly labeled `SIMULATED`; the signature exercises the evidence-binding path
but does not turn the evidence into a hardware quote.

It can also call two OpenAI-compatible models running on loopback:

```sh
./build/asb-a2a-test --debug-simple \
  --workflow llm-conversation \
  --prompt-file ./prompt.txt \
  --agent-a-llm-url http://127.0.0.1:11434 \
  --agent-a-llm-model model-a \
  --agent-b-llm-url http://127.0.0.1:11434 \
  --agent-b-llm-model model-b
```

Both model URLs must use `http://` and a loopback hostname. Proxy use is
disabled, and any resolved address outside loopback is rejected.

That workflow makes one ASB-bound A-to-B request. Agent B's reply returns on
the authenticated TLS connection but is not a separately ASB-bound reverse
request.

By default, the run creates ephemeral demo PKI and local file-backed state and
removes them when it exits. If `--state-dir` is supplied, the test keys and
replay state remain there for debugging and must be treated as disposable test
material. The run collects no SNP, TDX, TPM, or vTPM evidence, does not place
either Agent in confidential execution, and makes no production or
hardware-qualification claim. Do not use production data or credentials with
this debug mode.

## Secure LLM-to-LLM Conversation

The product-candidate `llm-conversation` workflow connects two separately
configured OpenAI-compatible models:

```text
Agent A + LLM A
      |
      | exact, bound A2A request
      v
ASB boundary: mTLS + grant + session + attestation + policy + replay
      |
      v
Agent B + LLM B
```

Agent A's model writes the request. Agent B calls its model only after the
request passes ASB verification. The two model endpoints and API keys are
configured independently, so they may use different servers or providers.

```sh
make a2a-test
./build/asb-a2a-test \
  --workflow llm-conversation \
  --prompt-file ./prompt.txt \
  --agent-a-llm-url https://provider-a.example \
  --agent-a-llm-model model-a \
  --agent-b-llm-url https://provider-b.example \
  --agent-b-llm-model model-b
```

Set provider keys with `ASB_AGENT_A_LLM_API_KEY` and
`ASB_AGENT_B_LLM_API_KEY`, preferably through a secret manager. The default
demo launches separate processes on one host. An experimental multi-host mode
generates per-role credential bundles and linked run evidence, but no physical
multi-host or independent-vendor run is claimed. Reverse-direction ASB binding
is also outside the verified product surface. See the
[multiprocess guide](examples/a2a-multiprocess/README.md) for the exact scope.

## Acceptance Contract

The verifier evaluates one ordered contract:

1. Authenticate the authority grant and its policy scope.
2. Verify holder-of-key proof over the exact grant and accepted session.
3. Check freshness, nonce, and replay state.
4. Bind any required attestation result to the same session.
5. Compare authenticated observed values with verifier-local expected policy.
6. Commit one-shot replay state before returning the accepted identity. A
   non-idempotent application can reserve its stable operation in the same
   transaction.

The core implementation is centered on `pkg/clients`, `pkg/atls`, and
`pkg/atls/identitypolicy`. `pkg/agtp` contains reference adapters for JWT/JWS,
CWT/COSE, gateway-route policy experiments, and a narrow local discovery
slice.

## Repository Map

- `docs/SSOT.md`: normative repository source for profile behavior, dimensions,
  verification order, and compatibility notes.
- `docs/threat-model.md`: explanatory relay, replay, diversion, wrong-Agent,
  gateway-route, downgrade, and privacy threat model.
- `docs/draft06-a2a-profile.md`: experimental, non-normative draft-06-inspired
  v2 profile for the multiprocess A2A demonstration.
- `docs/live-red-team-report.md`: current live-style red-team evidence and
  evaluation boundaries.
- `docs/a2a-security-testkit-v1.md`: candidate self-contained A2A security
  binding test surface and result contract.
- `docs/API_COMPATIBILITY.md`: supported v1 API and compatibility policy.
- `docs/production-deployment-profile.md`: fixed production choices for trust,
  revocation, attestation, distributed replay, and exact action binding.
- `docs/azure-sev-snp-attestation-bridge.md`: experimental Azure Attestation
  token-to-ASB bridge boundary and live confidential-VM qualification.
- `docs/attestation-module-boundary.md`: platform-neutral ASB boundary,
  separate SNP/TDX modules, Cocos integration, and test lanes.
- `docs/attestation-module-migration-v2.md`: v2 API and release-order migration.
- `docs/redis-failover-runbook.md`: private multi-node replay topology,
  replication acknowledgement, and real failover gate.
- `formal/`: ProVerif and TLA+ models, recorded results, and
  model-to-implementation traceability.
- `pkg/clients`, `pkg/atls`, and `pkg/atls/identitypolicy`: Direct-Agent
  acceptance implementation.
- `modules/attestation/snp` and `modules/attestation/tdx`: independent,
  experimental `v0.x` hardware appraisers. They are not production-qualified.
- `integrations/cocos`: experimental Cocos evidence and compatibility
  composition outside the ASB root module.
- `pkg/production`: supported attested and software-only fail-closed
  compositions, plus TLS Redis/Valkey replay and shared operation/result
  adapters.
- `pkg/authorityquorum`: generic k-of-n authority approval binding with an
  atomic consume contract and a reduced, secret-free projection.
- `pkg/operationjournal`: durable application-operation reservation and state,
  including atomic replay acceptance and optional opaque result persistence.
- `interop/draft06-v2`: standard-library Python verifiers for the v2 context
  vector and full HTTP/JWS fixture. OpenSSL checks the fixture's three ES256
  signatures. This is same-repository, second-language evidence, not a complete
  interoperability claim.
- `docs/authority-quorum-binding-v1.md`: authority-slot, policy rotation,
  revocation, session interruption, and external release boundary.
- `examples/protected-change-consumer`: independent HTTPS application consumer
  and E2E negative tests; it is not Split-Knowledge.
- `pkg/agtp/discovery`: local Go Presence, capability DISCOVER,
  Kademlia-style peer lookup, and ANS subset; it is not a complete AGTP wire
  implementation.
- `pkg/agtp/discovery/peer`: bounded three-node loopback product profile with
  persistent gossip, real-port DHT lookup, mTLS+ASB peer authentication,
  limits, metrics, and audit.
- `examples/agtp-discover-consumer`: software-only ASB gate for an exact local
  `DISCOVER /population` query, with mTLS/session/replay negative tests.
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
- attested and software-only production compositions with current
  trust/revocation snapshots, exact TLS/action binding, and TLS-only
  Redis/Valkey SETNX replay, plus an experimental Azure SEV-SNP token-to-result
  bridge tested with signed synthetic tokens;
- an independent protected-change HTTPS consumer that exercises both
  production compositions and rejects changed action, wrong TLS session,
  replay, revoked grant, unexpected or mismatched attestation, and replay-store
  outage;
- a 20-client TLS replay-store race that requires exactly one SETNX winner and
  a replica acknowledgement for that accepted write; and
- a TLS 1.3 Redis Sentinel gate that stops the primary, observes replica
  promotion, and verifies replay-record survival after ASB process restart.

For accepted TLS sessions, the AGTP observed-identity path derives
`tls_exporter_sha256` from the accepted `tls.ConnectionState`. Fixed exporter
bytes are used only in synthetic unit fixtures.

The latest recorded signed implementation checkpoint is commit
`0fe710afd3e50848864f84b64cd45f9064c5a37d`; GitHub reports its signature as
verified. GitHub Actions `CI` run `30875915840`, `Security Red Team` run
`30875915843`, and `Redis Sentinel Failover` run `30875915839` completed
successfully on that commit on 2026-08-04 UTC. The Redis result qualifies the
tested self-operated Sentinel topology, not a managed-provider service or SLA.
`Proto Consistency` run `30782322014` completed successfully on the preceding
product merge `9684c3d08785bad344cf32cdd812eefd892caccf`; subsequent commits did
not change generated protobuf sources.

See `docs/live-red-team-report.md` for the evidence matrix.

## A2A Interaction Lab

The packaged binary is both a runnable two-Agent lab and a self-contained
Direct-Agent v1 security test kit candidate:

```sh
make a2a-test
./build/asb-a2a-test
```

It starts Manager, Attester, Verifier, durable Replay Store, Agent A, and Agent
B as separate processes. The default suite runs eight ASB binding scenarios
over the A2A 1.0 HTTP+JSON Send Message surface.

Print JSON or write a report file:

```sh
./build/asb-a2a-test --format json
./build/asb-a2a-test --report ./asb-a2a-report.json
```

Reports follow the versioned
[`a2a-security-test-report-v1` JSON Schema](schemas/a2a-security-test-report-v1.schema.json).
This is an ASB binding tester, not a general A2A conformance suite. External
target mode is not implemented. Text and JSON reports, including the optional
two-model conversation, also work with the separate experimental `draft06-v2`
profile.

The v2 test data also includes a fixed
[HTTP/JWS wire fixture](examples/a2a-multiprocess/testdata/README.md) and an
[independently implemented Python verifier](interop/draft06-v2/README.md) for
the fixed contexts and full fixture. Their claim boundaries are stated with the
fixtures.

See the [test-kit candidate](docs/a2a-security-testkit-v1.md) and
[multiprocess guide](examples/a2a-multiprocess/README.md) for the scenario list,
conversation limits, Docker topology, and hardware prerequisites.

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

## Authority Quorum Demonstration

Run the local 2-of-3 authority approval demonstration:

```sh
go run ./examples/authority-quorum-demo
```

The demo creates two trusted post-verification projections and exercises the
immutable approval and atomic quorum-consume core. It does not run the ASB/JWT
adapter, hold secret shares, or claim an exactly-once external release. See
[`docs/authority-quorum-binding-v1.md`](docs/authority-quorum-binding-v1.md).

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

Repository identity note: the canonical public repository is
`github.com/ToppyMicroServices/agents-secure-binding`, and the next major Go
module path is `github.com/ToppyMicroServices/agents-secure-binding/v2`.
The Go module major version is independent of the Direct-Agent wire-profile
version.

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
GOTOOLCHAIN=go1.26.6+auto go test -v -race -count=1 \
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

ASB-protected local AGTP discovery slice:

```sh
go test ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
```

See [`examples/agtp-discover-consumer/README.md`](examples/agtp-discover-consumer/README.md)
for the local test boundary.

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
