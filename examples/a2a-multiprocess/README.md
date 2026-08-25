# ASB A2A Security Test Kit

This directory contains the candidate self-contained ASB binding tester. It
runs the security roles as separate operating-system processes and exercises
the A2A 1.0 HTTP+JSON Send Message surface. The same binary can run natively,
as six role-isolated containers, or as explicit roles on separate hosts.

The tester checks ASB bindings. It is not a general A2A conformance suite, and
the bundled tests use the ASB reference roles. Another Agent B implementation
can be connected through the multi-host adapter contract below, but no
independent-vendor run is claimed by this repository.

The no-flag behavior remains the original `v1` profile. An independent,
experimental `draft06-v2` profile is available for exercising the repository's
non-normative draft-06 interpretation without changing the v1 wire contract.

```text
Manager ──signed grant──────────────┐
Attester ──evidence──> Verifier ────┼──> Agent A == mTLS 1.3/A2A ==> Agent B
                                    │                              │
                                    └──session-bound result───────┘
                                                     Replay Store <┘
```

Agent A first reads Agent B's Agent Card, obtains a fixed-policy Manager grant,
and opens the exact TLS connection used for `POST /message:send`. The TLS 1.3
exporter, canonical A2A request context, Agent A certificate, and attestation
evidence are bound together. Agent B verifies the grant, Agent signature,
attestation result, local policy, and durable one-shot replay record before
returning a completed A2A task.

The A2A portion of the application surface is an interoperable subset of the
official A2A 1.0 HTTP+JSON binding:

- `GET /.well-known/agent-card.json`
- `POST /message:send`
- `Content-Type: application/a2a+json`
- `A2A-Version: 1.0`
- `A2A-Extensions` selecting both required security-extension URIs
- Agent Card `mutualTLS` security scheme
- v1 required extension URIs
  `urn:agents-secure-binding:security-binding:v1` and
  `urn:agents-secure-binding:attestation-result:v1`
- `draft06-v2` required extension URIs
  `urn:agents-secure-binding:security-binding:v2` and
  `urn:agents-secure-binding:attestation-result:v2`

The v2 challenge path, `POST /extensions/agents-secure-binding/v2/challenges`,
is repository-local rather than an A2A endpoint.

The [A2A 1.0.1 specification](https://github.com/a2aproject/A2A/blob/v1.0.1/docs/specification.md)
describes the protocol binding. Its
[Protocol Buffers schema](https://github.com/a2aproject/A2A/blob/v1.0.1/specification/a2a.proto)
is the normative data-model source. This demo deliberately implements only the
Agent Card and Send Message subset; it does not claim full A2A conformance.

## Build and run Direct-Agent v1

From the repository root:

```sh
make a2a-test
./build/asb-a2a-test
```

The default self-test runs eight scenarios:

1. `ASB-A2A-001`: accept a correctly bound new message;
2. `ASB-A2A-002`: reject a tampered attestation result at Agent B;
3. `ASB-A2A-003`: reject an unknown client-supplied Task ID;
4. `ASB-A2A-004`: reject an expired session proof;
5. `ASB-A2A-005`: reject replay of a consumed proof;
6. `ASB-A2A-006`: reject credentials moved to another TLS session;
7. `ASB-A2A-007`: reject a resource change made after binding; and
8. `ASB-A2A-008`: reject an A2A version downgrade.

Use JSON on standard output or write a report file:

```sh
./build/asb-a2a-test --format json
./build/asb-a2a-test --report ./asb-a2a-report.json
```

The report follows
[`schemas/a2a-security-test-report-v1.schema.json`](../../schemas/a2a-security-test-report-v1.schema.json).
It records whether simulation or a requested hardware platform was used. The
command exits with zero only when all expected decisions are observed.

The source form remains available:

```sh
go run ./examples/a2a-multiprocess
```

## Run two selected LLMs

The `llm-conversation` workflow uses two OpenAI-compatible
[Chat Completions](https://developers.openai.com/api/reference/cli/resources/chat/subresources/completions/methods/create)
endpoints. When a provider requires authentication, set its API key in
`ASB_AGENT_A_LLM_API_KEY` or `ASB_AGENT_B_LLM_API_KEY` with your shell or
secret manager. A keyless local runtime may leave its variable unset. Then run:

```sh
./build/asb-a2a-test \
  --workflow llm-conversation \
  --prompt-file ./prompt.txt \
  --agent-a-llm-url https://provider-a.example \
  --agent-a-llm-model model-a \
  --agent-b-llm-url https://provider-b.example \
  --agent-b-llm-model model-b
```

The prompt goes to Agent A's model. Its output becomes an ASB-bound A2A
request. Agent B completes the normal transport, grant, session-binding,
attestation, authorization, and replay checks before calling its model. The
reply returns as a TLS-authenticated A2A text artifact.

HTTPS is required. HTTP is accepted only for a local loopback endpoint when
`--allow-insecure-llm-loopback` is set. The API key environment variable names
can be changed with `--agent-a-api-key-env` and `--agent-b-api-key-env`; they
must start with `ASB_` and remain different. The orchestrator passes each key
only to its matching Agent child. Key values are not put in CLI arguments,
reports, or logs.

With the default text format, stdout shows the Agent A request and Agent B
reply. JSON reports contain only the workflow decision. This workflow supports
both Direct-Agent v1 and the experimental `draft06-v2` profile, makes one round
trip, and does not retry model calls. Select v2 with:

```sh
./build/asb-a2a-test \
  --binding-profile draft06-v2 \
  --workflow llm-conversation \
  --prompt-file ./prompt.txt \
  --agent-a-llm-url https://provider-a.example \
  --agent-a-llm-model model-a \
  --agent-b-llm-url https://provider-b.example \
  --agent-b-llm-model model-b
```

Model IDs are configured labels, not proof of model-weight provenance. Agent
B's artifact is authenticated by the return TLS connection; it is not a
separately ASB-signed reverse-direction message. ASB does not establish the
truth or safety of model-generated text.

The separate `draft06-v2` profile remains experimental:

```sh
go run ./examples/a2a-multiprocess --binding-profile draft06-v2
```

In that profile, Agent B issues a 32-byte, single-use `verifier_nonce` and a
16-byte `attempt_id`. Agent A obtains the challenge and sends the bound A2A
request on the same completed, non-resumed TLS 1.3 connection. The profile
constructs separate task and target contexts, uses `sbaip_context_v2`, binds
attestation to the accepted endpoint SPKI and 32-byte TLS exporter, evaluates
D6 target matching separately from D7 authorization, and commits durable
replay state only after the other acceptance checks succeed. The replay service
also reserves a stable operation ID and request digest in the same update.
Agent B records RUNNING before invoking the model or demo action, then records
SUCCEEDED and an encrypted copy of the exact A2A response in one store update.
The encryption key remains with Agent B. If the HTTP response is lost, a fresh,
exactly bound request retrieves that response without invoking the model again.
An execution error is recorded as INDETERMINATE; RUNNING and INDETERMINATE do
not permit automatic re-execution.

The orchestrator bootstraps an ephemeral CA and role-specific keys, starts five
servers as child processes, then starts Agent A as a sixth process.

The `draft06-v2` security-test run reports one accepted request and ten blocked
cases: nonce reuse after a task-context change, a challenge borrowed by another
TLS connection, target and operation substitutions, wrong endpoint role and
interaction type, absent exporter binding, a reserialized-grant digest, and
missing attestation binder or result. The summary is `11/11`; see the
[experimental v2 profile](../../docs/draft06-a2a-profile.md) for the unit-level
checks and their limits. Text and JSON reports are available for both profiles.

Only decisions and process endpoints are logged. JWTs, evidence, private keys,
raw replay keys, and plaintext responses are not logged. The replay service
stores a SHA-256 digest of each one-shot key and opaque encrypted responses;
state is committed with an atomic rename.

For reproducible review, the
[full-wire fixture](testdata/README.md) fixes the HTTP request, public-key JWS
inputs, canonical contexts, binding hashes, and expected Accepted Assertion.
The separate [Python vector verifier](../../interop/draft06-v2/README.md)
rebuilds those values and uses OpenSSL to check all three ES256 signatures.
It starts from recorded TLS outputs and is not a live multi-host test.

## Run the reference roles on separate hosts

[`testdata/multihost-deployment.example.json`](testdata/multihost-deployment.example.json)
is the deployment input. Copy it and replace the example origins with names or
IP addresses reachable from their clients. Agent A must reach Manager,
Attester, Verifier, and Agent B; Agent B must reach Replay. Each server needs a
distinct, path-free HTTPS origin and an explicit non-loopback listen address.
The file also fixes the binding profile and attestation mode for every role.

Create the role bundles on an offline setup host:

```sh
./build/asb-a2a-test \
  --role bootstrap \
  --state-dir ./asb-multihost-state \
  --deployment-config ./deployment.json
```

Multi-host bootstrap refuses a non-empty state directory. It creates a
24-hour test CA, a TLS certificate whose SAN matches each configured origin,
and the existing role signing relationships. It also writes
`asb-multihost-state/multihost-trust.json`. That manifest contains endpoints,
certificate fingerprints, and public-key fingerprints. It contains no private
key or credential secret.

Distribute only the directory needed by each role. For example, the Manager
host receives `manager/`, while the Agent A host receives `agent-a/`. Place the
role directory under the path passed as `--state-dir`; do not copy the complete
bootstrap directory to an online host. Copy `deployment.json` to every host and
copy `multihost-trust.json` to Agent A for the run record.

Start the five servers on their assigned hosts. The deployment file supplies
their listen addresses and service URLs:

```sh
./build/asb-a2a-test --role replay   --state-dir /var/lib/asb --deployment-config /etc/asb/deployment.json
./build/asb-a2a-test --role manager  --state-dir /var/lib/asb --deployment-config /etc/asb/deployment.json
./build/asb-a2a-test --role attester --state-dir /var/lib/asb --deployment-config /etc/asb/deployment.json
./build/asb-a2a-test --role verifier --state-dir /var/lib/asb --deployment-config /etc/asb/deployment.json
./build/asb-a2a-test --role agent-b  --state-dir /var/lib/asb --deployment-config /etc/asb/deployment.json
```

Then run Agent A from another host:

```sh
./build/asb-a2a-test \
  --role agent-a \
  --state-dir /var/lib/asb \
  --deployment-config /etc/asb/deployment.json \
  --trust-manifest /etc/asb/multihost-trust.json \
  --format json \
  --report ./asb-multihost-report.json \
  --deployment-evidence ./asb-multihost-evidence.json
```

The ordinary report is marked `target` because Agent A did not start the other
roles. The separate evidence file links the exact deployment file, non-secret
trust manifest, and report by SHA-256. It records the configured origins and the
result status, but not grants, proofs, nonces, private keys, API keys, request
text, or response text. Both output files are owner-readable only.

Verify the links later, without credentials or network access:

```sh
./build/asb-a2a-test \
  --role verify-evidence \
  --deployment-config ./deployment.json \
  --trust-manifest ./multihost-trust.json \
  --report ./asb-multihost-report.json \
  --deployment-evidence ./asb-multihost-evidence.json
```

The hashes detect a changed input. The evidence file is not signed, so retain
or sign the four files with the operator's normal audit system when origin and
custody must also be proved.

The evidence shows that a run succeeded through the configured, hostname-
verified mTLS origins. A DNS name is not proof that services ran on different
physical machines. The file therefore states that physical separation,
independent-vendor interoperability, multi-replica behavior, and full A2A
conformance were not established.

### Agent B adapter entry point

An alternate Agent B can use the generated `agent-b/` credential bundle. A
custom PKI needs a matching trust manifest. The implementation must expose the
health check, Agent Card, v2 challenge endpoint, and A2A Send Message endpoint
used by this test. The exact request and expected binding projection are fixed
by [`testdata/draft06-v2-wire.json`](testdata/draft06-v2-wire.json).
The [Python verifier](../../interop/draft06-v2/README.md) is a second
implementation of the recorded fixture checks.

This is an adapter boundary, not independent-vendor evidence. Such a claim
requires a separately maintained implementation and an actual recorded run.
The optional Redis/Valkey acceptance backend coordinates Agent B replicas, but
the recorded fixture does not prove a multi-replica deployment. The challenge
store also remains process-local.

### Shared acceptance store

The replay role uses an owner-only file by default. Select the shared backend
explicitly with `--acceptance-store redis`, a TLS address, server name, CA file,
and `--redis-password-env`. The password is read from that environment variable
only by the replay process; it is never a command-line argument.

Redis/Valkey Lua scripts commit replay plus operation acceptance and successful
state plus sealed result as single primary commands. Operation and result keys
do not expire: use `noeviction` and do not delete them without a reviewed
archival policy. `WAIT` acknowledgements can be required with
`--redis-replica-acks` and `--redis-replication-timeout`, but they do not make
failover zero-loss. A caller that loses a response must look up the exact
operation before taking further action. The configured address must route to
the writable primary; this small adapter does not perform Sentinel discovery or
follow Redis Cluster redirects.

## Run with Docker Compose

```sh
docker compose -f examples/a2a-multiprocess/compose.yaml \
  up --build --abort-on-container-exit --exit-code-from agent-a
```

Select the draft-06 profile for all relevant containers with:

```sh
BINDING_PROFILE=draft06-v2 \
docker compose -f examples/a2a-multiprocess/compose.yaml \
  up --build --abort-on-container-exit --exit-code-from agent-a
```

Manager, Attester, Verifier, Replay Store, Agent A, and Agent B have separate
containers and separate named credential volumes. The bootstrap container is
the only component that initially mounts every credential volume. Remove the
ephemeral demo PKI and replay state after the run with:

```sh
docker compose -f examples/a2a-multiprocess/compose.yaml down -v
```

## Try hardware attestation

Hardware mode is fail-closed. It requires a Linux confidential guest, an SNP or
TDX guest device, network access from the Verifier to the AMD KDS or Intel PCS,
and the exact expected 48-byte launch measurement. For example:

```sh
ATTESTATION_PLATFORM=snp \
ATTESTATION_DEVICE=/dev/sev-guest \
EXPECTED_MEASUREMENT_HEX=<96-hex-characters> \
docker compose \
  -f examples/a2a-multiprocess/compose.yaml \
  -f examples/a2a-multiprocess/compose.hardware.yaml \
  up --build --abort-on-container-exit --exit-code-from agent-a
```

Use `ATTESTATION_PLATFORM=tdx` and the guest's TDX device path for TDX. The
Verifier checks the evidence signature and certificate chain, revocation data,
the 64-byte report data derived from the live TLS binder, and the configured
measurement. Missing devices, collateral, measurements, or verification steps
cause rejection. The hardware override runs only the Attester container as
root (with all Linux capabilities dropped) so it can open the mapped device.

## Canonical request context

The context input to the TLS exporter and Session Binding Statement is:

```text
A2A/1.0\nPOST\n/message:send\n<canonical JSON request>
```

The canonical JSON is Go's deterministic JSON encoding of the supported Send
Message structure after removing the two security-extension payload values.
The extension URI list remains covered. Omitting the payload values avoids a
circular dependency because those values contain the resulting hashes and
signatures. Application fields, task and context IDs, part metadata, resource,
operation, output modes, and extension selection remain covered.

The `draft06-v2` path does not use this v1 JSON construction. It length-prefixes
fixed fields under `ASB-A2A-TASK-v2` and `ASB-A2A-TARGET-v2`, then supplies both
byte strings independently to `sbaip_context_v2`. The strict v2 decoder rejects
duplicate members (including escaped duplicates), member-name aliases, unknown
members, invalid UTF-8, U+FFFD, unsupported metadata, and whitespace-normalized
resource or operation substitutions.

## Scope boundaries

- `draft06-v2` is experimental and non-normative. Passing this demonstration
  or its negative tests is not a claim of conformance to an Internet-Draft,
  A2A as a whole, or a production attestation deployment.

- Simulation evidence is signed by a dedicated demo Attester key, is labeled
  `SIMULATED`, and is accepted only with Agent B's explicit
  `--allow-simulation` policy.
- Bootstrap creates a short-lived local CA; it is not online enrollment,
  production certificate issuance, CRL, or OCSP.
- The demo uses a fixed application policy and synthetic document reference.
  Consent text, retention policy, real data, and external application adapters
  remain deployment responsibilities.
- The Compose topology is single-replica and does not exercise the optional
  Redis/Valkey shared store or model a TLS-terminating proxy. Hardware appraisal
  needs deployment-specific collateral and launch measurement management.
- Agent B owns the result-sealing key. Replicas need the same protected key;
  rotation and encrypted-result retention are not automated by this demo.
