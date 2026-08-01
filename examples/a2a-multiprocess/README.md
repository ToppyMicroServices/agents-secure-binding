# Multiprocess A2A binding demonstration

This demonstration runs the security-binding roles as separate operating-system
processes and carries one task over the A2A 1.0 HTTP+JSON Send Message surface.
The same binary can run natively or as six role-isolated containers.

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

The [A2A specification](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)
describes the protocol binding. Its
[Protocol Buffers schema](https://github.com/a2aproject/A2A/blob/main/specification/a2a.proto)
is the normative data-model source. This demo deliberately implements only the
Agent Card and Send Message subset; it does not claim full A2A conformance.

## Run as native processes

```sh
go run ./examples/a2a-multiprocess
```

Run the separate draft-06 profile with:

```sh
go run ./examples/a2a-multiprocess --binding-profile draft06-v2
```

In that profile, Agent B issues a 32-byte, single-use `verifier_nonce` and a
16-byte `attempt_id`. Agent A obtains the challenge and sends the bound A2A
request on the same completed, non-resumed TLS 1.3 connection. The profile
constructs separate task and target contexts, uses `sbaip_context_v2`, binds
attestation to the accepted endpoint SPKI and 32-byte TLS exporter, evaluates
D6 target matching separately from D7 authorization, and commits durable
replay state only after the other acceptance checks succeed.

The orchestrator bootstraps an ephemeral CA and role-specific keys, starts five
servers as child processes, then starts Agent A as a sixth process. A successful
default v1 run reports the accepted request and five negative decisions:

1. tampered attestation evidence;
2. replay of a consumed Session Binding Statement;
3. credentials borrowed across TLS sessions;
4. resource substitution; and
5. A2A version downgrade.

The `draft06-v2` run reports one accepted request and ten blocked cases: nonce
reuse after a task-context change, a challenge borrowed by another TLS
connection, target and operation substitutions, wrong endpoint role and
interaction type, absent exporter binding, a reserialized-grant digest, and
missing attestation binder or result. The summary is `11/11`; see the
[experimental v2 profile](../../docs/draft06-a2a-profile.md) for the unit-level
checks and their limits.

Only decisions and process endpoints are logged. JWTs, evidence, private keys,
and raw replay keys are not logged. The replay service stores only a SHA-256
digest of each one-shot key and commits state with an atomic rename.

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
- The Compose topology is single-replica and does not model a TLS-terminating
  proxy. Hardware appraisal needs deployment-specific collateral and launch
  measurement management.
