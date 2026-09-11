# Authenticated least-privilege execution

`pkg/leastprivilege/asbbinding` connects finite optimization to ASB v2 proofs,
current operator policy and a durable execution journal. A caller may propose a
candidate. It cannot install policy, choose its authenticated actor/task, or
declare an uncertain operation successful.

The profile is software-only and uses mutual TLS 1.3. It is an application
profile, not a new hardware-attestation profile or an IETF allocation. Its
protocol identifier is `urn:asb:least-privilege:execution:v1`.

## Trusted configuration

The operator creates one `Policies` instance, installs `PolicyRecord` values
using `Put`, opens the [durable journal](least-privilege-durability.md), and builds
`NewService(Config{...})`. Configuration supplies the authority and actor public
keys, capability-signing private key, issuer/audience, verifier work budget, and
operation-specific `Executors`. Optional `Reconcilers` query authoritative
downstream results; they must never execute or retry an operation.

The requesting agent must have no write authority over this configuration or
the journal. The service snapshots policy, keys and callback maps. Grant keys
and actor keys must be distinct Ed25519 keys with distinct IDs. It accepts only
the configured ASB v2 profile and exact D4–D7 bindings. No generic command or
arbitrary URL executor is provided.

`Operation` contains an operation ID, mandate ID and exact `Action`. It has no
actor or task fields. `VerifySessionIdentityJWTV2` derives those values from the
verified grant/proof and compares them with the trusted mandate. D7 binds the
operation, resource, policy reference and exact `AuthorizationDetail`. The
`ContextDigest` covers the mode, operation ID, mandate ID and action digest.
An authorization proof therefore cannot be reused for execution or recovery.

An unset or false `AllowAutomatic` still returns `ErrHumanRequired`. Mathematical
optimality does not grant an action that the mandate has not authorized.

## HTTP entry point

`NewHTTPHandler` serves POST requests to `/challenge`, `/authorize`, `/execute`
and `/reconcile`. Install it on an `http.Server` whose `tls.Config` uses
`MinVersion: tls.VersionTLS13`, `ClientAuth: tls.RequireAndVerifyClientCert`, an
operator-selected client CA pool and the server's certificate. Set server
timeouts and deployment request limits appropriate to the service. The handler
requires an actual verified mutual TLS connection and does not accept proxy
headers as transport evidence.

First request a challenge for the exact operation and mode. Construct the ASB
session proof using the returned binding and the existing authority grant, then
send the operation, proof, nonce and candidate or capability on the same TLS
connection. The server binds its nonce to the peer certificate SPKI, exporter,
mode and context. Challenges are bounded in count and lifetime and consumed once.
The HTTP request schema never accepts a peer-supplied `Transport`.

`/authorize` independently verifies the proposed optimum and returns a short-lived
signed capability. `/execute` requires a new proof, verifies the capability
against current policy, reserves durable admission and calls the configured
executor once. `/reconcile` requires its own new proof and consults a configured
authoritative query. It accepts no outcome or evidence digest from the caller.
Malformed requests and authentication failures return bounded, redacted errors.
An uncertain result remains explicitly `UNKNOWN`; a failed response is not
permission to repeat the operation.

Direct Go callers may supply `Transport` only from verifier-local connection and
challenge evidence. The HTTP adapter constructs it from TLS itself. Passing a
peer-decoded `Transport` directly to `Service` would violate this API's contract.

## Current policy and recovery

All admissions and dispatches hold the policy read guard. `Put` and `Revoke`
take the write guard and wait for earlier admissions to finish. Once an update
returns, a later operation in this authority process cannot begin dispatch using
the previous policy. Revocation cannot undo an effect already dispatched. A
blocked downstream call delays an update, bounded by the accepted proof and
capability deadlines when the adapter honors context cancellation.

Changing a mandate or its problem invalidates old capabilities. A revoked
mandate ID cannot be revived, and an existing mandate's expiry cannot be
extended. Issue a globally new mandate ID for new authority. Restart must load
current trusted policy and revocations; the in-process policy map is not a
durable or distributed policy authority. Run one policy authority process for
this service. Independent journal writers share admission safety, but separate
policy maps would not coordinate revocation.

Exact completed retries return the stored result without invoking the executor.
`RUNNING` or `UNKNOWN` retries do not dispatch. Authenticated reconciliation binds
the original operation, request and current mandate before querying an adapter.
An unavailable query, missing evidence, or interrupted journal write preserves
uncertainty. The peer recovery path requires the original mandate to remain
valid and unchanged. After expiry, revocation or policy replacement, a trusted
operator must use the protected recovery procedure described in the durability
document; there is no public
policy override or raw completion endpoint.

For the scoped S3 executor, see [the AWS profile](least-privilege-aws.md). For
TaskCoord delegation, `ReconcileDelegation` reads the immutable authoritative
event without repeating its commit. The local Redis restart test verifies this
specific recovery path, not generic provider reconciliation or production HA.

## Validation boundary

Service tests use actual signed Ed25519 ASB grants and session proofs. They cover
actor/task and D7 substitution, exporter mismatch, signature tampering, replay,
policy replacement and revocation races, Human-required mandates and authenticated
recovery after response loss. The HTTP suite exercises actual mutual TLS
handshakes separately from the service's trusted-transport unit fixtures.

The [dedicated workflow](../.github/workflows/leastprivilege.yaml) runs race tests,
vet, the local authorization demo and portable certificate generation/checking
on Linux and macOS. Provider fixtures and local Redis tests do not establish
live cloud behavior, hardware assurance or a released production service.
