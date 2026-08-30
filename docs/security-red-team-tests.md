# Security Red-Team Tests

Live-style red-team regressions for the AGTP identity hook used by
session-bound agent identity clients.

For the current coverage report and LRTT backlog, see
`docs/live-red-team-report.md`.

## Scope

Most tests exercise the production-facing client hook:

- `AttestedClientConfig.AGTPObservedIdentity()`
- `agtp.VerifySessionIdentityJWT`
- `identitypolicy.ValidateAssertion`
- `identitypolicy.MemoryReplayCache`

The CWT/COSE profile tests exercise `agtp.VerifySessionIdentityCWT` directly,
because runtime client configuration is still JWT/JWS-wired. The client-hook
tests confirm that attacker-shaped inputs are rejected through the same callback
that a client configuration wires into the lower-layer TLS and attestation
acceptance path.

## Negative Acceptance Baseline

These are the first ten reject conditions used to keep the SSOT, implementation,
and red-team report aligned. Covered means the condition is fixed by an
executable regression test in this repository.

| ID | Reject condition | Coverage |
| --- | --- | --- |
| NEG-01 | Valid Identity Grant but missing or incomplete Session Binding Statement. | Covered by partial JWT configuration rejection and missing binding `jti` rejection. |
| NEG-02 | Valid grant but Session Binding Statement signed by an unauthorized Agent key. | Covered by `TestAGTPObservedIdentityRedTeamRejectsAgentThreats` and CWT unauthorized binding-key coverage. |
| NEG-03 | Valid grant but Session Binding Statement `grant_hash` targets another grant. | Covered by `TestAGTPObservedIdentityRedTeamRejectsGrantSubstitution` and JWT envelope substitution coverage. |
| NEG-04 | Valid grant and binding but TLS endpoint-key hash, TLS exporter hash, or request-context hash differs from the accepted session. | Covered by `TestAGTPObservedIdentityRedTeamRejectsAttacks` and real TLS exporter binding coverage. |
| NEG-05 | Accepted lower-layer attestation binder exists but `attestation_binder_sha256` is absent from the binding. | Covered by `TestAGTPObservedIdentityRedTeamRejectsMissingAttestationBinder`. |
| NEG-06 | Reuse of the same binding nonce or replay-cache key. | Covered by replay, concurrent replay, and multi-process replay-race tests. |
| NEG-07 | Peer metadata matches local policy text but the Manager-signed grant does not. | Covered by semantic drift cases in the client-hook red-team tests. |
| NEG-08 | Manager signing key is reused as the Agent confirmation or binding key. | Covered by `TestAGTPObservedIdentityRedTeamRejectsManagerKeyAsBindingKey` and the identity-policy unit test. |
| NEG-09 | Non-canonical semantic alias, such as an `intent_ref` spelling variant, is normalized into acceptance. | Covered by `TestValidateDoesNotNormalizePeerProvidedReferenceValues`. |
| NEG-10 | Gateway TLS is valid but the gateway-to-Agent route assertion is missing, stale, replayed, signed by an unauthorized gateway route key, missing required Agent holder-of-key proof, or scoped to the wrong tenant partition. | Runtime coverage is not implemented in the direct-Agent profile; SSOT defines the gateway route assertion requirements for future gateway-routed profile work. |
| NEG-11 | Hardware evidence or attestation results contain a valid measurement but are not bound to the current verifier challenge, TLS exporter value, and application context. | Evidence-binding unit tests cover report-data and nonce mismatches. Live hardware stale-evidence coverage remains outside the dependency-free red-team harness. |

## Tests

The client-hook red-team coverage lives in `pkg/clients/clients_test.go`. The
CWT/COSE profile red-team coverage lives in `pkg/agtp/cwt_test.go`.

### `TestAGTPObservedIdentityAcceptsManagerIssuedGrantE2E`

Coverage:

- a Manager issues an Identity Grant;
- an Agent issues a Session Binding Statement for that exact grant;
- the client verifies both through `AGTPObservedIdentity()`;
- the resulting assertion is compared with the accepted TLS session binding.

The flow stays close to the production client hook without requiring a network
Manager service.

### `TestAGTPObservedIdentityRedTeamRealTLSAttestationBinding`

Coverage:

- a Manager grant and Agent Session Binding Statement are accepted when their
  binding values come from the same real TLS exporter and accepted attestation
  payload;
- a Session Binding Statement whose binding values were borrowed from another
  TLS / attestation session is rejected with `identitypolicy.ErrMismatch`.

The test uses an in-memory TLS 1.3 connection and the exported-authenticator
attestation path. It does not generate hardware evidence inside a confidential
VM.

### `TestVerifySessionIdentityCWTRedTeamRejectsCOSEProfileAttacks`

Coverage:

- an Agent-signed forged grant and a tampered Manager-key signature are
  rejected;
- a Session Binding Statement signed by an otherwise valid but unauthorized
  binding key is rejected;
- a binding statement cannot target a different Manager-signed grant hash;
- an expired binding statement is rejected;
- a grant that passes signature checks still fails local policy comparison when
  its semantic identity values drift;
- a COSE `kid` in the unprotected header is rejected.

The tokens are CWT/COSE_Sign1. Encoding changes; issuer trust,
confirmation-key authority, exact grant hash, freshness, replay, and local
policy comparison remain the acceptance gates.

### `TestAGTPObservedIdentityAcceptsHTTPJWKSAndRejectsRevocation`

Coverage:

- `/jwks` returns Manager and Agent verification keys;
- `/revocations` returns revoked grant `jti` values;
- the client uses a `KeyFunc` backed by the HTTP key source;
- the client rejects a grant when the HTTP revocation source lists its `jti`.

This is a dependency-free integration test, not a Redis, JWKS, or registry
product implementation.

### `TestAGTPObservedIdentityRedTeamRejectsAttacks`

Coverage:

- a peer-signed grant cannot impersonate the Manager;
- a diverted service identity cannot satisfy local client policy;
- diverted tenant or deployment identity cannot satisfy local client policy;
- a borrowed binding for a different accepted leaf key is rejected.
- a borrowed binding for a different request context is rejected.

Failure classes:

- unauthorized issuer or signing key;
- diversion against local expected service, tenant, and deployment identity;
- relay or borrowed-evidence attempts against the accepted TLS endpoint key and
  request context.

### `TestAGTPObservedIdentityRedTeamRejectsAgentThreats`

Coverage:

- impersonation by a peer-signed grant;
- prompt-injection-shaped unsafe task context;
- tool misuse through the wrong tool scope;
- data exfiltration through the wrong resource target;
- capability escalation through a stronger-than-authorized scope;
- policy bypass through required mode without concrete checks;
- confused-deputy behavior through the wrong delegation id;
- a newly spawned agent key attempting to inherit a parent grant;
- audit evasion through missing grant or binding ids.

Identical machine, account, or session context is insufficient unless the
semantic agent, task, delegation, capability, and audit bindings also match
local policy.

### `TestAGTPObservedIdentityRedTeamRejectsReplay`

Coverage:

- first use is accepted;
- second use is rejected with `identitypolicy.ErrReplayDetected`.

### `TestAGTPObservedIdentityRedTeamRejectsReplayRace`

Coverage:

- exactly one concurrent attempt is accepted;
- duplicate attempts fail with `identitypolicy.ErrReplayDetected`.

Single-process live-style race; multi-process coverage is separate.

### `TestAGTPObservedIdentityRedTeamRejectsReplayRaceMultiProcess`

Coverage:

- exactly one worker accepts the session binding;
- every duplicate worker fails with `identitypolicy.ErrReplayDetected`;
- replay protection is enforced across process boundaries, not only across
  goroutines in one address space.

The local replay service models SET NX EX semantics: record the
`grant_hash/audience/tls_exporter_sha256/request_context_sha256/nonce` key once
for the binding TTL, return duplicate on subsequent attempts, and fail closed if
the store cannot make that decision.
It is not a live Redis, Valkey, or multi-node deployment test.

### `TestAGTPObservedIdentityRedTeamRejectsKeyAndRevocationFailures`

Coverage:

- stale JWKS that lacks a rotated Manager key fails closed;
- key rotation overlap accepts a rotated Manager key only when the key source
  contains both the old and rotated keys;
- HTTP JWKS `500` fails closed;
- HTTP JWKS timeout fails closed;
- revocation-source outage fails closed before accepting the grant;
- a disabled Manager key rejects the Identity Grant;
- a revoked Manager grant `jti` is rejected;
- a disabled Agent binding key rejects the Session Binding Statement.

### `TestAGTPObservedIdentityRedTeamRejectsAttestationBinderMismatch`

Coverage: a valid grant, leaf key, request context, and local policy do not
accept a Session Binding Statement whose `attestation_binder_sha256` differs
from the accepted lower-layer validation result.

### `TestAGTPObservedIdentityRedTeamRejectsMissingAttestationBinder`

Coverage: accepted attestation-to-channel evidence makes the corresponding
Session Binding Statement `attestation_binder_sha256` field mandatory.

### `TestAGTPObservedIdentityRedTeamRejectsManagerKeyAsBindingKey`

Coverage: a Manager-signed grant cannot authorize the Manager key itself as the
Agent confirmation key, even when local key lookup exposes that key to the
binding verifier.

### `TestAGTPObservedIdentityRedTeamRejectsGrantSubstitution`

Coverage: the verifier rejects grant substitution through the `grant_hash`
comparison even when both grants are Manager-signed.

### `TestVerifySessionIdentityJWTEnvelopeRedTeamRejectsSubstitution`

Coverage:

- replacing the inner grant without updating the outer `grant_hash` is rejected;
- an outer `grant_hash` that does not match the exact inner grant bytes is
  rejected;
- an Agent-signed inner grant cannot bypass Manager-signature verification;
- a tampered outer envelope cannot bypass Agent-signature verification;
- Agent-signed semantic claims in the outer envelope are ignored rather than
  treated as Manager authorization;
- an envelope without an inner grant is rejected.

The runtime client configuration path remains wired to the two-token JWT/JWS
profile.

### `TestAGTPObservedIdentityRedTeamRejectsVerifiedGrantCacheMisuse`

Coverage: prior successful verification is not acceptance evidence for a later
session after the same grant `jti` is listed as revoked.

### `TestValidateResponseCachePolicyRedTeamRejectsCallerDependentPublicCache`

Coverage: a caller-dependent endpoint cannot be declared `public` when a naive
method/path/input cache key would leak an admin-scoped response to a read-only
Agent.

### `TestValidateResponseCachePolicyRedTeamPartitionsPrivateCache`

Coverage: a `private` cache partitioned by `Agent-ID` and `Authority-Scope`
does not return the admin-scoped response to the read-only Agent.

## Expected Result

All red-team cases should fail closed before the client treats the observed
identity as accepted. Successful execution means the attacker-shaped input was
rejected, not accepted.

## Command

The ASB core/module split and the meaning of each test layer are described in
[attestation-module-boundary.md](attestation-module-boundary.md).

Run the hardware-independent ASB core checks on macOS or Linux with:

```sh
make test-asb-core
```

Run the focused client red-team tests with:

```sh
env GOCACHE=/tmp/go-build-asb go test -count=1 ./pkg/clients
```

For the broader security regression set, run:

```sh
env GOCACHE=/tmp/go-build-asb go test -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/atls/ea ./pkg/atls/eaattestation ./pkg/atls/internal_transport ./pkg/atls ./pkg/clients ./pkg/clients/grpc ./pkg/clients/http
```

Run the response-cache red-team tests with:

```sh
env GOCACHE=/tmp/go-build-asb go test -count=1 -run 'ResponseCachePolicyRedTeam' ./pkg/agtp
```

Hardware-backed attestation replay coverage is separate from the ASB core CI
profile. Use the manual `Hardware Attestation Red Team` workflow with a
confidential self-hosted runner and explicitly select `snp` or `tdx`. The
workflow requires CoRIM reference values and a platform verification policy,
then exercises the external Cocos integration. Run the same gate directly on a
suitable runner with, for example:

```sh
cd integrations/cocos
GOWORK=off go run ./cmd/hardware-attestation-redteam \
  --platform snp \
  --corim-policy /runner/policy/reference-values.corim \
  --platform-policy /runner/policy/snp-policy.json \
  --corim-public-key /runner/policy/corim-public-key.pem \
  --require-full-verification \
  --evidence-dir /runner/evidence/asb-snp
```

No live SNP or TDX result is recorded for this change.
