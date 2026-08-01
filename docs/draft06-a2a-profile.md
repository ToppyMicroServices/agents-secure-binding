# Experimental draft-06 A2A binding profile

## Status

This document defines the repository-local `draft06-v2` profile used by the
multiprocess A2A demonstration. It is an experimental, non-normative profile
inspired by
[`draft-okutomi-session-bound-agent-identity-06`][draft-06]. It is not an IETF
or A2A conformance claim.

[draft-06]: https://datatracker.ietf.org/doc/html/draft-okutomi-session-bound-agent-identity-06

The profile is separate from v1. With no `--binding-profile` flag the demo
continues to use v1. V1 proof claims, exporter inputs, extension URIs,
attestation binders, and replay records are never reinterpreted as v2.

Its application-protocol scope is the demo's A2A 1.0 Agent Card discovery and
single-part Send Message subset plus the repository challenge endpoint. Reverse
requests, callbacks, continuation, exported authenticators, derived grants,
and gateway-routed identity require separately defined profiles and are
rejected here.

## Fixed values

| Input | Repository profile value |
| --- | --- |
| Profile selector | `draft06-v2` |
| Proof `profile_type` | `sbaip.session-binding` |
| Proof `profile_version` | `2` |
| Proof protected header | `alg=ES256`, `kid=demo-agent-a-key`, `typ=sbaip-session-binding+jwt`; no other members |
| Proof signer role | the Agent confirmation key named by the verified grant's `cnf.kid`; endpoint-key signing is not enabled |
| `endpoint_role` | `client-tls-endpoint` |
| `interaction_type` | `agent-to-agent` |
| `protocol_id` | `urn:agents-secure-binding:a2a-http-json:v2` |
| Grant and proof canonical audience | the single JSON string `agent-b` |
| Exporter label | `EXPORTER-Agents-Secure-Binding-A2A-v2` |
| Exporter length | 32 bytes |
| A2A method and path | `POST /message:send` |
| Challenge path | `POST /extensions/agents-secure-binding/v2/challenges` |
| Security extensions | `urn:agents-secure-binding:security-binding:v2` and `urn:agents-secure-binding:attestation-result:v2` |
| Appraisal policy | `urn:agents-secure-binding:attestation-policy:demo-v2` |
| Attestation-result signer | issuer `demo-attestation-verifier`, ES256 key `demo-verifier-key`, protected `typ=JWT` |

Agent B accepts only a completed, directly authenticated TLS 1.3 connection.
TLS resumption and profile-authenticated 0-RTT are rejected. The accepted
endpoint key is the DER SubjectPublicKeyInfo of the current client leaf, whose
validity interval is checked again for the challenge and protected request.

## Authority grant profile

V2 binds the existing compact v1 identity-grant format; it does not silently
introduce a new authority token. The demo requires ES256, an explicitly
configured `kid`, protected `typ` equal to `JWT`, and no protected fields other
than `alg`, `kid`, and `typ`. Thus `crit` and unsupported protected parameters
are rejected. The grant uses exact `profile_type=sbaip.identity-grant` and
`profile_version=1`; legacy aliases are not accepted on the v2 path.

The v2 path requires `iss`, `sub`, single-string `aud`, `jti`, `iat`, `exp`,
and `cnf.kid`. Known claim names are case-sensitive. Case aliases and duplicate
members are rejected. Unknown signed, non-critical grant payload claims are
ignored by this repository profile; they never become local policy.

The Manager adds these authenticated claims only when v2 is selected:

| Claim | Decision use |
| --- | --- |
| `thread_id` | D5 authorized A2A `contextId` |
| `target_resource` | D6 resource |
| `target_operation` | D6 operation |

D3-D5 also use the existing `service`, `deployment`, `workload`, `agent`,
`task_id`, and `intent_ref` claims. D7 uses `capability_ref`, `scope` or
`scopes`, `resource` or `resources`, and `authorization_details`. The demo
accepts only the intersection authorized by the signed grant and Agent B's
fixed local policy; surplus grant values do not expand the returned effective
authorization.

The reusable v2 verifier returns an `AcceptedAssertionV2` projection containing
only verifier-selected values and bounded effective authorization. It does not
return the raw grant or surplus observed fields as accepted application input.

The singular and plural D7 forms are mutually exclusive. `scope` is split only
on one ASCII space between non-empty values; leading, trailing, repeated, or
non-ASCII whitespace is rejected. Singular `resource` is one atomic value and
is never whitespace-split. Array members use the exact decision-string rules
below.

Agent B, not the request, supplies the expected policy:

| Decision | Local source and comparison |
| --- | --- |
| D3 | compiled demo service and deployment identifiers; exact string comparison |
| D4 | compiled workload and Agent identifiers; exact string comparison after authenticated grant and holder-key checks |
| D5 | compiled task, context/thread, and intent identifiers; exact comparison with both grant and request projection |
| D6 | compiled resource and operation target; exact comparison with grant and raw request values |
| D7 | compiled capability, scope, and resource allow-list; exact set comparison in the demo |

For this one-operation demo, the locally requested capability is the fixed
mapping from operation `summarize` to the demo capability and read scope. There
is no peer field that can enlarge the requested set. The reusable policy helper
also supports contains-all validation, but its returned authorization remains
the verifier-local subset.

The grant digest is computed from the exact verified compact JWS bytes:

```text
grant_hash = SHA-256(
  "sbaip.identity-grant.jwt.v1" || NUL || exact_compact_jws_bytes
)
```

Parsing and reserializing grant claims is not an equivalent digest input.

## Challenge flow

1. Agent A and Agent B complete direct mutual TLS 1.3.
2. Agent A requests `{}` from the challenge endpoint on that connection.
3. Agent B generates a 32-byte unpredictable `verifier_nonce` and a 16-byte
   opaque `attempt_id`, encoded as unpadded base64url, with a 30-second lifetime.
4. Pending state is bound to the TLS channel and client SPKI.
5. Agent A builds the contexts and proof, then sends the protected A2A request
   on the same connection.
6. Agent B moves the challenge from issued to in-flight while verifying. A
   successful replay commit consumes it; a failed verification releases it
   only until its original expiry.

The nonce is single-use. `attempt_id` is optional in the byte construction,
but this demo always issues one. Collision checks cover all live entries in one
Agent B challenge store. Restart discards pending challenges and therefore
fails closed. Multi-replica uniqueness and coordination are not provided.

## Canonical byte construction

Every field uses:

```text
field(name, value) = u16be(len(name)) || ASCII(name) ||
                     u32be(len(value)) || value
```

Lengths count octets. Decision strings must be valid UTF-8 without control or
replacement characters. The decoder rejects duplicate, case-aliased, unknown,
invalid UTF-8, unpaired-surrogate, and trailing JSON input before constructing
security contexts. It performs no Unicode normalization, URI repair,
whitespace trimming, or semantic aliasing.

Ordered string lists use a 32-bit count followed by 32-bit-length-prefixed
items sorted by raw UTF-8 bytes. Duplicate list members are rejected.

### Task context

```text
task_context = "ASB-A2A-TASK-v2" || NUL ||
  field("a2a_version", UTF8("1.0")) ||
  field("method", ASCII("POST")) ||
  field("path", ASCII("/message:send")) ||
  field("message_id", UTF8(message.messageId)) ||
  field("context_id", UTF8(message.contextId)) ||
  field("task_id", UTF8(message.taskId)) ||
  field("role", UTF8(message.role)) ||
  field("accepted_output_modes", list(sorted output modes)) ||
  field("part_media_type", UTF8(message.parts[0].mediaType)) ||
  field("part_text_sha256", SHA-256(UTF8(message.parts[0].text))) ||
  field("selected_extensions", list(sorted extension URIs))
```

Security-extension payload values are excluded because they contain the proof
being constructed. Their selected URIs remain bound.

### Target context

```text
target_context = "ASB-A2A-TARGET-v2" || NUL ||
  field("resource", UTF8(message.parts[0].metadata.resource)) ||
  field("operation", UTF8(message.parts[0].metadata.operation))
```

Resource and operation are absent from `task_context`; D6 compares their exact
raw values with the authority grant and Agent B's independent local policy.

### SBAIP context and hashes

```text
binding_context = "SBAIP-CONTEXT-v2" || NUL ||
  field("endpoint_role", endpoint_role) ||
  field("interaction_type", interaction_type) ||
  field("protocol_id", protocol_id) ||
  field("aud", aud) ||
  field("grant_hash", grant_hash_raw_32) ||
  field("task_context", task_context) ||
  field("target_context", target_context) ||
  field("verifier_nonce", verifier_nonce) ||
  field("attempt_id", attempt_id)

EKM = TLS-Exporter(connection, exporter_label, binding_context, 32)

accepted_endpoint_spki_sha256 = SHA-256(client_leaf_spki)
tls_exporter_sha256            = SHA-256(EKM)
binding_context_sha256         = SHA-256(binding_context)
```

`attempt_id` is encoded even when empty. Appendix B golden-vector tests pin the
exact context bytes and all four published hashes.

## Session proof and attestation

The Agent-signed proof contains `grant_hash`, `endpoint_role`,
`interaction_type`, `accepted_endpoint_spki_sha256`, `tls_exporter_sha256`,
`binding_context_sha256`, `verifier_nonce`, optional `attempt_id`, and required
`attestation_binder_sha256`, plus the fixed profile, issuer, audience, `jti`,
`iat`, and `exp` claims. SHA-256 claims use `sha256:` followed by 64 lowercase
hex digits. Nonces use strict unpadded base64url. Protected and payload member
sets are exact; unknown, duplicate, or case-aliased proof members are rejected.

The proof is verified under the ES256 Agent confirmation key identified by the
verified grant's exact `cnf.kid`. The protected header contains only `alg`,
`kid`, and `typ`; this profile does not authorize the TLS endpoint key or an
authority key to sign the proof.

The attestation binding is:

```text
attestation_input = "SBAIP-ATTESTATION-BINDING-v1" || NUL ||
  field("leaf_spki", client_leaf_spki) ||
  field("ekm", EKM)

attestation_binder_sha256 = SHA-256(attestation_input)
report_data               = SHA-512(attestation_input)
```

The `v1` suffix above is the draft-06 domain separator, not the repository v1
profile. The separate Verifier signs the result with the locally configured
ES256 key `demo-verifier-key`, exact issuer `demo-attestation-verifier`, subject
`agent-a`, and audience `agent-b`. Its protected header contains only `alg`,
`kid`, and `typ=JWT`. Required signed claims include `iat`, `exp`, the binder,
measurement result, v2 result profile, and the fixed `appraisal_policy_id`.
Unknown signed payload claims are ignored and do not become policy; unsupported
protected-header members are rejected. The result must be currently fresh. The
proof and Security Binding Object instead use the stored challenge's
`expires_at`; Agent B requires each `exp` to equal that stored expiry and
requires the proof and object `iat` and `exp` values to match each other. The
binder is the result's challenge-to-channel value: its EKM depends on the
context containing the verifier nonce and attempt ID. Agent B checks these
values before D3-D7 policy.

## Verification and replay order

Agent B first rejects requests outside the strict A2A/TLS subset, reserves the
live challenge, authenticates the exact authority grant, reconstructs the task,
target, and channel binding, and validates the Security Binding Object. The
high-level acceptance routine verifies the grant and Agent proof again, checks
the bounded lifetime and authority-to-holder key relationship, and compares the
recomputed binding. Its attestation callback then verifies the result signature,
profile, audience, freshness, binder, and local appraisal policy before D3-D5
identity/task policy, D6 target, and D7 effective authorization. The durable
replay commit is last. Agent B returns a successful task only after that commit.

The domain-separated replay digest covers at least:

```text
grant_hash, aud, endpoint_role, interaction_type,
tls_exporter_sha256, binding_context_sha256,
verifier_nonce, attempt_id
```

The replay service stores only a digest. Nil, typed-nil, unavailable,
malformed, or duplicate replay state fails closed.

## CI negative matrix

CI runs the complete multiprocess v2 demonstration. Its end-to-end cases cover
an accepted request plus nonce reuse after a task-context change, a challenge
borrowed by another TLS connection, D6 resource and operation substitutions,
wrong endpoint role and interaction type, absent exporter binding, a digest of
reserialized grant claims, and missing attestation binder or result.

The same CI package runs narrower unit-level rejection checks related to the
draft Section 21 matrix: peer-only D3 input; a changed exporter representing a
different connection; a borrowed attestation binder; wrong appraisal policy;
surplus D7 values; unavailable replay state; an unsupported downstream signer;
creator-isolation policy without authenticated evidence; resumed TLS and an
early-data indicator; and recognized forwarding headers on a Direct-Agent
request. Context tests separately pin task/target separation and canonical list
encoding.

Exported authenticators, reverse requests, callbacks, continuation, derived
grants, and gateway-routed identity are outside this profile. Role, interaction,
and signer mutations verify fail-closed profile selection; they are not complete
protocol tests for those unsupported flows. The early-data and forwarding-header
checks are not a general TLS 0-RTT or gateway deployment harness. These are
executable negative checks, not a proof of protocol security, complete coverage
of every Section 21 case, or whole-draft conformance.

Externally visible failures use coarse classes such as `challenge-rejected`,
`session-binding-mismatch`, `attestation-result`, `policy-mismatch`,
`replay-detected`, and `profile-rejected`. Demo output records the decision and
profile, not grant or proof tokens, evidence, exporter bytes, raw replay keys,
challenge bytes, or private keys.

## Caveats and deployment boundary

- Challenge state is process-local; multi-replica coordination is unsupported.
- The direct profile does not treat a TLS-terminating proxy as the final Agent.
- Hardware collection paths exist, but production endorsement, collateral,
  measurement, and appraisal policy remain deployment responsibilities.
- Certificate enrollment, CRL/OCSP service, application data, consent and
  retention policy, external adapters, and backup erasure are outside this
  repository profile.
- Go TLS, X.509, JSON, JWT, filesystem, and clock behavior remain trusted
  implementation dependencies; the tests do not prove formal equivalence.
