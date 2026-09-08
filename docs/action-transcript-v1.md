# Action request transcript v1

Status: unreleased repository profile. This document defines the exact bytes
hashed for Action acceptance, verifier-attempt identity, later Action
mutations, and the trusted TaskCoord context used by acceptance. It does not
change the durable JSON snapshot formats.

The machine-readable cross-language vectors are in
[`testdata/action-transcript-v1-vectors.json`](../testdata/action-transcript-v1-vectors.json).

## Digest format

Each request digest or attempt fingerprint is:

```text
lowercase("sha256:" || hex(SHA-256(transcript)))
```

The profile/version is the first value in every transcript. A bare
`sha256:<hex>` value does not identify the profile by itself, so an application
must select the profile from its protocol version rather than from the digest
string.

One complete transcript, including its domain, must not exceed 16,384 bytes.
An encoder must return an error and no digest when this bound is exceeded.

## Primitive encodings

The notation below is normative. Concatenation is written `||`.

```text
S(x)     = u16be(len(UTF8(x))) || UTF8(x)
U32(x)   = exactly four bytes, unsigned big-endian
U64(x)   = exactly eight bytes, unsigned big-endian
TIME(x)  = i64be(unix_seconds(x)) || u32be(nanoseconds(x))
OPT(x)   = 00 when absent; 01 || x when present
```

`S(x)` uses the exact valid UTF-8 bytes supplied by the typed request. The
length counts bytes, not Unicode code points. No NFC, NFD, case, whitespace,
or other normalization is performed. An empty scalar string is encoded as
`0000`; it is not omitted.

`TIME(x)` represents an instant relative to the Unix epoch. `unix_seconds` is
a signed 64-bit two's-complement big-endian integer. `nanoseconds` is in the
range 0 through 999,999,999. Time-zone name, numeric offset, and process-local
monotonic-clock data are not encoded. A required zero timestamp or a timestamp
outside the durable RFC 3339 range is invalid.

Only `00` and `01` are valid optional tags. A decoder, if implemented, must
reject any other tag, truncation, or trailing bytes. Pointer absence is
different from a present value whose scalar fields are empty or zero. The
semantic validators reject present nested values that violate lifecycle
invariants.

## Mutation request

Domain:

```text
asb.action-mutation-request/v1
```

`AuthenticatedOperation` is excluded because it carries the resulting
`mutation_digest`. All caller-controlled `Event` fields are encoded in this
order:

```text
S(domain)
S(event_id)
S(kind)
U64(expected_revision)
TIME(at)
S(reason.code)
S(reason.detail)
OPT(fence {
  S(lease_id)
  S(executor_id)
  U64(generation)
})
OPT(lease {
  S(lease_id)
  S(executor_id)
  U64(generation)
  TIME(issued_at)
  TIME(expires_at)
})
OPT(resume_condition {
  S(type)
  OPT(TIME(not_before))
  OPT(TIME(probe_after))
  S(target)
  S(dependency_action_id)
  S(signal)
})
OPT(checkpoint {
  U64(sequence)
  S(payload_digest)
  S(storage_ref)
  TIME(created_at)
})
S(evidence_ref)
S(reconciliation_result)
S(result_ref)
S(error_code)
```

## Acceptance request

Domain:

```text
asb.action-accept-request/v1
```

`accepted_at` is excluded because the Store derives it from its transaction
clock. `AuthenticatedOperation` is excluded because it carries the resulting
digest. The exact order is:

```text
S(domain)
S("ACCEPT")
S(event_id)
S(action_id)
S(action_digest)
S(owner_id)
S(recovery_policy.mode)
U32(recovery_policy.max_attempts)
S(recovery_policy.idempotency_key)
S(acceptance_context_digest)
```

## TaskCoord acceptance context

Domain:

```text
asb.task-action-accept-context/v1
```

The complete Assignment is validated and must be `ACCEPTED`. The selected
trusted projection is encoded in this order:

```text
S(domain)
S(assignment_id)
U64(expected_assignment_revision)
S(task_id)
S(participant_id)
S(role)
S(authority_digest)
S("ACCEPTED")
```

An accepted Assignment cannot be revision one: revision one is its initial
`OFFER`, and `ACCEPT` advances it. The v1 golden vector therefore uses revision
two. This lifecycle invariant is part of the vector input, not an encoding
special case.

`authority_digest` in this context is the TaskCoord form: exactly 64 lowercase
hexadecimal characters without a `sha256:` prefix. `action_digest` and
`acceptance_context_digest` in the outer acceptance transcript use the
canonical `sha256:<64 lowercase hex>` form.

## Acceptance verifier attempt

Domain:

```text
asb.task-action-accept-attempt/v1
```

This transcript identifies the complete verifier projection used for one
acceptance attempt. It is separate from the business request digest. The exact
order is:

```text
S(domain)
S(actor_id)
S(authorization_id)
S(proof_id)
S("ACCEPT")
S(action_id)
S(action_digest)
S(mutation_digest)
S(verifier_nonce)
TIME(issued_at)
TIME(expires_at)
```

An exact retry must match both the acceptance business digest and this attempt
fingerprint. The stored result may be returned after `expires_at` only when
the complete attempt already produced that result. Expiry never permits a new
commit. A different proof for the same business request is a reconciliation
case, not an idempotent retry, because silently replacing it would rewrite the
first audit provenance.

## Validation boundary

The transcript fixes byte representation; it does not replace the typed
lifecycle rules. Before a state change, the Action and TaskCoord validators
still reject unsupported enums, malformed identifiers or digests, unsafe
references, zero revisions and generations, invalid recovery policies,
ambiguous resume-condition forms, and invalid timestamps. No digest makes an
otherwise invalid transition acceptable.

The exported Go encoders are:

- `actionlifecycle.MutationRequestTranscript`;
- `actionlifecycle.AcceptanceRequestTranscript`;
- `actionbinding.AcceptanceContextTranscript`; and
- `actionbinding.AcceptanceAttemptTranscript`.

Their matching digest helpers hash those exact returned bytes.

## Golden vectors and migration

The vector file fixes the exact input, transcript hex, and digest for all four
domains. Its valid context/outer-acceptance pair and verifier attempt have
these digests:

```text
context    sha256:965b87ed6a9f2e6cddf277658572fa4b735a2e65666ad1745e1a662ccb7a93de
acceptance sha256:2b95550763c89ee3060509497ba2b0406df53088e05bce6313e4d99e8684b1f9
attempt    sha256:6c53680a1dc1248669b04422373ae8fcb42a10de2ccc9b4462abe7d4c9155fe3
mutation   sha256:0c1f96ac6db0a6d02d2a7f61c72a0045a4ca0b81214098d197a56bfa0a1b63cb
```

The earlier field-ordered Go JSON form existed only in unreleased repository
work and was not a supported interoperability profile. This byte grammar is
the v1 definition. Implementations of this profile do not emit or accept the
earlier JSON-derived digest. If a deployment has independently persisted such
experimental digests, it must treat them as a separate local legacy profile;
there is no silent dual verification.
