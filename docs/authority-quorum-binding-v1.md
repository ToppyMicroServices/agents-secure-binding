# Authority Quorum Binding v1

Status: experimental implementation profile.

This profile lets several independently authenticated authority slots approve
one exact operation. ASB checks each approval. A shared store commits the
quorum once.

It distributes approval authority. It does not distribute secret material by
itself.

## Model

An authority slot is a stable policy member such as `authority:a`. It is not a
certificate, key ID, process, or replica. Several keys may map to one slot
during key rotation, but that slot still has one vote.

The verifier binds each approval to:

```text
decision_id
policy_digest
operation_digest
```

The local policy adds the audience, epoch, threshold, member slots, validity
period, and `authority_map_digest`. That map binds each slot to a verified
issuer, Actor, proof issuer, key ID, and fingerprint of the verification key.
Its digest is part of `policy_digest`. Adding or removing a rotation key
therefore creates a new policy version.

The application profile creates `operation_digest`. For Split-Knowledge, that
digest should cover the authorization, candidate version, relying party, job,
purpose, consent, requested view, output policy, and operation type. These
fields remain outside the generic ASB package.

## Acceptance

A deployment service terminates verified TLS 1.3. It can use `ServerTLSConfig`
and call `BindingFromTLS` on the accepted connection. The ASB adapter then
checks the grant, session proof, audience, exact authorization detail, TLS
binding, and freshness window. This package does not provide an HTTP service.

The authority slot comes from a trusted map, not the approval request. The
adapter fingerprints the key that verified the proof and checks it against the
map. A key ID alone is not a credential identity.

A network handler calls `asbbinding.Profile.Submit` after deriving the TLS
binding. It must not decode a peer-provided `Approval` and call `Store` or
`Service.Approve` directly. The JSON decoders are for trusted durable state.

The durable approval stores decision-scoped tags for the principal, credential,
and authorization. It does not store the raw proof, signature, key, nonce,
secret share, fragment, or contact data. Reusing the same proof is an
idempotent retry. Changing a bound request field fails verification.

## Quorum commit

Only `Store.ConsumeQuorum` returns `VerifiedQuorum`. A separate check such as
`HasQuorum` is not an authorization result because approvals or revocation may
change before commit.

The store transaction must:

1. load the current policy, approvals, revocation, and consumption state;
2. require distinct authority slots, principals, and credentials with
   unexpired approvals;
3. record the consumption ID and selected evidence set before returning.

`consumption_id` is unique across decisions. An exact retry returns the stored
projection only before `accepted_until`. At or after that time it returns an
expiry error and cannot start a new effect. A different consumption fails.

Revocation before consumption blocks the decision. `RevokeDecision` is a
trusted application or administrator call; the core does not authenticate it.
Revoking a credential after an approval does not remove that vote by itself.
The application must revoke the decision when it needs that result. A
correction or policy change uses a new decision ID.

`MemoryStore` exercises these rules in one process. Production deployments need
a shared, durable, cross-process transaction or linearizable CAS.

## Session interruption

A connection timeout before approval leaves no vote. Once the store accepts an
approval, later session loss does not remove it. If an approval expires before
quorum is reached, the caller starts a new decision rather than rewriting the
old record.

Missing authorities mean that quorum is not yet available. They do not imply a
rejection or external operation failure.

## External release

`VerifiedQuorum` does not contain a reconstruction key or plaintext. It is also
not a signed, portable proof. Only the fresh value returned directly by
`ConsumeQuorum` may authorize a first external effect. Decoded peer-supplied
JSON must not be used for that purpose.

On a retry, a release adapter first checks its own durable receipt for the
global `consumption_id`. If a release already happened, it returns that receipt.
Otherwise it obtains a fresh quorum result before starting the effect.

Database consumption and an external physical or cryptographic release are not
one transaction. Deployments need an idempotent release adapter or a durable
outbox. ASB does not claim exactly-once external release.

Policy approval nodes and threshold reveal nodes should normally be different
sets. Using the same nodes for both removes that separation when the threshold
is compromised.

## Privacy and limits

The returned projection contains the decision, policy and operation digests,
audience, threshold, approval count, and validity window. It does not list
approvers or expose a digest that can be used to guess the selected set.

Durable approvals contain an authority slot and decision-scoped pseudonymous
tags. They are internal records, not public logs, and should be protected as
sensitive operational data.

ASB can enforce distinct configured authority slots. It cannot prove that the
operators behind those slots are independent. Threshold secret generation,
share storage, resharing, reconstruction, and deletion remain in the external
release system.

The durable JSON documents are defined by
[`schemas/authority-quorum-binding-v1.schema.json`](../schemas/authority-quorum-binding-v1.schema.json).

## Demo

The local 2-of-3 demonstration creates two trusted projections for a policy
with three authority slots. It starts at the boundary after ASB verification:

```sh
go run ./examples/authority-quorum-demo
```

The ASB/JWT adapter and negative cases are exercised by:

```sh
go test -race -count=1 ./pkg/authorityquorum/...
```
