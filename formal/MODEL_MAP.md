# Model-to-implementation map

This map is traceability evidence. It is not a machine-checked proof that the
Go implementation refines either model.

## Core binding acceptance

| Model term | Current implementation surface |
| --- | --- |
| `grant_payload`, `grant_issued` | `clients.VerifyIdentityGrantJWT` produces an authenticated `identitypolicy.VerifiedGrant` from locally accepted issuer, audience, method, and key policy |
| `binding_payload`, `agent_bound` | `clients.VerifySessionBindingJWT` produces an authenticated `identitypolicy.VerifiedSessionBindingStatement` |
| Grant-to-holder authorization | `identitypolicy.ValidateSessionBindingStatement` checks grant hash, audience, confirmation or authorized endpoint key, signer separation, and lifetime |
| Exporter, request context, and attestation binder | `identitypolicy.Binding`; `atls.IdentityBindingFromConnectionState` derives accepted-session values |
| Exact local semantic policy | `identitypolicy.Policy.ValidateAssertion` compares verified observed values with verifier-local expected values |
| One-shot nonce use | `identitypolicy.MarkSessionBindingUsed` and the caller-supplied `identitypolicy.ReplayCache` |
| `accepted` | Successful `clients.VerifySessionIdentityJWT`, after grant and session-proof verification, local policy comparison, and replay marking |

The ProVerif model idealizes signatures, hashing, and fresh session inputs. It
does not model the JWT parser, Go error paths, certificate validation, replay
store failure, time arithmetic, or the concrete TLS exporter implementation.

## Durable gate target

`tla/DurableGate.tla` has no current implementation mapping in this repository.
The public Go tree exposes in-process and SETNX-style replay-cache adapters, but
it does not implement the model's single durable snapshot containing
revocations, leases, an audit outbox, and a persistent logical-time floor.

The TLA+ result therefore supports review of a possible application-level
contract only. It must not be cited as evidence that current Go packages have
durable crash-recovery or revocation semantics.
