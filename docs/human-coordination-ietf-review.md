# Human Coordination interoperability topics for IETF review

Status: candidate material for a future revision of the individual
Agent-Human Interaction Internet-Draft. This repository document is not an
Internet-Draft, an adopted Working Group item, or evidence of IETF consensus.

This note extracts the parts of the Human Coordination work that may need an
Internet-level interoperability contract. It deliberately leaves local product
architecture out of that contract.

## Datatracker snapshot

Status was rechecked on 3 September 2026 against the IETF Datatracker:

- [`draft-okutomi-agent-human-interaction-00`](https://datatracker.ietf.org/doc/draft-okutomi-agent-human-interaction/)
  is an Active Internet-Draft (individual), has no RFC stream, and has no
  formal standing in the IETF standards process. It is an intentionally
  incomplete overlay and does not define a wire protocol.
- [`draft-okutomi-session-bound-agent-identity-06`](https://datatracker.ietf.org/doc/draft-okutomi-session-bound-agent-identity/)
  is also an Active Internet-Draft (individual) with no RFC stream. It leaves
  protocol wire formats and deployment choices to binding profiles.
- [`agentproto`](https://datatracker.ietf.org/wg/agentproto/about/) and
  [`dmsc`](https://datatracker.ietf.org/wg/dmsc/about/) are BOFs and are not
  chartered Working Groups.
- [`draft-rosenberg-aiproto-cheq-00`](https://datatracker.ietf.org/doc/draft-rosenberg-aiproto-cheq/)
  is an expired individual Internet-Draft. It is useful prior work, but it is
  not an active or adopted specification.

Any update based on this note remains an individual contribution unless its
status later changes through the IETF process. Discussion in a BOF or on an
IETF list is not Working Group adoption or IETF consensus.

## Fixed model

The following product decisions are already fixed and are inputs to the
interoperability discussion, not questions to reopen:

- A Human Participant is the accountable party. A gateway Actor is the
  authenticated sender of an operation. They remain separate identities even
  when policy permits the Actor to act for the Human.
- Responsibility, communication, and execution are separate. A relay receipt
  does not mutate an Assignment or complete an Action.
- Realm is verifier-local policy context and an identifier namespace. The v1
  documents do not carry or accept a caller-controlled `realm_id`. Equal
  identifier bytes in different realms do not establish the same identity.
- Assurance is derived from the verified profile and evidence. A caller cannot
  select or elevate its assurance level.

## Candidate interoperability contract

These are candidate requirements for an update to the individual draft. They
describe observable behavior between independent implementations without
selecting a wire encoding.

### Human assurance

An implementation should report which evidence class supported an accepted
operation. The current vocabulary separates three levels:

| Assurance level | Interoperable meaning | Current ASB status |
| --- | --- | --- |
| `gateway-asserted-for-human` | An authenticated gateway Actor exercised authority for an exact operation that the verifier attributed to a Human Participant. | Implemented |
| `authenticated-human-evidence` | A trusted Human authentication authority supplied separate evidence bound to the exact operation. | Not implemented |
| `human-held-key-exact-request` | An enrolled Human-held key signed the domain-separated exact request and verifier context. | Not implemented |

The first level proves the gateway operation, not Human presence, Human-facing
UI confirmation, legal consent, or a Human signature. Human authentication
evidence and Human-held-key evidence need their own issuer, key-enrolment,
freshness, revocation, audience, and exact-request rules. A protocol must not
collapse these evidence classes into the label “Human-authored.”

### Authority, audience, and cross-domain use

A receiver selects the expected authority, audience, endpoint, operation
profile, Actor, and Participant policy from local configuration. Peer-supplied
values do not become expected policy merely because their signatures verify.

For a cross-domain operation, the selected profile needs to bind all of the
following to one acceptance decision:

- the source authority and the exact authority it delegated;
- the destination audience, service, and operation profile;
- the authenticated gateway Actor and separately resolved Human Participant;
- the exact operation, freshness, replay state, and accepted channel; and
- any intermediary role that is authorized to translate or forward the
  operation.

Identifier equality across domains is not an identity proof. A deployment may
map a remote identifier to a local identity only through an authenticated,
audience-scoped trust relationship selected by the receiver. Cross-domain use
does not add a caller-controlled realm field to the v1 documents. Delegation
also does not become transitively valid in another authority domain without a
new, explicit authorization accepted by that domain.

### Unknown outcomes, retry, status, and reconciliation

Every mutation needs a stable operation identity that the requester can use
after a lost response and that the receiver binds to the exact operation. The
draft can require that abstract property without deciding whether a concrete
protocol carries a separate command ID or maps an existing event ID to it.

An observer must treat a transport timeout or lost response as **unknown**, not
as failure. Unknown means that a commit or external effect may already have
occurred. While the outcome is unknown, an implementation must not blindly
repeat a non-idempotent effect.

A conforming status or reconciliation mechanism should be authorized for the
same realm, audience, requester, and operation scope. After that authorization,
it needs to distinguish:

1. the exact operation committed and its first canonical result is available;
2. the authoritative system established that no effect occurred and retry is
   safe; or
3. the outcome remains unknown and requires further provider or operator
   reconciliation.

An exact retry uses the same stable operation identity and operation bytes,
with fresh authentication when required. It returns the first canonical result
when one exists. Reuse of that identity for different operation bytes is a
conflict, but existence or conflict details must not be exposed before
authorization. An external provider call additionally needs a provider-visible
idempotency identity or a reconciliation procedure. These rules do not claim
exactly-once execution.

The concrete status resource, error vocabulary, operation-ID field, retention
period, and atomic journal layout remain unfrozen. A future wire profile must
define them together; it must not define retry independently of the durable
outcome and reconciliation contract.

### Relay observations are not interchangeable

Future profiles should qualify the subject of each observation and keep these
states distinct:

| Observation | What it may establish | What it does not establish |
| --- | --- | --- |
| `accepted` | The named receiver or gateway accepted the exact request for processing. | Delivery to a Human, reading, approval, or completion. |
| `delivered` | Evidence from the selected channel says the content reached the intended delivery endpoint. | That a Human read or approved it. |
| `read` | An authenticated Human-facing client reports that the content was presented or opened. | Understanding, approval, or task completion. |
| `approved` | Human authentication evidence authorizes the exact operation or content under the declared assurance level. | That the effect was executed or completed successfully. |
| `completed` | The selected Task or Action protocol records its defined terminal successful outcome. | By itself, the physical effect, product quality, or a Human signature. |

Any future wire terms should be qualified, for example `relay_accepted`, so
they are not confused with Assignment `ACCEPTED`. The current ASB
`PROVIDER_ACKNOWLEDGED` event establishes only that the configured gateway
accepted a dispatch request. ASB does not currently implement `delivered`,
`read`, Human `approved`, or relay-derived `completed` observations.

### Privacy and abuse resistance

Interoperable Human reachability needs the following privacy properties:

- Candidate and reachability identifiers are pairwise and scoped to the
  requester, purpose, capability, verifier-local realm, and validity period.
  They do not reveal a stable Human or Participant identifier.
- Authentication and scope checks precede existence-sensitive lookup. Search
  results are bounded, pre-authorization errors do not disclose whether a
  Human or operation exists, and deployments apply rate and abuse controls.
- Consent and reachability grants are revocable. Current consent, Participant
  status, scope, and expiry are checked again before queueing and immediately
  before dispatch. Revocation does not silently rewrite immutable history.
- A deployment publishes retention and deletion periods for contact, consent,
  interaction, receipt, status, and audit records. Logs omit direct contact
  data and minimize stable cross-request identifiers.
- A plain digest is a binding value, not confidentiality. A digest of
  low-entropy content permits guessing. Sensitive content needs protected
  storage and an access-controlled opaque reference; secrecy must not depend
  on the digest alone.
- Recipient controls, blocking and revocation, quotas, loop prevention, and an
  abuse-reporting path are deployment requirements for an exposed relay.

Public contact data is not permission for indexing, automated matching, or
contact. A relay should disclose the minimum state needed by the requesting
party and keep direct contact and provider details inside the trusted gateway.

### Channel binding through reverse proxies

Direct mode is valid only when the verifier derives the peer identity and
channel binding from the accepted end-to-end TLS connection. Forwarded HTTP
headers, including certificate or exporter values copied into headers, cannot
replace that evidence.

When a reverse proxy terminates TLS, the proxy is a separate authenticated
intermediary. The deployment must either retain end-to-end channel binding or
use a separately specified gateway-routed profile. Such a profile needs an
authenticated and integrity-protected assertion bound to the exact downstream
connection, destination audience, route, Actor, request digest, freshness, and
replay state. It must define who trusts the proxy and how spoofable inbound
forwarding metadata is removed. A deployment must not claim direct-Agent
binding merely because an upstream proxy observed a client certificate.

This note does not select a proxy header, token format, or service-mesh
mechanism.

## Product choices outside the Internet protocol surface

The interoperability proposal must not standardize:

- Redis, Valkey, or another storage product;
- Go APIs, package names, or in-process interfaces;
- database schemas, database ownership, or the component that owns a local
  transaction;
- worker layout, queue implementation, provider SDK, UI, contact-vault
  product, or operational topology; or
- SNP, TDX, TPM, Cocos, or another attestation/integration module.

Those choices may be documented in implementation-status sections and tested
by a product, but conformance depends on externally observable semantics and
security properties.

## Wire-format and IANA change trigger

The next individual draft should continue to request no IANA action and should
not freeze an ASB JSON shape, HTTP endpoint, error code, media type, registry,
or Go representation. Wire-format and IANA work becomes justified when
independently developed implementations identify a concrete interoperability
need that cannot be met by the existing Task, Action, authorization, or
transport protocols.

At that point, the proposal should publish the competing implementation
experience, identify the smallest missing contract, add positive and negative
cross-implementation vectors, and define version negotiation and downgrade
behavior before allocating names. Until then, these topics are review input,
not a compatibility promise or a production-readiness claim.
