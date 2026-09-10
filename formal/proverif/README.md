# ProVerif protocol models

## Core binding

`binding_acceptance.pv` models a narrow symbolic contract:

- an authority-signed grant authorizes one Agent key, audience, semantic value
  tuple, and grant identifier;
- the Agent signs the exact grant digest, exporter, nonce, request context, and
  attestation binder for one modeled session; and
- acceptance corresponds to both prior events, with an injective
  Agent-binding correspondence across fresh modeled sessions.

Run the model with ProVerif 2.05:

```sh
sh formal/proverif/run.sh
```

The runner uses `proverif` from `PATH`, or `opam exec -- proverif`.

## Interpretation boundary

The model uses ideal symbolic signatures and hashing and gives the public
network to an active attacker. The exact D3 through D6 policy values are
abstracted as one `required_values` term. Fresh exporter, nonce, request
context, and attestation binder values are selected for each modeled session.

This checks use of those values by the symbolic protocol. It does not verify:

- TLS, exported authenticators, X.509, or an attestation format;
- JWT/JWS parsing, JSON handling, or algorithm selection;
- time, certificate validity, or key lifecycle;
- replay-cache durability, crash recovery, or multi-replica behavior; or
- correspondence between the model and compiled Go code.

See `../MODEL_MAP.md` for implementation traceability and `RESULTS.md` for the
recorded tool result.

## Human ingress

`human_ingress_acceptance.pv` models
`asb.taskcoord-human-request/v1` as a gateway assertion for an accountable
Human Participant. It checks exact profile, verifier-local realm and audience,
Participant, operation kind, canonical digest, authority grant, gateway Actor
holder proof, and fresh session binding. A separate relay-profile issuer and
same-transport negative sessions for another realm, audience, Participant,
operation kind, and request digest are present on the attacker-controlled
network. The negative sessions deliberately share their verifier's fresh
exporter, nonce, and context, so transport freshness cannot mask a missing
semantic-domain check.

Run it with:

```sh
sh formal/proverif/run_human_ingress.sh
```

The injective query checks cryptographic proof reuse across replicated
verifier sessions with fresh exporter, nonce, and context values. Atomic
same-session replay consumption and lost-commit recovery are state-machine
properties checked separately in TLA+; this model does not claim replay-cache
durability.

The event is named `gateway_asserted_for_human` deliberately. There is no Human
signing key in the model and no claim of Human presence, UI confirmation,
legal consent, or exact-request approval. See
`../HUMAN_COORDINATION_MAP.md` for mappings and assumptions and
`HUMAN_INGRESS_RESULTS.md` for the recorded result.
