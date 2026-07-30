# Core binding ProVerif model

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
