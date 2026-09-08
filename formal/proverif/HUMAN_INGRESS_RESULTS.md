# Recorded Human ingress ProVerif result

The Human ingress model was checked locally on 2026-09-03 with ProVerif 2.05:

```sh
sh formal/proverif/run_human_ingress.sh
```

The runner observed six successful result lines and no false or unproved
query:

```text
RESULT not attacker(authority_key[]) is true.
RESULT not attacker(gateway_a_key[]) is true.
RESULT not attacker(gateway_b_key[]) is true.
RESULT event(human_ingress_accepted(...)) ==>
  material_profile = human_profile && local_realm = material_realm &&
  local_audience = material_audience &&
  local_semantics = material_semantics is true.
RESULT event(human_ingress_accepted(...)) ==>
  event(operation_authority_granted(...)) &&
  event(gateway_asserted_for_human(...)) is true.
RESULT inj-event(human_ingress_accepted(...)) ==>
  inj-event(gateway_asserted_for_human(...)) is true.
```

The result establishes only the queries in the symbolic model. Two gateway
keys and a public network allow cross-Actor and cross-session material mixing.
Realm, audience, Participant, operation-kind, and digest mismatch processes use
the same fresh transport values as the verifier they attack. As a negative
mutation check, removing both the grant and holder-proof comparisons for any
one of realm, audience, or the semantic tuple made the acceptance
correspondence queries false. Removing both profile comparisons likewise made
all three acceptance queries false by admitting the relay-profile session.
The injective result still depends on fresh
exporter, nonce, and context values for each verifier session.
It does not establish atomic or durable same-context replay storage,
gateway-key custody, TLS behavior, compiled-Go equivalence, or that a Human
personally signed, saw, understood, or approved the request.
