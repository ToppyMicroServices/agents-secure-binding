# Recorded ProVerif result

The public model was checked locally on 2026-07-30 with ProVerif 2.05:

```sh
sh formal/proverif/run.sh
```

ProVerif reported all five selected queries as true:

```text
RESULT not attacker(authority_key[]) is true.
RESULT not attacker(agent_a_key[]) is true.
RESULT not attacker(agent_b_key[]) is true.
RESULT event(accepted(...)) ==> event(grant_issued(...)) && event(agent_bound(...)) is true.
RESULT inj-event(accepted(...)) ==> inj-event(agent_bound(...)) is true.
```

The result establishes secrecy of the three modeled signing keys,
correspondence from acceptance to both an authority-issued grant and an exact
Agent binding, and injective correspondence from acceptance to that binding
event, under the model's symbolic assumptions. It does not establish
implementation equivalence, durable-state behavior, certificate parsing, or
application-specific privacy properties.
