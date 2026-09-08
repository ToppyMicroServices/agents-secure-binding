# Formal assurance

This directory contains non-normative formal models supporting narrow security
claims. The repository source of truth remains `docs/SSOT.md`.

The models are deliberately separated by their relationship to the Go tree:

- `proverif/binding_acceptance.pv` models the current core binding acceptance
  contract at a symbolic protocol level. `MODEL_MAP.md` records the intended
  correspondence to current packages.
- `proverif/human_ingress_acceptance.pv` models the gateway-asserted-for-Human
  ingress profile, exact semantic and realm separation, and injective proof
  correspondence across fresh verifier sessions.
- `tla/DurableGate.tla` is a generic target contract for an application that
  adds durable replay, revocation, lease, audit-outbox, crash-recovery, and
  logical-time state. The current Go tree does not implement that complete
  state machine.
- `tla/HumanIngressCommitRetry.tla` and `tla/HumanRelayDispatch.tla` are finite
  target contracts for unknown Human-ingress outcomes and relay
  dispatch/reconciliation. Production adapters do not yet refine them.

Passing a model proves only the queries or invariants stated in that model
under its assumptions. It does not prove TLS, X.509, JWT parsing, filesystem
semantics, the Go implementation, or semantic correctness of an Agent's work.

`HUMAN_COORDINATION_MAP.md` records the Human model-to-Go and requirement map,
compromise assumptions, and unmodeled boundaries. Application privacy and
Human-factors claims remain outside this directory.
