# Formal assurance

This directory contains non-normative formal models supporting narrow security
claims. The repository source of truth remains `docs/SSOT.md`.

The models are deliberately separated by their relationship to the Go tree:

- `proverif/binding_acceptance.pv` models the current core binding acceptance
  contract at a symbolic protocol level. `MODEL_MAP.md` records the intended
  correspondence to current packages.
- `tla/DurableGate.tla` is a generic target contract for an application that
  adds durable replay, revocation, lease, audit-outbox, crash-recovery, and
  logical-time state. The current Go tree does not implement that complete
  state machine.

Passing a model proves only the queries or invariants stated in that model
under its assumptions. It does not prove TLS, X.509, JWT parsing, filesystem
semantics, the Go implementation, or semantic correctness of an Agent's work.

Application-specific workflows and privacy experiments are intentionally not
part of this directory.
