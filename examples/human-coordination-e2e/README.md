# Human Coordination debug-simple E2E

Status: deterministic, software-only Developer Preview example. It is not a
production deployment, hardware qualification, provider-delivery test, or
multi-process interoperability result.

This example connects the repository's Human Coordination application
boundaries in one process so they can be inspected on a MacBook and in CI. It
uses two logical local Agent Participants, one Human Participant, and a
separate Human gateway Actor.

## Run on macOS

From the repository root:

```sh
make mac-human-coordination-e2e
```

The command writes a deterministic, privacy-minimized report to:

```text
build/human-coordination-e2e/evidence.json
```

Inspect the result with:

```sh
jq . build/human-coordination-e2e/evidence.json
```

The executable refuses to run unless both the debug flag and a report path are
provided. The equivalent direct command is:

```sh
GOWORK=off go run ./examples/human-coordination-e2e \
  --debug-simple \
  --report build/human-coordination-e2e/evidence.json
```

Do not use production credentials, contacts, message content, or identifiers
with this example.

## Scenario

The run performs these operations in order:

1. registers Planner Agent, Executor Agent, and Human Participants;
2. offers and accepts one Human Assignment while keeping the Human Participant
   separate from the gateway Actor;
3. appends an Agent question;
4. issues an opaque, consent-scoped Human reachability grant;
5. verifies and queues one exact Agent relay intent and dispatches it to
   `LocalGatewaySink`;
6. appends a response attributed to the Human through the distinct gateway
   Actor;
7. creates the v1 zero-or-one Assignment-to-Action binding;
8. proves that fulfillment is not yet eligible;
9. applies authenticated `START`, `WAIT(MANUAL)`, `RESUME`, and `COMPLETE`
   Action transitions;
10. proves that the successful Action only makes fulfillment eligible; and
11. applies a separate gateway-asserted-for-human `FULFILL` operation.

Provider acknowledgement is recorded only as relay transport state. It is not
treated as Human receipt, approval, response, or task completion.

## Assurance boundary

The report always records:

- `mode = "debug-simple"` and `production_claim = false`;
- software-only, in-process execution;
- no network calls, live TLS connection, hardware attestation, or external
  provider;
- `MemoryStore` and `LocalGatewaySink` reference boundaries; and
- a machine-readable `boundaries` entry for every exercised surface, including
  its `external-asb` or `trusted-internal` classification, profile ID when one
  exists, Human assurance level when applicable, and exact debug evidence
  source.

Only Human TaskCoord and Agent relay authorization use external ASB profiles.
Agent TaskCoord, Action acceptance and mutation, Human matching, and
reachability administration are explicit `trusted-internal` fixture
boundaries. Relay queueing consumes the ASB-derived relay projection, and relay
dispatch is a trusted Worker boundary. The example does not decode untrusted
wire input into any internal projection.

The implementation uses one fixed scenario timeline. Reachability expiry uses
an injected verifier-controlled clock, while relay-worker and Action operations
use deterministic timeline or sequence clocks. Clock values are not report
fields; report determinism is checked by comparing complete JSON bytes across
repeated runs.

TaskCoord and Task–Action use separate in-memory reference stores. The example
checks fulfillment eligibility before the separate gateway-asserted-for-human
`FULFILL`, but those two decisions are not one durable production transaction.

Human TaskCoord transitions and the relay intent use signed simulated ASB
evidence with dedicated debug keys. The session-binding fields exercise the
verifier logic, but they are not derived from a live TLS connection. This
example therefore complements the separate Human ingress mTLS tests; it does
not replace them.

The Human TaskCoord profile's assurance level is
`gateway-asserted-for-human`. The simulated gateway key, not a Human-held key,
signs the session binding. The scenario therefore provides no
authenticated-Human evidence and proves no Human liveness, UI confirmation, or
legal consent.

The two Agents are logical local Participants and Actors. No LLM server, second
process, remote host, Email/SNS/telephone provider, contact vault, Redis/Valkey
service, SNP, TDX, TPM, or Cocos component is started.

The ordinary reachability constructor still uses `time.Now`; only this
reference scenario selects the additive clock-injection constructor. The debug
path therefore does not change a production or default clock.

The evidence JSON contains only debug identifiers, fixed states, runtime
limits, and the ordered check results. It excludes JWTs, signing keys, direct
contact data, consent internals, and opaque relay-session references.

## CI and tests

The macOS CI job runs the same Make target, verifies the JSON decision fields,
and uploads only `evidence.json` with one-day retention.

Focused checks:

```sh
GOWORK=off go test -count=1 ./examples/human-coordination-e2e
GOWORK=off go test -race -count=20 ./examples/human-coordination-e2e
GOWORK=off go vet ./examples/human-coordination-e2e
```

Passing this scenario is Developer Preview integration evidence. It does not
make `asb.human-coordination.production/v1` available.
