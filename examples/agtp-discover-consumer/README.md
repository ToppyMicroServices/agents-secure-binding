# ASB-protected AGTP DISCOVER

This example places an ASB acceptance gate in front of an AGTP coordinator's
`DISCOVER /population` operation.

The caller reaches the gateway over mTLS and supplies a Manager-signed Identity
Grant plus an Agent-signed Session Binding Statement. The gateway forwards the
query only after the ASB software-only production profile verifies:

- the Manager and Agent signatures under separate trust roots;
- the caller Agent and the `agtp.discover` authorization;
- the exact capability and result limit;
- the accepted mTLS session and TLS exporter;
- token lifetime and one-shot replay state.

The forwarded AGTP response body is not rewritten, so the caller can still
verify a coordinator-signed DISCOVER response.

## Local tests

```bash
go test ./examples/agtp-discover-consumer
```

The default tests use loopback mTLS and a small AGTP wire fixture. They verify
one accepted query and rejection of capability substitution, cross-session
reuse, and replay.

To use a running local AGTP coordinator with at least one matching Presence
record:

```bash
ASB_AGTP_UPSTREAM=127.0.0.1:9000 \
ASB_AGTP_CAPABILITY=generate \
go test ./examples/agtp-discover-consumer \
  -run TestLiveASBDiscoverAgainstAGTP -v
```

`ASB_AGTP_CAPABILITY` defaults to `generate`.

## Boundary

This is a local software-only reference consumer, not an AGTP wire-specification
change. Hardware attestation is not selected. The tests use an in-process replay
cache and ephemeral credentials; a multi-instance deployment needs durable
atomic replay storage and configured Manager, Agent, client-CA, and server keys.

The AGTP coordinator should be reachable only by the gateway. If callers can
connect directly to the upstream coordinator, they can bypass this ASB gate.
