# Protected Change consumer

This reference application is intentionally unrelated to Split-Knowledge. It
accepts one tenant-configuration change over mutually authenticated TLS 1.3 and
applies it only after the `pkg/production` verifier accepts:

- separate Manager and Agent trust keys plus current revocation state;
- the exact action context and accepted TLS exporter binding;
- a signed, fresh, policy-approved attestation result;
- a verifier-issued one-shot nonce; and
- the shared replay-store commit.

The integration test uses a real HTTPS request boundary and covers the positive
path plus changed-action, wrong-session, replay, revocation, and attestation
failures:

```sh
go test -race -count=1 ./examples/protected-change-consumer
```

`MemoryChangeStore` is only the consumer's test/reference outcome store. A
deployment should replace it with its own durable idempotent application store.
