# ASB-authenticated DISCOVER

This example authenticates a caller with ASB before querying the local Go
Presence store. It does not run or proxy the Python AGTP server.

The accepted Identity Grant fixes the Agent-ID, `agtp.discover` scope,
capability, result limit, and `/population` resource. The Session Binding fixes
the same request to the accepted mTLS session. Only then does the application
pass the authenticated Agent-ID into Presence visibility filtering.

```bash
go test ./pkg/agtp/discovery/... ./examples/agtp-discover-consumer
```

The tests cover the successful query plus capability substitution, wrong TLS
session, replay, TTL update, selective visibility, partitioned withdrawal,
three-node DHT lookup, and ANS registration and deletion.

The HTTP consumer test uses ephemeral credentials and an in-memory replay
cache. The separate three-node peer profile uses durable replay and discovery
state plus authenticated DHT and gossip transport. A deployment must still
provide its own Manager, Agent, client-CA, and server keys.

See [the implementation boundary](../../docs/agtp-discovery-local.md) for the
supported subset and the features intentionally left out.
