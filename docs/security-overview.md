# Security overview

Agents Secure Binding (ASB) helps a service check the identity and delegated
authority attached to an Agent request. The verifier checks an authority grant,
proof from the key named by that grant, the accepted connection, and the
service's own expected policy. It also checks freshness and replay state.

A valid grant or signature can still be used in the wrong setting. ASB is
designed to reject mismatches in the Agent, task, action, or connection before
the application accepts the Agent. Some profiles also require attestation
evidence; the exact checks depend on the selected profile.

The application decides whether to approve and carry out an action and how to
record its outcome. ASB provides verification for that decision; it does not
make the decision for the application.

## Evidence and limits

The [live red-team report](live-red-team-report.md) lists specific tests, runs,
and remaining evaluation. It is an evidence index, not independent proof that
every deployment is secure. Local or simulated attestation checks do not
establish production hardware assurance.

For exact profile requirements, read the [SSOT](SSOT.md). The [README](../README.md)
lists the current release and component status.
