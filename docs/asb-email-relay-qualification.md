# Email relay qualification: SES candidate

This is a proposed deployment and test plan, not an implemented SES adapter or
a qualification result. No live email has been sent by this work. The selected
provider, AWS account/region, verified sender, authorized recipient and content,
event channel, and credentials remain pending. GitHub Actions and Runpod are
candidate Linux test hosts; neither establishes a long-lived deployment by name
alone. The existing [relay library](agent-to-human-relay-v1.md) has bounded Linux
persistence and synthetic provider tests.

## Provider boundary

SES `SendEmail` returns a `MessageId` when SES accepts the message. Acceptance
can occur without subsequent sending. Its documented request has no caller
idempotency token. `GetMessageInsights` requires that provider-assigned ID, so
it alone cannot recover an attempt whose response was lost before the ID was
saved. This is the reason for the proposed event journal below.
Sources: [SendEmail](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html),
[GetMessageInsights](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_GetMessageInsights.html).

Keep these observations separate:

| Observation | Permitted interpretation |
| --- | --- |
| Successful send response or authenticated exact-request acceptance event | Provider accepted the request; ASB may record `PROVIDER_ACKNOWLEDGED` |
| SES `Delivery` event | The recipient's mail server accepted the email; inbox placement or reading is not established |
| Open/click event or an ordinary email reply | Transport or engagement telemetry; no ASB Human authorization |
| Fresh authenticated Human operation bound to the expected interaction | Human acknowledgement/decision under that separate ASB profile |

SES documents delivery as transfer to the recipient's mail server in its
[event format](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-contents.html).
The ASB [Human production profile](human-coordination-production-v1.md) defines
the separate Human authorization boundary.

## Proposed adapter

Use a dedicated sender identity with only `ses:SendEmail`, restricted to the
chosen identity ARN, exact From address and permitted recipients. Keep SES
administration and event ingestion authority separate. Resolve opaque relay
sessions to contacts in protected gateway configuration; addresses and provider
credentials never enter Agent-visible receipts. SES supports identity and
address restrictions through IAM; the concrete policy depends on the selected
resources. [SES IAM controls](https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html)

The adapter would durably reserve each `IntentID` before any send and reject a
different request using that ID. Bind all `DispatchRequest` fields:
`IntentID`, `RelaySessionRef`, `Channel`, `ContentRef`, and `ContentDigest`.
Pin the private route/configuration revision and provider account/region too.
Fetch content only from the configured store, enforce size limits, and verify
its digest before constructing the approved message. Do not treat an arbitrary
HTTPS reference as permission to fetch it.

Send once through the trusted worker, with a deadline inside the store's
30-second callback bound. Disable SDK send retries and transport redirects or
replay; Go SDK v2 defaults to three attempts and supplies `aws.NopRetryer` for
one attempt. Verify actual wire-attempt counts with a fault-injecting test
server before a live send. Repeated calls return saved evidence or UNKNOWN,
without invoking SES again. [SDK retries](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-retries-timeouts.html)

Configure SES event publishing before sending. Include a provider-safe opaque
intent tag and a versioned digest of the full request/configuration binding;
retain their exact mapping privately. SES publishes message IDs and tags in
events. The candidate collector would authenticate each event, check its
configured source/account and exact binding, and persist the receipt before
acknowledging ingestion. For SNS HTTPS delivery, verify the signature and
expected `TopicArn`; never trust an arbitrary certificate URL from input.
Sources: [event publishing](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-send-email.html),
[event contents](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-contents.html),
[SNS authentication](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html).

`ProviderReconciler.Lookup` would read that trusted journal and compare the
complete immutable request. Missing, delayed, expired, mismatched or unavailable
evidence leaves `DISPATCHING` unchanged. It never sends, cancels an attempted
delivery, releases the grant, or replaces a terminal outcome. Set bounded event
retention, ingestion backlog and storage limits; reaching a limit must preserve
unknown attempts and block new sends rather than discard deduplication state.

## Linux acceptance sequence

These are future probes for the selected adapter and service composition:

1. Record commit, binary hash, Linux/kernel, filesystem/volume, service identity,
   restart policy and private state paths. Run existing relay/SQLite process
   tests, then provider adapter tests with no external delivery. Verify one
   wire attempt under timeouts, connection loss, retries and concurrent callers.
2. Install the selected service under its dedicated user. Verify startup,
   permissions, bounded shutdown and reopening the same persistent state.
   Observe actual systemd execution where that is claimed; unit syntax checks
   do not establish it. A Runpod container without systemd cannot qualify a
   systemd claim.
3. After sender, recipient, content, send count and fault window are explicitly
   authorized, send one bounded test intent. Record provider acceptance and
   authenticated event ingestion separately. SES's mailbox simulator can
   exercise transport outcomes, but it is a real billed SES send and does not
   demonstrate Human interaction. [Simulator scope](https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html)
4. Interrupt the worker after provider acceptance but before local acknowledgement.
   Reopen and reconcile through the event journal; demonstrate no additional
   send. Repeat with the event delayed or absent and require UNKNOWN. Replay
   duplicate, wrong-source and wrong-digest events and require no new effect.
5. Exercise revocation before dispatch, credential expiry, rate limiting,
   collector outage, full storage and bounded backlog. Confirm no blind retry,
   no release of consumed grants, and monotonic terminal receipts. Stop all
   writers for a consistent backup/restore exercise; do not infer power-loss
   or multi-host failover qualification from process termination.

Preserve bounded private logs, exact request/evidence digests and observed send
counts in a [qualification bundle](production-qualification.md). Do not include
contacts, message bodies or credentials in public evidence. Record skipped or
unavailable probes explicitly. A signed source-test bundle cannot substitute
for the unperformed live-provider or host probes above.
