# Cloudflare email notifications

`pkg/humanrelay/cloudflare` connects the trusted Human relay worker to
Cloudflare Email Sending. It sends a plain-text notification to one configured
recipient. The adapter implements `humanrelay.SessionDispatcher` and
`humanrelay.ProviderReconciler`; it does not add an Agent-facing send endpoint.

This is an SDK adapter, not a deployed notification service or a live-provider
qualification result. The Linux tests use a local TLS server with Cloudflare's
documented response shape. They do not send email, test inbox placement, or
establish Cloudflare account readiness. SES remains an alternative proposal.

## Connect a trusted worker

Cloudflare documents sending through
`POST https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send`.
The adapter fixes this destination, disables redirects and automatic send
retries, and applies a bounded deadline. It does not fetch the opaque session
or content URLs. Deployment-controlled maps resolve both values in memory.
The maps are copied when the dispatcher is constructed.

Each map is limited to 1,000 entries. Subjects are limited to 256 UTF-8 bytes
and bodies to 16 KiB. The default deadline is 10 seconds, with a configurable
range of 1 millisecond to 20 seconds. The default concurrent-operation limit
is four, with a maximum of 32; excess calls fail immediately. Responses are
limited to 64 KiB. These are adapter limits, not Cloudflare account quotas.

Prepare an Email Sending domain and a dedicated API token with permission to
send on the selected account. Cloudflare's current Email Sending service is
Beta and requires Cloudflare DNS; check its current plan and entitlement
requirements before enabling a live deployment.
Sources: [setup](https://developers.cloudflare.com/email-service/get-started/send-emails/),
[service scope](https://developers.cloudflare.com/email-service/),
[REST API](https://developers.cloudflare.com/email-service/api/send-emails/rest-api/).

The following excerpt belongs inside a trusted Linux worker. `authority` is an
already-open `*sqlitestore.Store` containing verified Participants, consent and
reachability grants. `token` comes from the deployment's private credential
source. Both the state directory and configuration must be owner-only. The
placeholder addresses and account ID must be replaced with authorized values.

```go
journal, err := operationjournal.OpenFileStore("/var/lib/asb-notify/provider.json")
if err != nil {
    return err
}
message := cloudflare.Message{
    Subject: "ASB: review requested",
    Text:    "A request is waiting in your ASB inbox. Sign in to review it.",
}
contentDigest, err := cloudflare.MessageDigest(message)
if err != nil {
    return err
}
dispatcher, err := cloudflare.New(cloudflare.Config{
    AccountID: "0123456789abcdef0123456789abcdef",
    APIToken:  token,
    Sender:    "notifications@example.com",
    Routes: map[string]string{
        "https://relay.example/sessions/opaque-1": "recipient@example.net",
    },
    Messages: map[string]cloudflare.Message{
        "https://content.example/notifications/review-v1": message,
    },
    Journal: journal,
    Timeout: 10 * time.Second,
    MaxInFlight: 4,
})
if err != nil {
    return err
}
defer dispatcher.Close()
relay, err := humanrelay.OpenFileStore("/var/lib/asb-notify/relay.json", authority)
if err != nil {
    return err
}
worker, err := humanrelay.NewWorker(relay, dispatcher)
if err != nil {
    return err
}
```

Imports are `time`, the `/v2/pkg/humanrelay` and
`/v2/pkg/operationjournal` packages, and
`/v2/pkg/humanrelay/cloudflare`, under module
`github.com/ToppyMicroServices/agents-secure-binding`.

Use `contentDigest` as the relay request's `ContentDigest` and the matching map
key as its `ContentRef`. `MessageDigest` binds the subject and plain-text body;
it is not a digest of just the body. Queue through the existing authenticated
relay service before calling `worker.Dispatch(ctx, intentID)`. The worker
rechecks the durable reachability grant immediately before its provider
callback. Do not mount `Dispatch` or `Lookup` as unauthenticated network routes.

Keep the provider token, private recipient map and message configuration outside
Agent input and receipts. Notification content should direct the recipient to
their authenticated ASB inbox. Do not place bearer login tokens or approval
capabilities in the email. Delivery or a link click never performs a Human
approval.

## Persistence and recovery

The adapter binds every dispatch field, Cloudflare account, sender, resolved
recipient and exact message to a durable journal reservation. A reused IntentID
with different bound values conflicts. Token rotation does not change that
binding. Only the caller that wins the transition to `RUNNING` may send.

The example `operationjournal.FileStore` is a single-process journal. Run
exactly one worker process with that journal; independent worker processes need
a Store implementation that provides the same atomic transitions across those
processes. The outer relay store's process lock does not turn every journal
operation into a cross-process transaction.

Schedule worker dispatches below `MaxInFlight`, including capacity used by
concurrent reconciliation. The relay persists `DISPATCHING` before invoking
the adapter, so a busy adapter leaves the intent uncertain even when it made
no network request. Freeing capacity does not allow that worker intent to be
sent again. A standalone adapter call can return `ErrBusy` before reserving its
journal, but that error is not permission to retry a worker's consumed dispatch
reservation. Check the durable relay receipt; never requeue it automatically.

| Observation | Result |
| --- | --- |
| HTTP success with the exact recipient in `delivered` or `queued`, and no recipient rejection | Persist a transport acknowledgement, then allow `PROVIDER_ACKNOWLEDGED` |
| Revoked grant before dispatch | Relay records `CANCELED`; no Cloudflare request |
| Adapter capacity exhausted after the worker reserves dispatch | Keep `DISPATCHING`, without a network attempt or automatic retry |
| Timeout, lost response, malformed response, rejection, or ambiguous persistence failure after dispatch starts | Do not resend; retain an uncertain attempt |
| Repeated dispatch after a saved acknowledgement | Return saved evidence without another request |
| Reconciliation with a saved, exactly bound acknowledgement | Recover that evidence into the relay receipt without sending |
| Reconciliation without a saved acknowledgement | Keep `DISPATCHING`; absence is not proof of no send |

The provider API guide shows recipient-grouped responses without a message ID,
while the generated API reference also lists `message_id` and
`suppressed_recipients`. The adapter accepts the documented success variants,
checks the recipient groups, and does not require a provider message ID. It
retains an opaque digest as acknowledgement evidence; provider addresses and
raw responses are not returned to Agents.
Sources: [REST guide](https://developers.cloudflare.com/email-service/api/send-emails/rest-api/),
[API reference](https://developers.cloudflare.com/api/resources/email_sending/methods/send/).

`Lookup` reads the local journal only. It can recover an acknowledgement saved
before the relay receipt was committed. It cannot recover a send whose HTTP
response was lost before the adapter saved evidence. There is no Cloudflare
event collector in this adapter. A future collector must authenticate and
correlate exact requests; ordinary delivery or engagement events cannot confer
ASB approval. Cloudflare's
[delivery event](https://developers.cloudflare.com/email-service/reference/event-subscriptions/)
means the recipient mail server accepted the message, not that the Human read
or approved it.

Do not delete journal entries to retry an unknown send. Preserve relay state,
authority and journal together. Stop all writers for a consistent backup, and
fence restored state before resuming sends; an old backup can omit attempts
that already reached Cloudflare. The reference file journal retains at most
10,000 operations and fails closed at its limit. Plan retention and capacity
before reaching that bound. This adapter provides no automatic compaction,
multi-host failover or recovery from rolled-back storage.
`operationjournal.FileStore` treats a missing file as a new journal, so do not
recreate a missing provider journal for existing relay state. Diagnose data
loss and restore the consistent, fenced state set first.

## Validation

Run on Linux:

```sh
go test -race -count=1 ./pkg/humanrelay/...
make human-coordination-gate
```

The adapter tests cover request binding, bounded transport, uncertain results,
duplicate attempts, and local acknowledgement recovery. Linux composition tests
exercise real loopback TLS, SQLite authority, relay persistence, reopen, and
revocation. These are implementation tests with trusted verifier fixtures;
they do not replace external ASB authentication tests or live email delivery.

A live check requires a configured account and sending domain, an authorized
sender and recipient, approved content, and a bounded send count. Keep its
result separate from the synthetic Linux results. This change does not
promote the Human Coordination production profile or certify an operator host.
