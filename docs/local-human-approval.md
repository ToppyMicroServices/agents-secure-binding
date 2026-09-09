# Try local Human approval

`asb-human` lets an Agent propose a change and wait for your decision in a
browser. Approving changes one Boolean, `maintenance_mode`, in the app's own
SQLite database. Declining leaves that setting unchanged. Nothing is sent to
an external service, and no real server configuration is changed.

This is an experimental preview for one trusted computer and OS user. It is
available in this source branch, not in `v2.0.0-rc.2`. It does not require SNP,
TDX, a GPU, an LLM account, Docker, Node.js, or a separate SQLite installation.

## Start here

Install Go 1.26.6 and open a terminal in the repository root. Check `go version`
if you are unsure which version is active. The first `go run` downloads
dependencies and compiles the app, so allow for that initial setup. The same
commands work in macOS/Linux terminals and Windows PowerShell.

First, check the local workflow without opening a browser:

```text
go run ./cmd/asb-human self-test
```

The command prints its progress and ends with:

```text
PASS: local approval self-test completed.
```

It uses real TLS 1.3/mTLS and ASB verification to submit a proposal, simulate
approval and decline, and check saved results after reopening SQLite. It picks
a free loopback port and removes its private temporary state when it finishes.
The Human reviewer is simulated: this is a software check, not evidence of
Human identity or hardware security. A failed check exits with an error. The
default runtime limit is 30 seconds after compilation; use
`self-test --timeout 1m` if a slower machine needs more time.

Now make a decision yourself:

```text
go run ./cmd/asb-human demo --data-dir ./.asb-human
```

1. Open the private login link printed in the terminal, on the same computer.
2. Review the pending proposal and its before/after values. The separate Agent
   process requests `maintenance_mode=true` by default.
3. Choose 「承認する」 (approve) or 「拒否する」 (decline), then confirm. The Japanese UI
   shows 「適用済み」 or 「拒否済み」; the Agent result uses `APPLIED` or `DENIED`.
4. Press Ctrl+C when you are finished. The service stays running after the
   Agent receives its result.

The app creates `.asb-human` for its keys, database, and recovery receipts.
Let it create this private directory rather than using an existing shared
folder. Keep both the directory and login link private. The link uses a URL
fragment (`#login=...`), not a query parameter; the command does not launch a
browser for you. `demo` chooses free ports automatically, so use the printed
link rather than a fixed address.

Running `demo` again keeps earlier decisions and starts a new proposal. To
request the opposite value, add `--enabled=false`. Use the
[recovery workflow](#recover-an-interrupted-proposal) to resume an existing
proposal instead of creating a new one.

## Build once for regular use

Building an executable avoids invoking the Go build step each time. On macOS
or Linux:

```text
go build -o asb-human ./cmd/asb-human
./asb-human self-test
./asb-human demo --data-dir ./.asb-human
```

On Windows PowerShell:

```text
go build -o asb-human.exe ./cmd/asb-human
.\asb-human.exe self-test
.\asb-human.exe demo --data-dir ./.asb-human
```

The executable includes the browser UI and SQLite implementation. Examples
below use `./asb-human`; use `.\asb-human.exe` in PowerShell, or substitute
`go run ./cmd/asb-human` when running from source. Each command supports `--help`.

<details>
<summary>Try a CI-built executable without installing Go</summary>

After a successful [Local Human Approval workflow run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/workflows/human-approval.yaml?query=branch%3Afeat%2Fhuman-coordination-product-v1),
sign in to GitHub, open that run, and select its artifact for your OS and
architecture. The artifact name includes the full source commit ID. Extract
the archive and read `USAGE.md`; `SHA256SUMS` contains the binary checksum.

These are 14-day CI artifacts, not signed or notarized releases. Downloading
an artifact does not establish production readiness. On macOS and Linux,
restore the executable bit with `chmod +x asb-human` before running it.

</details>

## If something does not work

| Symptom | What to do |
| --- | --- |
| `go` is not found, or dependency downloads fail | Check the Go installation and network access. Downloads are needed for the first source build; no LLM credentials are needed. |
| `address already in use` | A chosen port is occupied. `demo` uses free ports by default. For `serve`, choose unused ports with `--core-listen` and `--web-listen`, then pass the core address to the Agent as shown below. |
| The browser cannot connect | Keep `demo` or `serve` running and use the exact printed link on the same computer. The browser connects to the web port, not the core TLS port. |
| The login no longer works after a restart | Open the newly printed login link. Browser sessions are not retained across service restarts; saved decisions are. |
| The data directory is not private, or initialization is incomplete | For a new trial, choose a new, unused `--data-dir` path. Do not delete an existing directory to repair it: it may contain keys, decisions, and receipts. |
| The Agent is still waiting | A person must approve or decline in the browser. `self-test` is the unattended check; `demo` does not approve on your behalf. |
| An operation is `STALE` | Another approved change advanced the setting after this proposal was created. This proposal has no effect. Review the current state before intentionally creating a new one. |
| A saved proposal is rejected with `CONFLICT` | Keep its receipt and inspect it. Repeating the same rejected command cannot resolve a revision or identifier conflict. See the recovery guidance below before creating a replacement. |
| The response is unavailable or the outcome is unknown | Keep the receipt and follow the recovery steps below. Do not assume the change failed and submit a replacement. |

`serve` defaults to `http://127.0.0.1:8090` for the browser and
`127.0.0.1:8091` for the TLS 1.3/mTLS core. `demo` chooses free ports instead.
Listener flags accept explicit loopback IPs only. Wildcard addresses and
`localhost` are rejected. This preview is not designed for remote access or a
reverse proxy.

Both listeners use a 15-second request-read deadline and a 30-second write
deadline. These bound incomplete bodies and stalled writes, including TLS
control writes during a core read. They are local resource limits, not a
production denial-of-service guarantee.

## Run the Agent separately

Start the service in one terminal:

```text
./asb-human serve --data-dir ./.asb-human
```

`serve` initializes a new directory automatically and preserves existing
state. An optional `init --data-dir ./.asb-human` command creates credentials
without starting the service. In another terminal, submit a named proposal:

```text
./asb-human agent --data-dir ./.asb-human --operation-id change-001 --enabled=true --wait
```

Open the login link from the service terminal to decide. Without `--wait`, the
Agent returns after the proposal acknowledgement. With `--wait`, it polls
using fresh authentication until the operation reaches a terminal state:

| `operation.state` | Meaning |
| --- | --- |
| `PENDING_REVIEW` | Waiting for a decision; the setting is unchanged. |
| `APPLIED` | Approved and applied to the local database. |
| `DENIED` | Declined; this proposal did not change the setting. |
| `STALE` | The reviewed setting revision is no longer current; no change was applied. |

A successful command exit alone does not mean approval. Read
`operation.state` in the result. JSON events are written to standard output
for scripts, including the `ready` event's actual `core_address` and
`web_origin`. If you choose a different core port, pass the same address to
both `agent` and `inspect`:

```text
./asb-human serve --data-dir ./.asb-human --core-listen 127.0.0.1:9091 --web-listen 127.0.0.1:9090
./asb-human agent --data-dir ./.asb-human --core-address 127.0.0.1:9091 --wait
```

## Recover an interrupted proposal

The Agent saves a receipt **before** it submits a proposal. The
`proposal_saved` event gives its absolute path. For `change-001`, the default
path is `.asb-human/receipts/proposal-change-001.json`. Keep this file: it
contains the original command, expected revision, IDs, and digest needed to
recover the same operation.

If the service stopped, restart `serve` with the same data directory. First
inspect the saved proposal:

```text
./asb-human inspect --data-dir ./.asb-human --receipt ./.asb-human/receipts/proposal-change-001.json
```

To resume submission and wait for its decision:

```text
./asb-human agent --data-dir ./.asb-human --receipt ./.asb-human/receipts/proposal-change-001.json --wait
```

The app reuses the exact saved command with fresh authentication. If the
first submission committed, it returns the original command result; live
status then shows any later decision. It never silently updates a saved
proposal to a newer setting revision. A malformed or partial receipt is
rejected without submission or replacement. Preserve it while investigating.

A receipt can also exist for a proposal that was never accepted. For example,
the Agent may stop after saving the receipt, while another approval advances
the setting. Resuming the old proposal then returns `CONFLICT`; it is not a
lost success response, and repeating that same command will not fix it.
Inspect the receipt against the same service and data directory. If no matching
operation is found, review the current setting in the browser. If you still
want the change, deliberately submit a new proposal with a new operation ID
and receipt. Keep the original receipt; do not edit its revision or reuse its ID.

Use the same `--core-address` if the service uses a nondefault port.
`agent --timeout 2m` limits waiting to two minutes and leaves the receipt
available. `--receipt` can also select an explicit path when creating a new
proposal; existing receipts are never overwritten.

<details>
<summary>Inspect by operation ID and digest</summary>

```text
./asb-human inspect --data-dir ./.asb-human --operation-id change-001 --digest sha256:<64-lowercase-hex-digits>
```

Replace the digest placeholder with the exact value from `proposal_saved` or
the response, including `sha256:`. If only `--operation-id` is supplied,
`inspect` reads the receipt at the default path.

</details>

## Trust and storage limits

The browser gateway asserts `human:local-owner` on behalf of the person using
the private login link. ASB authenticates the gateway key; the person does not
hold an independent signing key. This preview is not multi-user isolation,
hardware attestation, or a production storage adapter for generic TaskCoord.

One SQLite transaction records the local decision, setting change, replay
state, and command outcome. Recovery covers that database effect, not an
external action. Keep the state on a local filesystem owned by the same
trusted OS user. Receipts are created exclusively, flushed before submission,
and restricted to their owner on Unix. Windows access depends on the user's
directory permissions; Unix file modes do not establish Windows ACLs.

Local credentials expire one year after initialization. There is no
credential-renewal or data-migration command yet, so this preview is not a
long-term storage service. Do not discard old state to repair credential
errors; retaining its history requires an explicit renewal or migration plan.

For a simple backup, stop the service and copy the **complete private
directory**, including keys, receipts, and database sidecars. Do not copy only
the main database while the service is running. SQLite uses WAL and FULL
synchronous commits; process-restart tests do not prove survival of disk loss
or arbitrary power failure.

<details>
<summary>Capacity and retention</summary>

The browser shows up to 100 operations, with pending work first so older
requests do not disappear behind newer history. It also reports the total
pending and saved operation counts when the list is truncated. The store
accepts at most 5,000 proposals and reserves space for their terminal decisions
within its 10,000 mutation-receipt limit. Original mutation results are
retained without automatic deletion. STATUS and INBOX return current state,
not old read receipts. Expired replay entries are cleaned during transactions,
with at most 100,000 live replay entries. Reaching a limit rejects new work
rather than evicting recovery records.

</details>

## Developer checks

The source examples above use the checked-in shared `go.work`. CI also tests
the root module independently with `GOWORK=off`.

```text
go test -race -count=1 ./internal/humanapp ./cmd/asb-human
go vet ./internal/humanapp ./cmd/asb-human
```

The [Local Human Approval workflow](../.github/workflows/human-approval.yaml)
is configured for Ubuntu, macOS, and Windows runtime tests and separate
cross-builds. Check the results for your commit: a successful cross-build does
not establish that the app ran on that OS. The
[validation record](local-human-approval-validation.md) distinguishes local
checks from CI and remaining qualification work.
