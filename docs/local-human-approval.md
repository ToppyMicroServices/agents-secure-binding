# Try local Human approval

`asb-human` lets an Agent propose a change and wait for your decision in a
browser. Approving changes one Boolean, `maintenance_mode`, in the app's own
SQLite database. Declining, marking a proposal not applicable, or being unable
to decide leaves that setting unchanged. Nothing is sent to
an external service, and no real server configuration is changed.

The local approval app is an experimental preview for one trusted computer and
OS user. It first shipped in `v2.0.0-rc.3`. These instructions describe the
current source. For a downloaded build, use the `USAGE.md` shipped with it.

## Start here

You can [download and verify a prebuilt preview](asb-human-binary-quickstart.md)
on Linux x64, Windows x64 or Apple Silicon. To build from source, follow the
[README quick start](../README.md#quick-start) to install Go 1.26.11 and open
the repository in a terminal. The first run downloads the Go dependencies.
The following source commands work on Linux, macOS and Windows PowerShell.

First, check the local workflow without opening a browser:

```text
go run ./cmd/asb-human self-test
```

The command prints its progress and ends with:

```text
PASS: local approval self-test completed.
```

It uses real TLS 1.3/mTLS and ASB verification to submit proposals, simulate
all four decisions, and check saved results after reopening SQLite. It picks
a free loopback port and removes its private temporary state when it finishes.
The Human reviewer is simulated: this is a software check, not evidence of
Human identity or hardware security. A failed check exits with an error. The
default runtime limit is 30 seconds after compilation; use
`self-test --timeout 1m` if a slower machine needs more time.

Now make a decision yourself:

| Platform | Command |
| --- | --- |
| macOS or Linux | `go run ./cmd/asb-human demo --data-dir ./.asb-human` |
| Windows PowerShell | `go run ./cmd/asb-human demo` |

1. On the same computer, open the login file named in the terminal in a text
   editor. Copy the link into your browser.
2. Review the pending proposal and its before/after values. The separate Agent
   process requests `maintenance_mode=true` by default.
3. Choose 「許可する」 (approve), 「拒否する」 (decline), 「該当なし」 (not applicable),
   or 「判断不明」 (unable to decide), then confirm. Only approval can apply a change.
4. Press Ctrl+C when you are finished. The service stays running after the
   Agent receives its result.

The app keeps its keys, database and recovery receipts in `.asb-human` for the
macOS/Linux example and in the per-user `%AppData%\asb-human` directory on
Windows. The terminal shows the login file path. Each link in that file can be
used once and expires within five minutes. Reopen the file for a fresh link
after use or expiry. Keep the directory and its links private. `demo` chooses
free ports each time.

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
.\asb-human.exe demo
```

The executable includes the browser UI and SQLite implementation. Examples
below use `./asb-human`; use `.\asb-human.exe` in PowerShell, or substitute
`go run ./cmd/asb-human` when running from source. Each command supports `--help`.
On Windows, omit `--data-dir ./.asb-human` in the examples below to keep using
your per-user state. When a command takes a receipt path, use the path printed
when you submitted the proposal.

## If something does not work

| Symptom | What to do |
| --- | --- |
| `go` is not found, or dependency downloads fail | Check the Go installation and network access. Downloads are needed for the first source build; no LLM credentials are needed. |
| `address already in use` | A chosen port is occupied. `demo` uses free ports by default. For `serve`, choose unused ports with `--core-listen` and `--web-listen`, then pass the core address to the Agent as shown below. |
| The browser cannot connect | Keep `demo` or `serve` running and use the current link from its login file on the same computer. The browser connects to the web port, not the core TLS port. |
| The login no longer works after a restart | Open the login file named by the current process and use its latest link. Restarting the service ends old browser sessions and preserves saved decisions. |
| The data directory is not private, or initialization is incomplete | For a new trial, choose a new, unused `--data-dir` path. Do not delete an existing directory to repair it: it may contain keys, decisions, and receipts. |
| The Agent is still waiting | A person must choose one of the four decisions in the browser. `self-test` is the unattended check; `demo` does not decide on your behalf. |
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

Use the login file named in the service terminal to open the inbox. Without
`--wait`, the Agent returns after the proposal acknowledgement. With `--wait`, it polls
using fresh authentication until the operation reaches a terminal state:

| `operation.state` | Meaning |
| --- | --- |
| `PENDING_REVIEW` | Waiting for a decision; the setting is unchanged. |
| `APPLIED` | Approved and applied to the local database. |
| `DENIED` | Declined; this proposal did not change the setting. |
| `NOT_APPLICABLE` | The person says this proposal is outside their review scope; no change was applied. |
| `UNDETERMINED` | The person cannot decide, for example because information is missing; no change was applied. |
| `STALE` | The reviewed setting revision is no longer current; no change was applied. |

A successful command exit alone does not mean approval. Read
`operation.state` in the result. JSON events are written to standard output
for scripts, including the `ready` event's actual `core_address` and
`web_origin`. The `login_file` field gives the path to the private login file.
If you choose a different core port, pass the same address to
both `agent` and `inspect`:

```text
./asb-human serve --data-dir ./.asb-human --core-listen 127.0.0.1:9091 --web-listen 127.0.0.1:9090
./asb-human agent --data-dir ./.asb-human --core-address 127.0.0.1:9091 --wait
```

## Four Human decisions

These distinctions also matter for a Human reviewer. A refusal, an out-of-scope
request, and insufficient information are different answers. None authorizes
the proposed change.

The browser sends `POST /api/decision` with `operation_id`, `proposal_digest`,
`expected_revision`, and one explicit `decision` value:

| Human answer | `decision` | Result for a current proposal |
| --- | --- | --- |
| 許可 | `APPROVE` | `APPLIED`; the setting changes. |
| 拒否 | `DECLINE` | `DENIED`; the setting is unchanged. |
| 該当なし | `NOT_APPLICABLE` | `NOT_APPLICABLE`; the setting is unchanged. |
| 判断不明 | `UNDETERMINED` | `UNDETERMINED`; the setting is unchanged. |

These are answers to a proposal. The local actor/command policy separately
returns `Permit`, `Deny`, `Indeterminate`, or `NotApplicable`. Only `Permit`
passes that policy check; the ASB proof and proposal binding are checked
separately.

The existing session, same-origin, and CSRF checks still apply. For older
clients, `approve: true` or `approve: false` alone maps to `APPROVE` or `DECLINE`.
A request containing both `decision` and `approve` is rejected, as are missing,
null, or unknown decision values.

All four answers finish the proposal. Its decision is immutable; repeating a
saved command recovers the same result. If more information later permits a
new review, create a new proposal with a new operation ID and receipt. Keep the
original decision as history. A proposal that became `STALE` still has no effect.

`UNDETERMINED` is a recorded Human answer. `OUTCOME_UNKNOWN` instead means the
service could not confirm the result of a request, for example after losing a
response. It is not a fifth Human answer or an operation state to treat as
approval. Refresh or inspect the original operation before trying another
action, as described below.

See the [related-check review](decision-semantics-review.md) for how these
answers differ from proof verification, task acceptance, quorum approvals,
and execution outcomes.

## Recover an interrupted proposal

The Agent saves a receipt **before** it submits a proposal. The
`proposal_saved` event gives its absolute path. For `change-001`, the default
path is `.asb-human/receipts/proposal-change-001.json`. Keep this file: it
contains the original command, expected revision, IDs, and digest needed to
recover the same operation.

Recovery messages quote receipt arguments for PowerShell on Windows and POSIX
shells on macOS/Linux. Errors are emitted as JSON: decode the `error` field
before copying a suggested argument; JSON backslash escapes are not shell
syntax. The unquoted path is also in the `proposal_saved` event's `receipt`
field. Windows Command Prompt is not the documented shell.

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
the private login file to start a browser session. ASB authenticates the
gateway key. The person does not hold an independent signing key. This preview is not multi-user isolation,
hardware attestation, or a production storage adapter for generic TaskCoord.

One SQLite transaction records the local decision, setting change, replay
state, and command outcome. Recovery covers that database effect, not an
external action. Keep the state on a local filesystem owned by the same
trusted OS user. Receipts are created exclusively, flushed before submission,
and restricted to their owner on Unix.

On Windows, the app creates its state directory with a protected discretionary
access control list (DACL). Its permissions for the current user, SYSTEM and
Administrators are inherited by files and folders inside it. An existing state
directory with broader access is rejected. Use the default `%AppData%\asb-human`
in a private user profile. For a custom `--data-dir`, choose a local path whose
parent directories are trusted and writable only by you or system administrators.
Choose a path without junctions or other directory links along it. To keep existing decisions and
receipts, stop the app, restrict the existing directory **and its contents** to
those accounts, then rotate any credentials that others could have read.
Keep the existing database and receipts during this change.

If you save a receipt with `--receipt` or export an archive with `storage-export
--output` outside the state directory, use a private destination directory.
Apply suitable permissions to those files and to any backup copies.

Local credentials expire one year after initialization. Stop every process
using the data directory, inspect the non-secret status, and rotate the complete
local trust generation before expiry:

```text
asb-human credentials-status --data-dir ./.asb-human
asb-human credentials-rotate --data-dir ./.asb-human
```

Rotation stages and validates a complete CA, server, agent, gateway, and
authority-key generation before atomically selecting it. It does not move or
rewrite the SQLite database, receipts, or bootstrap token. Previous generations
remain private in `credential-generations` as recovery evidence; there is no
supported rollback or automatic cleanup command yet. The data-directory lock rejects
rotation while `serve`, `demo`, `agent`, `inspect`, or a storage operation is
active.

Older data directories can contain a bootstrap token. Current servers use
single-use login links. If you need to rotate the legacy token, stop the service
and run:

```text
asb-human token-rotate --data-dir ./.asb-human
```

The legacy token cannot start a browser session on the current server. On
restart, use the login file named by `serve` or `demo`.

For a simple backup, stop the service and copy the **complete private
directory**, including keys, receipts, and database sidecars. Protect backups
with the same access controls as the working directory. Do not copy only
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

Inspect the current online counts and limits without deleting records:

```text
asb-human storage-status --data-dir ./.asb-human
```

Create a consistent SQLite snapshot with a SHA-256-bound JSON manifest, then
verify it independently:

```text
asb-human storage-export --data-dir ./.asb-human \
  --output /private/archive/asb-human-2026-09-22.sqlite
asb-human storage-verify --data-dir ./.asb-human \
  --archive /private/archive/asb-human-2026-09-22.sqlite
```

The archive directory must be private on Unix, and existing archive or manifest
files are never replaced. Verification on Unix creates a private temporary
snapshot, rereads the source to reject in-place changes, and therefore needs
free temporary space up to the archive size. On
Windows it holds the archive open without write, delete, or rename sharing for
the duration of verification. Export does not compact the online database, so
the 5,000/10,000 limits remain a fail-closed boundary. Long-running deployments
still need a selected retention policy and a tested compaction/tombstone design
before they can reclaim online capacity.

</details>

## Developer checks

The source examples above use the checked-in shared `go.work`. CI also tests
the root module independently with `GOWORK=off`.

```text
go test -race -count=1 ./internal/humanapp ./cmd/asb-human
go vet ./internal/humanapp ./cmd/asb-human
```

The [Local Human Approval workflow](../.github/workflows/human-approval.yaml)
normally runs Ubuntu and Windows runtime tests and separate cross-builds.
Native macOS runtime and artifact checks run only when started manually.
Check the results for your commit: a successful cross-build does not establish
that the app ran on that OS. The
[validation record](local-human-approval-validation.md) distinguishes local
checks from CI and remaining qualification work.
