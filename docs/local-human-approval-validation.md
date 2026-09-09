# Local approval validation

This record covers the current local approval application, not the generic
Human Coordination production profile. The application changes one Boolean
inside its own database. No external provider or hardware was used.

## Dependency repair

Checked on 2026-09-08; isolated Cocos tests and module consistency were also
rerun on 2026-09-09.

Root and Cocos select `google.golang.org/grpc v1.83.1` with `GOWORK=off`.
The upstream advisory [GHSA-vp52-pcj8-j9qc](https://github.com/grpc/grpc-go/security/advisories/GHSA-vp52-pcj8-j9qc)
identifies that release as patched. The repository does not disable its
default receive-buffer compaction; deployed environment settings were not
inspected. No exhaustion attack was reproduced.

The existing package-level vulnerability gates completed for both modules
without imported-package findings. They still reported eight findings in
root's required modules and three in Cocos's required modules. This is not a
graph-wide zero-vulnerability claim. A feature-branch update does not close
default-branch Dependabot alerts before merge.

## Application checks — 2026-09-08

- Go 1.26.6: application and CLI race tests passed, including actual SQLite,
  TLS 1.3/mTLS, fresh ASB proofs, separate command processes and restart.
- A committed approval response was dropped on a real HTTP connection. After
  reopening the database, a fresh-proof retry returned the original response
  bytes and the setting revision remained one.
- A transaction failure rolled back the replay mark and mutation together.
  Changed review revisions did not silently apply a new configuration value.
- The admission-limit test accepted 5,000 proposals, rejected the next, and
  completed all admitted proposals within the 10,000-receipt ceiling.
- Existing gRPC client/server regression tests passed. Existing production,
  clients, TaskCoord, protected-change consumer and schema tests also passed.
- Scoped `go vet`, module verification, module tidy-diff and workflow syntax
  checks passed.
- CGO-disabled builds completed for macOS arm64, Linux amd64 and Windows
  amd64. Only the macOS binaries were executed locally. Linux and Windows
  runtime validation is configured in `human-approval.yaml`; compile success
  does not establish those runtime results.
- In a real browser, the private fragment link logged in and removed the
  fragment from the address. Approval changed OFF/revision 0 to ON/revision 1.
  A second proposal was denied; ON/revision 1 was retained. Reload restored the
  browser session and both outcomes. The desktop layout was visually checked.

Commands used for the application checks:

```text
GOWORK=off GOTOOLCHAIN=go1.26.6+auto go test -race -count=1 ./internal/humanapp ./cmd/asb-human
GOWORK=off GOTOOLCHAIN=go1.26.6+auto go vet ./internal/humanapp ./cmd/asb-human
```

## Usability follow-up — 2026-09-09

The source quick-start `go run ./cmd/asb-human self-test` passed with Go
1.26.6, both in the shared workspace and with `GOWORK=off`. The compiled,
CGO-disabled macOS arm64 executable also passed. The self-test used temporary
credentials and real authenticated loopback connections, checked approval and
denial, reopened SQLite, and recovered the original proposal and decision
responses without another setting change. It removed its temporary state
before reporting PASS. The Human gateway was simulated.

The final application and CLI race tests passed again (40.108s and 6.309s),
as did scoped `go vet`. Additional checks covered:

- An old pending proposal remains visible behind more than 100 newer decided
  proposals. Whole-queue counts are returned, and reviewing the oldest item
  exposes the next waiting item.
- Two loopback origins on different ports retain distinct browser sessions,
  tested with a cookie jar. This avoids accidental session replacement; it
  does not isolate untrusted local services.
- Four dependency-free Node tests cover unchanged-card preservation, expanded
  details on changed results, confirmation-dialog races, and truncated inbox
  counts. JavaScript syntax and workflow syntax checks passed.
- The source guide's `demo` with default flags launched a separate Agent, printed a
  private login link, and used automatically assigned ports. In the browser,
  approval produced ON/revision 1; a second Agent proposal was denied without
  changing that setting. Reload restored the session and both outcomes.
  Expanded proposal details and keyboard focus survived several automatic
  refreshes. The desktop layout was visually inspected.
- Production, client, TaskCoord, protected-change consumer and schema
  regression tests passed. The core dependency-boundary check, root module
  verification and root tidy-diff passed. Cocos tests, vet, module verification
  and tidy-diff passed independently.
- Final CGO-disabled builds succeeded for macOS arm64, Linux amd64 and Windows
  amd64. Only macOS was executed locally. Linux/Windows runtime jobs and
  downloadable CI artifacts were configured, but no completed remote CI run
  or published artifact was available at that checkpoint.

README, contribution instructions, the source usage guide and the binary
quick-start were checked against these entry points. The normal source commands
use the checked-in `go.work`; the independent root checks explicitly disable
it. Source startup refreshed `go.work.sum` for the updated dependency graph.

## Pre-commit review and fixes — 2026-09-09

The review covered all pending application, dependency, workflow and document
changes. It found two functional recovery defects, which are now fixed:

- An inbox response started before a decision could restore the old setting
  and pending card after approval. Reads now carry a generation and obsolete
  responses are discarded. A fresh read is queued when needed. Nine Node
  tests pass, including late responses, session replacement and preservation
  of an uncertain outcome until a new manual read.
- A proposal saved but not admitted could be rejected after another change
  advanced the revision. The CLI called this unknown and recommended a retry
  that could never succeed. Proposal and inspection conflicts now have
  specific guidance. Receipt bytes and revisions remain immutable; transport
  and response-output failures still require outcome recovery.

Three bounded real-server probes also confirmed that incomplete bodies could
remain open beyond the header timeout. Both servers now use a 15-second read
deadline and a 30-second write deadline. Six real-socket tests cover declared
length and chunked bodies on the session, challenge and command routes; they
receive rejection at the read deadline. A complete authenticated request
passes through the same servers. Write deadlines also cover TLS control
writes during a read, as checked in Go 1.26.6 source. No connection-exhaustion
or TLS KeyUpdate-flood test was performed.

After the main fixes, the full root suite passed: 92 tested packages and 42
packages without tests. Application race tests passed in 44.031s. Following
the final inspection-conflict and write-deadline changes, all CLI race tests
passed again in 21.021s, and scoped vet passed. Independent Cocos, SNP and TDX
tests, vet and module consistency checks passed earlier in the same review;
those modules were not changed by these final application fixes.

Final CGO-disabled binaries compiled for macOS arm64, Linux amd64 and Windows
amd64. The exact macOS executable passed `self-test`. Its browser demo was
also exercised: approval produced ON/revision 1, denial preserved that value,
and reload restored the session and both results. The desktop screen was
visually checked. Deliberately delayed-response races were tested in Node,
not by manipulating the real browser's network.

Workflow syntax, JavaScript syntax and relative document links were checked.
At this pre-commit checkpoint, Linux/Windows execution, remote CI and published
artifacts were still unverified.
The local `golangci-lint` executable was unavailable; its CI action was not
reproduced.

## Remote OS verification — 2026-09-09

[Local Human Approval run 34350475409](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/34350475409)
passed all six jobs for signed commit
`8f1fa52c9b66db491f7d636fd0a9d68d5c772a56`. GitHub reported the commit signature
as verified. This is the tested application revision; the later documentation
update does not change its code.

| Native runtime | Runner image | Job duration |
| --- | --- | --- |
| Linux amd64 | Ubuntu 24.04 | 1m27s |
| macOS arm64 | macOS 26 | 1m55s |
| Windows amd64 | Windows Server 2025 | 7m41s |

Each runtime used Go 1.26.6 with `GOWORK=off` and passed application and CLI
race tests, vet, nine Node UI-logic tests, and `self-test`. The CLI suite includes
separate process recovery and an actual shell/native-child round trip of
receipt paths containing spaces, quotes, backslashes, dollar signs and Japanese
text. Windows used PowerShell 7 (`pwsh`); Windows PowerShell 5.1 was not tested.

The [initial run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/34348068927)
failed Windows receipt-guidance assertions: Go `%q` formatting escaped
backslashes, while the tests looked for raw paths. Recovery arguments now use
literal PowerShell or POSIX-shell quoting. The
[first fix run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/34349648190)
then exposed an unquoted Go test flag in the new shell test driver. Quoting
that fixed argument resolved the failure. Neither failed run is counted as
passing evidence; no tests were skipped to obtain the final result.

All three CGO-disabled artifacts were downloaded. Their binary checksums,
embedded OS/architecture, clean source revision, and bundled usage guide were
verified. The downloaded macOS executable also passed `self-test`. Linux and
Windows runtime evidence comes from native CI source builds; their separately
cross-built artifact executables were not directly run. Browser rendering on
Linux and Windows was not exercised; Node tests cover UI logic only.

The three push-triggered workflow executions used standard hosted runners in
this public repository. The timing API reported zero billable runtime for all
three runs. Final archives total 28,680,188 bytes with 14-day retention; this is
not an account-wide storage bill audit. No paid hardware was provisioned.
Existing Actions emitted Node 20 deprecation warnings; no runtime-security
override was enabled. The full repository CI and production/hardware gates
were not run by this dedicated application workflow. No self-hosted runner was
available, and live SNP/TDX qualification remains incomplete.

## Remaining boundaries

These results establish a local Developer Preview. They do not establish
multi-user isolation, independent Human-held-key evidence, browser coverage on
every OS, disk-loss recovery, credential renewal, high availability, or
external-effect reconciliation. Credential lifetime and storage limits are
listed in [the usage guide](local-human-approval.md).
