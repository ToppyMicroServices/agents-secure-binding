# ASB local approval: binary quick start

This archive contains an experimental `asb-human` executable for the OS and
architecture named in the artifact. No Go installation, Node.js, Docker, LLM
account, or TEE hardware is needed to run it. Keep all extracted files in one
folder and open a terminal there.

## Get an executable

Open the [Local Human Approval workflow](https://github.com/ToppyMicroServices/agents-secure-binding/actions/workflows/human-approval.yaml?query=branch%3Amain)
and select a successful `main` run. Sign in to GitHub to download its artifact
for your computer:

| Computer | Artifact name prefix |
| --- | --- |
| macOS, Apple silicon | `asb-human-darwin-arm64-` |
| Linux, x86-64 | `asb-human-linux-amd64-` |
| Windows, x86-64 | `asb-human-windows-amd64-` |

The suffix is the full source commit ID. CI artifacts expire after 14 days;
if no matching artifact is available, use the
[source-build instructions](https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/docs/local-human-approval.md#start-here).
Other OS/architecture combinations also use the source-build route.
The [Releases page](https://github.com/ToppyMicroServices/agents-secure-binding/releases)
is the place to check for retained, versioned assets; availability is specific
to each release. Extract the complete archive before continuing.

Choose a run or release record with a passing
**Run artifact** job for your OS and architecture. That job downloads the
archive, checks its binary checksum, and runs that executable's `self-test`
without rebuilding it. A successful **Compile** job alone is not an execution
test. The check uses a simulated Human reviewer, not a browser or TEE.

## macOS or Linux

Check the extracted binary against `SHA256SUMS` first. On macOS:

```text
shasum -a 256 -c SHA256SUMS
```

On Linux:

```text
sha256sum -c SHA256SUMS
```

Continue only if the check reports `asb-human: OK`. Restore the executable
bit, then run the unattended check:

```text
chmod +x asb-human
./asb-human self-test
```

To make a decision yourself in the browser:

```text
./asb-human demo --data-dir ./.asb-human
```

## Windows PowerShell

Check the checksum before running:

```powershell
$expected = ((Get-Content -LiteralPath .\SHA256SUMS -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath .\asb-human.exe -Algorithm SHA256).Hash
if ($actual -ine $expected) { throw 'Artifact checksum mismatch' }
```

```text
.\asb-human.exe self-test
.\asb-human.exe demo --data-dir ./.asb-human
```

## What to expect

`self-test` prints progress, checks all four Human decisions over real
authenticated loopback connections, and verifies saved results after reopening
SQLite. It simulates the Human reviewer, uses its own temporary state, and
removes that state when it finishes. Success ends with:

```text
PASS: local approval self-test completed.
```

`demo` starts the service and a separate Agent process. Open the private login
link printed in the terminal on the same computer. Review the proposal, then
choose 「許可する」「拒否する」「該当なし」 or 「判断不明」 and confirm. The Agent
prints `APPLIED`, `DENIED`, `NOT_APPLICABLE`, or `UNDETERMINED`. Only approval
changes this app's own `maintenance_mode` Boolean in its local SQLite database.
「判断不明」 is a saved Human judgment; 「処理結果不明」 means the request's result
has not been confirmed and needs a status check.

Press Ctrl+C to stop the service. `demo` keeps keys, decisions, and recovery
receipts in `.asb-human`; protect that directory and the login link. Each new
`demo` run keeps the history and creates a new proposal. Use the recovery
instructions in the guide below if you need to resume an interrupted proposal.

## Preview limits

Use one trusted computer and OS user. This is not multi-user isolation, real
Human identity verification, hardware qualification, or a production service.
It does not change any external server or send messages to a delivery provider.

The bundle includes its source and dependency inventory, the ASB license and
linked dependency notices. `SHA256SUMS` records the binary checksum; release
asset checksums and CI evidence are listed in the release record. Executables
are not platform-code-signed or notarized. If your OS blocks the executable,
use the source-build instructions instead of disabling its security checks.

See the [source, usage, and recovery guide](https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/docs/local-human-approval.md).
It includes Go build instructions, troubleshooting, separate Agent commands,
and storage limits. Run the executable with `--help` for available commands.
