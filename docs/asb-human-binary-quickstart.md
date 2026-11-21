# ASB local approval: binary quick start

The `asb-human` preview runs on one computer and includes the browser UI and
SQLite. You can try it without installing Go or running a separate service.

## Get a build for your computer

1. Sign in to GitHub and open the [Local Human Approval runs on main](https://github.com/ToppyMicroServices/agents-secure-binding/actions/workflows/human-approval.yaml?query=branch%3Amain).
   Select a successful run for the commit you intend to try. Use a run from the
   project's `main` branch. The commit page gives its full 40-character SHA.
2. In that run, open the passing **Run artifact** job for your platform. In
   **Verify and run the Unix artifact** or **Verify and run the Windows artifact**,
   copy the 64-character SHA-256 printed next to the executable's name. This is
   the digest of the executable bytes exercised by that job.
3. Under **Artifacts** on the run summary, download the matching archive below.
   Replace `<commit>` with the full commit SHA. Extract it in a new folder and
   open a terminal there.

| Computer | Run artifact job | Artifact name |
| --- | --- | --- |
| macOS, Apple Silicon | `Run artifact (darwin/arm64)` | `asb-human-darwin-arm64-<commit>` |
| Linux, Intel/AMD x64 | `Run artifact (linux/amd64)` | `asb-human-linux-amd64-<commit>` |
| Windows, Intel/AMD x64 | `Run artifact (windows/amd64)` | `asb-human-windows-amd64-<commit>` |

CI archives expire after 14 days. The native macOS artifact check runs on
manually dispatched jobs. If the archive, passing native job or its digest is
unavailable, use the [source build](https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/docs/local-human-approval.md#start-here).
Use that route for other architectures as well.

## Verify the executable and run the self-test

Replace `PASTE_DIGEST_FROM_RUN` with the executable SHA-256 you obtained from
the matching GitHub job. Use the job log as your reference. The copy of
`SHA256SUMS` in the downloaded archive is part of that same download.

**macOS**

```sh
expected='PASTE_DIGEST_FROM_RUN'
printf '%s  asb-human\n' "$expected" | shasum -a 256 -c - &&
  chmod +x asb-human && ./asb-human self-test
```

**Linux**

```sh
expected='PASTE_DIGEST_FROM_RUN'
printf '%s  asb-human\n' "$expected" | sha256sum -c - &&
  chmod +x asb-human && ./asb-human self-test
```

**Windows PowerShell**

```powershell
$expected = 'PASTE_DIGEST_FROM_RUN'
if ((Get-FileHash -Algorithm SHA256 -LiteralPath .\asb-human.exe).Hash -ne $expected) {
    throw 'The executable does not match the selected workflow run.'
}
.\asb-human.exe self-test
```

After the self-test passes, start the browser demo from the same folder:

| Shell | Command |
| --- | --- |
| macOS or Linux | `./asb-human demo --data-dir ./.asb-human` |
| Windows PowerShell | `.\asb-human.exe demo` |

## What to expect

`self-test` prints progress, checks all four Human decisions over real
authenticated loopback connections, and verifies saved results after reopening
SQLite. It simulates the Human reviewer, uses its own temporary state, and
removes that state when it finishes. Success ends with:

```text
PASS: local approval self-test completed.
```

`demo` starts the service and a separate Agent process. On the same computer,
open the login file named in the terminal in a text editor and copy its link
into your browser. Each link is single-use and expires within five minutes.
Reopen the file if you need a fresh link. Review the proposal, then
choose 「許可する」「拒否する」「該当なし」 or 「判断不明」 and confirm. The Agent
prints `APPLIED`, `DENIED`, `NOT_APPLICABLE`, or `UNDETERMINED`. Only approval
changes this app's own `maintenance_mode` Boolean in its local SQLite database.
「判断不明」 is a saved Human judgment; 「処理結果不明」 means the request's result
has not been confirmed and needs a status check.

Press Ctrl+C to stop the service. `demo` keeps keys, decisions, and recovery
receipts in `.asb-human` for the macOS/Linux example and `%AppData%\asb-human`
on Windows. Keep that directory and the login file private. Each new
`demo` run keeps the history and creates a new proposal. Use the recovery
instructions in the guide below if you need to resume an interrupted proposal.

## Preview limits

Use one trusted computer and OS user. This is not multi-user isolation, real
Human identity verification, hardware qualification, or a production service.
It does not change any external server or send messages to a delivery provider.

The bundle includes its source and dependency inventory, the ASB license and
linked dependency notices. Executables
are not platform-code-signed or notarized. If your OS blocks the executable,
use the source-build instructions instead of disabling its security checks.

See the [source, usage, and recovery guide](https://github.com/ToppyMicroServices/agents-secure-binding/blob/main/docs/local-human-approval.md).
It includes Go build instructions, troubleshooting, separate Agent commands,
and storage limits. Run the executable with `--help` for available commands.
