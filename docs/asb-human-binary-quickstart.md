# ASB local approval: binary quick start

This archive contains an experimental `asb-human` executable for the OS and
architecture named in the artifact. No Go installation, Node.js, Docker, LLM
account, or TEE hardware is needed to run it. Keep all extracted files in one
folder and open a terminal there.

Choose a successful **Local Human Approval** workflow run with a passing
**Run artifact** job for your OS and architecture. That job downloads the
archive, checks its binary checksum, and runs that executable's `self-test`
without rebuilding it. A successful **Compile** job alone is not an execution
test. The check uses a simulated Human reviewer, not a browser or TEE.

## macOS or Linux

Restore the executable bit, then run the unattended check:

```text
chmod +x asb-human
./asb-human self-test
```

To make a decision yourself in the browser:

```text
./asb-human demo --data-dir ./.asb-human
```

## Windows PowerShell

```text
.\asb-human.exe self-test
.\asb-human.exe demo --data-dir ./.asb-human
```

## What to expect

`self-test` prints progress, checks an approval and a decline over real
authenticated loopback connections, and verifies saved results after reopening
SQLite. It simulates the Human reviewer, uses its own temporary state, and
removes that state when it finishes. Success ends with:

```text
PASS: local approval self-test completed.
```

`demo` starts the service and a separate Agent process. Open the private login
link printed in the terminal on the same computer. Review the proposal, then
approve or decline and confirm. The Japanese UI shows 「適用済み」 for approval
or 「拒否済み」 for decline; the Agent prints `APPLIED` or `DENIED`. The only
possible effect is a change to this app's own `maintenance_mode` Boolean in
its local SQLite database.

Press Ctrl+C to stop the service. `demo` keeps keys, decisions, and recovery
receipts in `.asb-human`; protect that directory and the login link. Each new
`demo` run keeps the history and creates a new proposal. Use the recovery
instructions in the guide below if you need to resume an interrupted proposal.

## Preview limits

Use one trusted computer and OS user. This is not multi-user isolation, real
Human identity verification, hardware qualification, or a production service.
It does not change any external server or send messages to a delivery provider.

The artifact name identifies its source commit. `SHA256SUMS` records the binary
checksum, not a signature or proof of trust. These are short-lived CI artifacts,
not signed or notarized releases. If your OS blocks the executable, use the
source-build instructions instead of disabling its security checks.

See the [source, usage, and recovery guide](https://github.com/ToppyMicroServices/agents-secure-binding/blob/feat/human-coordination-product-v1/docs/local-human-approval.md).
It includes Go build instructions, troubleshooting, separate Agent commands,
and storage limits. Run the executable with `--help` for available commands.
