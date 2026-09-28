# Linux S3 reader operations

`asb-s3` assembles the finite optimizer, ASB v2 mTLS protocol, OIDC STS source,
and SQLite execution journal into a Linux service. It performs one authorized,
conditional, ranged S3 GetObject and returns a receipt digest. It does not return
object contents. It supports one active policy authority on one Linux host with
local durable storage. General IAM policy optimization, multi-host failover and
S3 download delivery are outside this product profile.

The product remains **preview**. Before deployment, run its AWS qualification
and recovery drill in the target environment. Ordinary CI proves local
conformance; it does not certify storage hardware under power loss or an
organization's OIDC issuer. The
[AWS adapter specification](least-privilege-aws.md) lists supported resources,
ETags, session-policy constraints and the finite-model guarantee.

## Provision a Linux host

Build on Linux using the repository's Go version:

```sh
GOWORK=off go build -trimpath -o asb-s3 ./cmd/asb-s3
sudo install -m 0755 asb-s3 /usr/local/bin/asb-s3
sudo useradd --system --home-dir /var/lib/asb-s3 --shell /usr/sbin/nologin asb-s3
sudo install -d -o asb-s3 -g asb-s3 -m 0700 /var/lib/asb-s3 /etc/asb-s3
sudo -u asb-s3 /usr/local/bin/asb-s3 init-store --directory /var/lib/asb-s3/journal
```

Use the existing account if it has already been provisioned. `init-store` requires
a new directory; it cannot reset existing state. Save its returned `namespace`
in the configuration. Install a trusted AWS CLI v2 at an explicit absolute path.
The service inherits no shell AWS configuration or credential discovery.

Fill [config.example.json](../packaging/s3/config.example.json) and install it as
`/etc/asb-s3/config.json`. All configuration, profile, mandate, certificate and
key files must be regular, owner-only files readable by `asb-s3` (typically
0600). Protect their parent directories and ACLs. The example contains invalid
placeholders; it is not a runnable credential bundle.

The capability signing key is an Ed25519 PKCS#8 PEM private key. `grant_keys`
and `actor_keys` contain base64-encoded raw 32-byte Ed25519 public keys under
distinct key IDs; grant and actor keys must differ. Keep actor and grant private
keys with their respective authorities, outside this service. The mTLS server
certificate must identify the hostname clients verify. The client CA signs
only the intended client identities; TLS 1.3 and a verified client certificate
are required. mTLS alone does not authorize an action: every operation still
needs a fresh ASB proof and an exact current mandate.

Choose a loopback or private LAN/VPC IP for `listen`. Wildcard and public listen
addresses are rejected. Preserve direct TLS between the agent and this service;
a TLS-terminating proxy cannot supply its channel binding. Limit network access
to the intended clients with host/VPC controls.

```sh
sudo install -m 0644 packaging/s3/asb-s3.service /etc/systemd/system/asb-s3.service
sudo install -d -m 0755 /etc/systemd/journald@asb-s3.conf.d
sudo install -m 0644 packaging/s3/journald-asb-s3.conf /etc/systemd/journald@asb-s3.conf.d/retention.conf
sudo systemctl daemon-reload
# Production hosts that must return after boot:
sudo systemctl enable --now asb-s3
sudo systemctl is-enabled asb-s3
sudo systemctl status asb-s3
# For a deliberately temporary trial, use start instead of enable --now.
```

The unit requires systemd 245 or later for its isolated journal namespace. It uses the dedicated account, a private temporary directory and a writable
state directory, with no Linux capabilities. Startup loads the complete policy
bundle and durably records removed mandates before admitting traffic. An
exclusive authority lock prevents a second service from using another policy
bundle against the same journal. Keep the journal on local storage that honors
fsync and SQLite locking; network filesystems and copied concurrent instances
are unsupported.

Before enabling the reader, configure the site's token projection service to
start at boot and produce a fresh owner-only token. Add a drop-in with `Requires=`
and `After=` naming that **actual** projector unit; no universal issuer-specific
unit name is assumed. Ordering alone is not readiness: the projector must report
ready only after atomically publishing a token, and must continue renewing it.
A listener accepting TLS is not proof of identity readiness. After a real boot,
check both enabled/active states and a newly authorized mTLS/ASB read. Preserve
old operation IDs. Test expired-token denial followed by renewal and a separately
authorized new operation. A syntax check or service restart is not a boot test.

## Maintenance and emergency stop

`SIGTERM`/`SIGINT` stop admission and drain already accepted handlers for up to
45 seconds. The runtime context is independent of the maintenance signal;
ASB proof, certificate, capability and the adapter's 30-second deadline still
expire normally. `KillMode=mixed` sends the initial systemd stop signal only to
the main process so the STS child can finish. If draining times out, the service
cancels active work and closes connections. It retains its authority lock until
the handlers return. At `TimeoutStopSec=60` the supervisor sends a final cgroup
SIGKILL if needed. This bounds the kill request, not completion of uninterruptible
kernel I/O: a task in that state can retain its locks until the kernel returns.
Direct unsupervised execution has no external kill deadline. Storage/host failure
still requires the deployment's fencing and recovery procedure.

For immediate emergency fencing, first submit a manual stop with
`systemctl stop --no-block asb-s3`, then use
`systemctl kill --kill-whom=all --signal=SIGKILL asb-s3` and verify the unit is
inactive. The pending manual stop prevents the failure restart policy from
reactivating it. If it must stay off across a host reboot, disable its automatic
start as well. Deliberately start (and, if needed, re-enable) the reviewed
configuration only after replacing revoked trust/configuration. A remote S3 request already sent cannot be undone.
Record any `RUNNING`/`UNKNOWN` outcomes; do not retry those operation IDs.

The listener admits at most **64 TCP connections before TLS**, independently of
the **8 active HTTP handlers**. Excess connections wait in the kernel listen
queue; no application TLS/goroutine is allocated to them. Clients need bounded
connect/request deadlines and capped exponential backoff with jitter, starting
at one second and capped at 30 seconds. Retry authorization/challenge exchanges
with fresh proofs; never automatically redispatch an uncertain operation.
HTTP header/read/write/idle limits are 5/10/40/30 seconds. Host memory/task limits
must be chosen from the deployment's measured workload; they are not substitutes
for admission limits.

## Authentication and rotation

The product accepts only an explicit `web_identity_token_file`. A trusted workload
identity issuer must project an owner-only token file and replace it atomically
before expiry. The executor reopens it for each STS call, so token renewal does
not need a service restart. Missing, malformed, expired or untrusted identity
fails without falling back to static credentials, SSO, environment variables or
instance metadata. AWS validates the token's issuer, audience, subject and expiry
against the role trust policy. This service does not enroll an issuer or refresh
a token by itself.

AWS IAM allows five minutes beyond the token's `exp` for clock skew. The exact
JWT expiry instant is therefore not an immediate AWS revocation boundary. The
live expiry gate waits six minutes beyond `exp` before requiring AWS rejection.
See [AWS OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html).

On Linux, request cancellation kills the CLI's process group. The direct child
also receives a parent-death signal. The supported service still requires its
systemd cgroup: a deliberately detached descendant and private token files after
SIGKILL need that outer lifecycle. Operator-installed wrappers must not detach
work. `PrivateTmp` removes the service's temporary credential copies on unit
stop; unsupervised process SIGKILL does not provide that cleanup.

The adapter calls `AssumeRoleWithWebIdentity` with the exact configured role,
the verified explicit-deny session policy, and a 900-second duration. It confines
the projected token to a private temporary file rather than a process argument.
It keeps returned credentials inside the adapter. See
[AWS WebIdentity STS](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html).

For GitHub qualification, use environment `aws-s3-live` and audience
`sts.amazonaws.com`. Configure the AWS role to trust only that repository and
environment's exact OIDC subject, and restrict environment deployment refs to
reviewed code. Check the actual subject format if immutable/custom subjects are
enabled. No wildcard repository trust is needed. The workflow requests the OIDC
token directly; it does not install ambient AWS credentials. See
[GitHub's AWS OIDC guide](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

Read `GET /repos/{owner}/{repo}/actions/oidc/customization/sub` before preparing
trust. With the default template and `use_immutable_subject: true`, append
`:environment:aws-s3-live` to the returned `sub_claim_prefix`; the prefix contains
both owner and repository IDs. A name-only subject will not match that format.
Keep custom-template subjects aligned with their actual configured claims.

To rotate server TLS, client trust, actor/grant keys or capability signing keys,
stop the service, atomically install the reviewed complete configuration, and
restart. There is no hot reload. Restart drops outstanding TLS challenges; agents
must acquire fresh ones. Keep old mandate IDs and the journal: signing-key
rotation is not permission to repeat an execution. Replacing the client CA or
grant/actor keys removes trust on restart. Issue new certificates before expiry
and test a real handshake after rotation. No certificate issuance service is
included.

## Mandates and agent interaction

`profile_file` holds the trusted AWS specification. `mandates_file` is a JSON
array of `leastprivilege.Mandate`. An empty array admits no execution. Use the
Go API to derive the bindings; do not hand-code its canonical digest format:

1. Compile the exact profile with `awsiam.Compile` and obtain `Profile.Digest()`.
2. Marshal `awsiam.Arguments` with that digest, owner, ETag and byte range. Preserve
   those bytes in `leastprivilege.Action{Operation: awsiam.Operation, Resource: ARN,
   Arguments: bytes}`; JSON encodes `Action.Arguments` as base64.
3. Set `ActionDigest` with `leastprivilege.DigestAction` and `ProblemDigest` with
   `leastprivilege.DigestProblem(profile.Problem())`. Bind the exact actor, task,
   policy reference, validity window and capability TTL (1–3600 seconds).
4. Prefix mandate and operation IDs with the journal's `namespace + "/"` and
   assign a new suffix for each authorized execution.

`allow_automatic` defaults to false. Set it to true only in a mandate that the
trusted operator has authorized for automatic execution. Finding a minimum
does not make an otherwise unauthorized action permissible. Clients use the
existing [ASB HTTP protocol](least-privilege-execution.md#http-entry-point):
`/challenge`, `/authorize` with a candidate from `leastprivilege.Solve`, then a
fresh `/challenge` and `/execute` with the signed capability and new proof on
the same TLS connection. There is no raw execution or remote policy-install API.

Install policy changes while the service is stopped and restart with the full
active bundle. At most 4096 mandates can be active. Omitted IDs become permanently
revoked in SQLite; reintroducing a revoked or modified ID fails startup, even
after a process restart. New authority requires a new ID. Completed IDs remain
consumed after they leave the active bundle. A profile or action change therefore
uses new mandates. Do not replace the database to undo a policy change.

## Long-term retention and backup

SQLite uses WAL with FULL synchronization and indexed admission records. It has
no 10,000-operation snapshot limit. All execution identities, linked mandate uses
and revocations remain retained. Only expired proof nonces are pruned during
later admissions; a persisted time watermark rejects rollback across pruning.
The journal contains bindings, deadlines, states and evidence digests, not S3
contents, action argument bytes or credential material. Retain the exact original
requests separately in the application's protected audit record.

```sh
# Frequent lightweight monitoring; no history scan:
sudo -u asb-s3 asb-s3 health --directory /var/lib/asb-s3/journal
# Occasional snapshot counts (five-second read budget):
sudo -u asb-s3 asb-s3 status --directory /var/lib/asb-s3/journal
# Scheduled full integrity scan, preferably off peak:
sudo -u asb-s3 asb-s3 check --directory /var/lib/asb-s3/journal
sudo install -d -o asb-s3 -g asb-s3 -m 0700 /var/lib/asb-s3/backups
sudo -u asb-s3 sh -c 'umask 077; asb-s3 backup \
  --directory /var/lib/asb-s3/journal \
  --output /var/lib/asb-s3/backups/snapshot-001.sqlite \
  > /var/lib/asb-s3/backups/snapshot-001.json'
```

Choose a new output name each time. Backup works while the service is running:
SQLite produces a consistent snapshot including committed WAL data, then the
command seals and fsyncs it before publishing. A sealed snapshot cannot be
opened as an execution journal. Do not copy only the live `journal.sqlite` file.
The JSON contains the snapshot SHA-256 and namespace. Keep it and the snapshot
in access-controlled off-host backup storage; the hash detects corruption, not
malicious replacement. The product's AWS role does not gain backup write access.

Backup and cleanup share an exclusive `.asb-s3-backup.lock` in the destination
directory. Backup automatically recovers reserved temporary files left by a
previous interrupted run. Stop any **older** backup binary that predates this
lock before upgrading or using `cleanup-backups --directory <backup-directory>`.
The cleanup command only processes private `.asb-s3-backup-work-<digits>`
directories with the exact durable ownership marker and expected regular files.
It refuses a live backup lock, unexpected contents or symlink/ownership, and
preserves every published snapshot. Legacy flat temporary filenames and unmarked
directories are left untouched: inspect those with the producing process stopped,
verify any published snapshot/manifest first, and remove only artifacts that the
operator has positively identified as incomplete work. Do not infer garbage from
a filename. Do not use the reserved prefix for outputs or remove the lock file.
A hard-link alias left after publication is counted separately from allocated
payload bytes reclaimed; marker/directory overhead is excluded from that count.

Administrative commands have a five-minute default deadline, configurable with
`--timeout` up to one hour. Copy/hash loops check cancellation every 64 KiB.
For an outer stop bound use a supervisor, or `timeout --signal=TERM --kill-after=10s
300s asb-s3 ...` with the appropriate full command. Context cancellation cannot
interrupt an I/O syscall stuck in the kernel. An interrupted restore keeps its
pending marker and is not executable; preserve it for inspection and restore
into a new directory. A backup publication can precede loss of its JSON response:
inspect the snapshot instead of overwriting it. No rollback of a published file
or removal of permanent execution history is performed.

Choose a backup schedule from the acceptable loss of audit history. Choose
off-host retention from audit obligations and recovery needs; the service does
not silently delete historical identities or snapshots. Monitor the reported
`bytes`, operation counts, uncertain count, available filesystem space and backup
job failures. Provision room for the database, WAL and a complete temporary
snapshot. Disk-full or I/O errors deny new admission; they never clear the journal.
There is no unlimited-storage claim or unattended retention reset.

## Restore and uncertainty

Stop and fence the old authority before restoring, including any copied VM or
disk. Do not start an old and a restored authority simultaneously.

```sh
sudo systemctl stop asb-s3
sudo -u asb-s3 asb-s3 restore \
  --input /var/lib/asb-s3/backups/snapshot-001.sqlite \
  --sha256 '<sha256 from the protected manifest>' \
  --directory /var/lib/asb-s3/restored-001
```

Restore requires a new directory, a sealed backup and the exact checksum. A
pending marker blocks opening an incomplete restore. Successful restore rotates
the namespace before admission is possible. Update both `store_directory` and
`namespace` in configuration, and install only newly authorized mandates with
that new namespace. Old operation and mandate IDs cannot execute, including IDs
missing from the snapshot. Changing a directory or signing key alone does not
establish this boundary. Raw disk rollback and host-administrator tampering are
outside it.

For a known operation, inspect the retained record without redispatching it:

```sh
sudo -u asb-s3 asb-s3 inspect --directory /var/lib/asb-s3/restored-001 \
  --operation '<original namespace/operation>' \
  --request-digest 'sha256:<original request digest>'
```

`RUNNING` after a crash and `UNKNOWN` mean the read may have happened. S3 GET has
no operation ID that can prove that original event; another GET does not resolve
it. The product provides no force-retry or synthetic-success command. A record
missing from a backup is also not proof of nonexecution. Preserve that uncertainty
in the audit record before deciding whether a separately authorized new read is
appropriate. A restored backup does not recover lost audit outcomes.

Run a recovery drill on a separate Linux journal before production: verify the
snapshot checksum, changed namespace, retained records, denial of old IDs, and
a newly approved read. Never use a drill to reactivate the retired authority.

## Operator diagnostics and state classification

The service writes bounded JSON events to stderr: UTC time, fixed stage/reason,
and a truncated SHA-256 correlation of the operation ID where available.
`identity`, `sts`, `s3`, and `journal` distinguish token/source acquisition, STS,
S3 response and durable persistence failures. HTTP errors remain generic. Raw
provider errors, tokens, keys, object contents and request arguments are excluded.
Output is limited to 60 events per 30 seconds and 64 queued events; subsequent
emitted events report suppressed counts. A blocked sink cannot block an
execution; the final process supervisor also bounds shutdown of that sink.
The unit adds journald rate limits and a separate `asb-s3` journal namespace.
The supplied configuration sets a 64 MiB disk-use target, 16 MiB runtime-use
target, seven-day retention and 128 MiB free-space reserve. Journald rotates files,
so allow for its active file and filesystem overhead; these are rotation targets,
not a byte-exact disk quota. Inspect with `journalctl --namespace=asb-s3 -u asb-s3`
and `journalctl --namespace=asb-s3 --disk-usage`. Adjust this isolated namespace's
budget to the deployment's requirements, restart `systemd-journald@asb-s3` after
changes, and ship required audit evidence through a protected channel.
These lossy operational events do not replace the durable execution journal.

**Decision QD-01:** retain `UNKNOWN` for all adapter failures, including token or
STS failures before S3 dispatch. Durable authority has already been consumed at
that boundary, and a diagnostic label is not proof permitting replay. Diagnosis
now distinguishes those stages without changing the state model. An operator
may authorize a new read with new IDs after reviewing the old uncertain record;
no automatic retry, forced `FAILED`, or synthetic success is introduced. A future
no-dispatch result would need a typed adapter contract and separate proof/tests
for cancellation races and result-persistence failure. Current evidence does not
require that change.

## Qualification evidence

For real OIDC expiry and recovery in the installed systemd unit, set workflow
input `systemd_identity=true` with `operations_minutes=0` and the existing
`read-explicit-fixture` confirmation. Run this in a separate disposable job from
the operations lab. It installs the checked-in unit under a fresh dedicated
user, performs an authorized read, and lets that same GitHub token expire
naturally. AWS must return a recognized expiry diagnostic. The trusted runner
then atomically projects a new token; the same service process must preserve
the uncertain operation and complete a separately authorized read. Evidence is
written only after all assertions pass, with the tested binary hash. The runner
removes its private files and service on exit; it does not change AWS resources.
The runner supplies this lab's projector. This does not qualify a site's
projector startup, issuer or physical reboot. See the
[release qualification record](s3-release-qualification.md) for current results.

For a bounded operational run, also set workflow input `operations_minutes` to
`15` or `45`; its default `0` leaves this gate off. The existing explicit AWS
confirmation and private fixture remain required. The runner creates a dedicated
`asb-s3` user and executes the same qualified binary with no new privileges and
no effective Linux capabilities. This uses a subprocess, not the systemd unit.

The client reads the approved object every 30 seconds while the trusted runner
atomically refreshes its projected OIDC token every minute. Three times, after a
confirmed result, it sends SIGKILL to the idle service and verifies that restart
returns the exact receipt with AWS acquisition disabled. It retains the oldest
receipt, backs up the live journal, stops the old authority, and checks namespace
rotation, old-authority rejection and a new read after restore. A 15-minute run
performs 32 reads through this gate; a 45-minute run performs 92. The earlier
adapter/product gates also run against the same fixture.

`operations-result.json` records the actual elapsed time, read/restart counts,
observed token changes, sampled resident memory/descriptors and journal size.
It is emitted only after the test passes, alongside the source and binary hash.
These samples do not establish freedom from memory leaks. This bounded lab
does not qualify long-term retention, interruption during an AWS effect,
physical power loss, systemd confinement or an organization's target host.

`ASB S3 Linux` builds the actual binary, runs race-enabled tests and vet, exercises
backup/restore commands, verifies the systemd unit and runs lint on Ubuntu. Tests
cover concurrent admission, process interruption, namespace rotation, more than
10,000 identities, persisted mandate revocation, OIDC source isolation and mTLS.
Its artifact includes the commit, Linux identification, JSON test results and
binary checksum. This is bounded automated coverage, not a long-duration soak.

The [2026-09-25 Linux conformance run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36086892025)
passed at source commit `80f1e3adeaf822fd1099bc5244537b9742749a3f`: 278 test cases
including subtests, vet, lint, live-gate compilation and binary recovery commands.
The downloaded binary matched the artifact's SHA-256; systemd verification had
no diagnostics. This recorded result does not include a real AWS invocation.

The [2026-09-26 OIDC/S3 qualification run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36246640700)
passed at `ecba88eeb7407fe9d6aa504e0d3f52e40c77a212`: GitHub OIDC authentication,
the permitted adapter GET and outside-object HTTP 403, plus 296 Linux test cases
including subtests. That run predates the product-process recovery gate below.

The [2026-09-27 product-process run](https://github.com/ToppyMicroServices/agents-secure-binding/actions/runs/36286602920)
passed at `6c73e3bf156618a625ae1010f444d9a731734ec7`: the actual service completed
an mTLS/ASB read, recovered its receipt after restart with AWS acquisition
disabled, restored a sealed backup, rejected the old authority, and completed
a newly authorized AWS read. The downloaded Linux conformance binary and the
AWS-executed binary had the same SHA-256. This was a loopback lab with disposable
identities; target deployment and long-duration qualification remain open.

For real AWS, fill
[live-fixture.example.json](../packaging/s3/live-fixture.example.json) using two
existing objects you are authorized to test, in the same bucket. Supply the
allowed object's actual ETag, expected account and valid byte range. Store this
JSON as environment secret `ASB_AWS_LIVE_FIXTURE_JSON` in `aws-s3-live`. The
workflow supplies CLI/token paths; leave `credentials_file` empty. Configure the
OIDC role trust before running. No account, bucket, object or IAM permission is
created by this gate.

Manually dispatch `ASB S3 Linux` on the reviewed branch with
`aws_confirmation=read-explicit-fixture`. After Linux conformance succeeds, its
AWS job uses environment `aws-s3-live` directly and checks that the private
fixture is available before building the gate or requesting an OIDC token.
Push and pull-request runs never invoke this live job.
It must show an allowed ranged GET and
an AWS 403 for the explicitly supplied excluded object. A skipped, failed or
unconfigured run is not qualification. The evidence contains the source commit,
AWS CLI version, receipt digest and result, without the fixture or tokens. The
adapter gate validates real STS/S3 behavior. A second opt-in gate starts the
actual Linux `asb-s3` binary with a private, disposable loopback PKI and exact
operator mandate. Its client verifies the TLS exporter, signs fresh ASB proofs,
and reads the supplied object through the service. After a process restart with
AWS acquisition disabled, the same completed operation must return its exact
stored receipt. The drill backs up the running journal, stops and reaps the old
process, restores into a new namespace, and checks the retained record. The
restored service must reject the old operation and accept a newly authorized
read with real AWS credentials. Its separate `product-result.json` is written
only after that gate passes and includes the executed binary's checksum. The
AWS job uses the binary from the same run's Linux conformance artifact, after
checking its source commit and checksum; it does not rebuild the product.

These are two bounded qualification gates. The product drill uses a Linux
runner and disposable identities; it does not certify an organization's deployed
identity authority, target storage under power loss, or long-duration operation.

An outside-object 403 alone does not identify which AWS policy caused denial.
Keep the fixture's reviewed role and resource-policy configuration with the
private qualification record. Do not interpret this finite test as exhaustive
coverage of IAM, SCPs, resource policies or every AWS action.
