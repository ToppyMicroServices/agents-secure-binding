# Linux S3 reader operations

`asb-s3` assembles the finite optimizer, ASB v2 mTLS protocol, OIDC STS source,
and SQLite execution journal into a Linux service. It performs one authorized,
conditional, ranged S3 GetObject and returns a receipt digest. It does not return
object contents. It supports one active policy authority on one Linux host with
local durable storage. General IAM policy optimization, multi-host failover and
S3 download delivery are outside this product profile.

The deployment remains **preview until its AWS qualification and recovery drill
pass**. Ordinary CI proves local conformance; it does not certify an AWS account,
storage hardware under power loss, or an organization's OIDC issuer. The
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
sudo systemctl daemon-reload
sudo systemctl start asb-s3
sudo systemctl status asb-s3
```

The unit uses the dedicated account, a private temporary directory and a writable
state directory, with no Linux capabilities. Startup loads the complete policy
bundle and durably records removed mandates before admitting traffic. An
exclusive authority lock prevents a second service from using another policy
bundle against the same journal. Keep the journal on local storage that honors
fsync and SQLite locking; network filesystems and copied concurrent instances
are unsupported.

## Authentication and rotation

The product accepts only an explicit `web_identity_token_file`. A trusted workload
identity issuer must project an owner-only token file and replace it atomically
before expiry. The executor reopens it for each STS call, so token renewal does
not need a service restart. Missing, malformed, expired or untrusted identity
fails without falling back to static credentials, SSO, environment variables or
instance metadata. AWS validates the token's issuer, audience, subject and expiry
against the role trust policy. This service does not enroll an issuer or refresh
a token by itself.

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
sudo -u asb-s3 asb-s3 status --directory /var/lib/asb-s3/journal
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

## Qualification evidence

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
live gate validates the real STS/S3 adapter; separate Linux tests validate the
ASB service and journal composition. It does not yet exercise a deployed
organization's complete agent-to-service path.

An outside-object 403 alone does not identify which AWS policy caused denial.
Keep the fixture's reviewed role and resource-policy configuration with the
private qualification record. Do not interpret this finite test as exhaustive
coverage of IAM, SCPs, resource policies or every AWS action.
