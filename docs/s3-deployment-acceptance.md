# Accepting a Linux S3 deployment

No organization host is currently qualified. Copy
[acceptance.example.json](../packaging/s3/acceptance.example.json) into the
operator's protected evidence store for the selected target. Keep `status` as
`not_run` until checks begin, then `in_progress`; use `accepted` only after the
responsible operator reviews passing results for every required check. A blank
or `not_run` field is not a pass. This is a manual acceptance record, not an
automatic certification tool.

Record the signed archive and installed binary hashes, actual OS/architecture,
systemd and AWS CLI versions, filesystem/mounts, storage durability contract,
token projector unit and backup destination. Use opaque references for internal
hosts and identity configuration; do not put tokens, private keys or object
contents into this record. Assign named owners for renewal, capacity alarms,
backups, and uncertain outcomes.

Use the [operations runbook](least-privilege-s3-product.md) and a dedicated,
explicitly authorized fixture on the target. Schedule disruptive drills in an
approved maintenance window. Each check needs a timestamp, installed binary hash
and a protected evidence reference:

| Check | Passing observation |
|---|---|
| Actual boot | Projector and reader start; a fresh authorized mTLS/ASB read completes |
| Expiry and renewal | Expired identity is rejected; atomic token replacement allows a new authorized read in the same process |
| Maintenance | Admission stops, accepted work drains within the recorded budget, and the unit stops |
| Emergency fencing | The complete service cgroup stops and remains stopped until intentional restart |
| Backup | A sealed snapshot and protected checksum reach the selected off-host destination and verify there |
| Restore | The old authority is fenced; a new-directory restore changes namespace, rejects old authority and accepts a newly authorized operation |
| Retained history | Receipts and `UNKNOWN` states remain; uncertain operation IDs are never redispatched |
| Observation and alerts | Chosen workload and duration stay within recorded budgets; renewal/capacity alert delivery reaches the responsible operator |

Choose the duration and resource thresholds from expected request rates, retained
history and response time. Record memory, descriptors, task/process counts,
journal/WAL growth, disk headroom, backup time and rejected/timed-out requests.
The GitHub reference tests and historical 45-minute run cannot fill these target
fields. There is no fixed observation duration that proves indefinite leak
absence.

Physical power-loss evidence is required only if that specific guarantee is
claimed for this host/storage. Otherwise leave `physical_power_loss_claim`
false and state the durable-storage assumptions. A process kill is not a power
cut. Protect the completed record, evidence hashes and operator approval together;
keep any OpenPGP signature detached from the final immutable record.
