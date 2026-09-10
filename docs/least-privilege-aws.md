# Bounded AWS S3 GetObject profile

`pkg/leastprivilege/awsiam` converts an operator-supplied set of exact S3 object
grants into a finite least-privilege problem. Its executor assumes a named role
with an explicit session-policy boundary, then performs one conditional, ranged
GetObject request. It returns a receipt digest, not object contents or temporary
credentials. This is a narrow adapter, not a full AWS IAM interpreter.

## Trusted specification

`Compile` accepts JSON with schema `asb.least-privilege.aws-s3/v1`:

```json
{
  "schema": "asb.least-privilege.aws-s3/v1",
  "role_arn": "arn:aws:iam::111122223333:role/asb-reader",
  "region": "eu-west-1",
  "credential_profile": "develop",
  "objects": [
    {
      "arn": "arn:aws:s3:::example-bucket/report.txt",
      "cost": 1,
      "owner_account": "111122223333"
    }
  ],
  "grants": [
    {
      "id": "reader",
      "policy": {
        "Version": "2012-10-17",
        "Statement": [{
          "Effect": "Allow",
          "Action": "s3:GetObject",
          "Resource": ["arn:aws:s3:::example-bucket/report.txt"]
        }]
      }
    }
  ],
  "required": ["arn:aws:s3:::example-bucket/report.txt"],
  "allowed": ["arn:aws:s3:::example-bucket/report.txt"],
  "max_response_bytes": 1024
}
```

Each object ARN is a permission atom with a positive operator-chosen cost. Each
policy is one selectable grant. Required and allowed sets must refer to catalog
objects. The compiler rejects duplicates, unknown references, unsupported JSON
fields (including case aliases), wildcard actions/resources, `Deny`, `Condition`,
`Principal`, `NotAction`, and `NotResource`. Input policies use scalar `Action`,
array `Statement`, and array `Resource`; the accepted action is exactly
`s3:GetObject`. Optional statement `Sid` is retained in the profile digest.

The standard `arn:aws` partition is supported. Object ARNs must fit the finite
model's 128-byte ID limit. Bucket names use lowercase alphanumeric characters
and hyphens, without consecutive hyphens or the `-s3alias` suffix; dots,
access-point aliases, directory buckets, and other S3 endpoint
profiles are outside this adapter. Keys use ASCII letters, digits, `-._~`, and
slash. Empty segments, `.` or `..` segments, trailing slash, percent escapes,
spaces, Unicode, and query/fragment syntax are refused. Nothing normalizes an
input key into another object's key.

`Profile.Digest()` binds the full decoded specification, including role, region,
credential-profile name, object owners/costs, grants, required/allowed sets and
response limit. Input order is retained; it is not a semantic-equivalence hash.
`Profile.Problem()` returns an owned copy for `Solve`, the mandate, and the ASB
service. Policies must come from the operator; the peer cannot install them.

## Bind and execute

The action operation is `s3:GetObject`; its resource is the exact object ARN.
Its JSON argument bytes contain:

```json
{
  "profile_digest": "sha256:<64 lowercase hex digits>",
  "expected_bucket_owner": "111122223333",
  "if_match": "\"0123456789abcdef0123456789abcdef\"",
  "range_start": 0,
  "range_end": 3
}
```

The mandate and fresh ASB proof bind these exact bytes. Expected owner must
match the trusted object catalog. The ETag must be a quoted 32-digit hex value,
optionally followed by a multipart suffix. A positive, explicit range is
mandatory and cannot exceed `max_response_bytes` (at most 1 MiB). The response
must be HTTP 206 with the same ETag and exactly the requested range/length.
ETag matching is an object precondition, not a cryptographic content-integrity
claim; the receipt also binds SHA-256 of the received bytes. Version IDs, SSE-C,
KMS decryption, and S3 Express sessions are unsupported. A version-specific read
can require a different IAM action. See the [GetObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).

Register the executor with the existing service:

```go
profile, err := awsiam.Compile(trustedSpecificationJSON)
// Handle err. Install profile.Problem() and the exact action in trusted policy.
executor, err := awsiam.NewExecutor(profile, awsiam.CLIConfig{
    Path: "/usr/local/bin/aws",
    CredentialsFile: "/absolute/operator/credentials",
    MaxEvaluations: 1 << leastprivilege.MaxGrants,
})
// Handle err. In asbbinding.Config:
executors := map[string]asbbinding.Executor{
    awsiam.Operation: executor.Execute,
}
```

The constructor accepts no network endpoint, proxy, HTTP client, or peer-provided
credential override. CLI and credential-file paths are local trusted
configuration; the credential file is read only when `Execute` runs. Only the
explicit named static-credential profile is copied into a private temporary
directory. Unknown credential fields, `credential_process`, role chaining,
SSO and metadata discovery are refused. Unrelated profiles stay out of the
child process. No ambient access keys, proxies, endpoint overrides, or AWS config
are inherited. Temporary files are removed after AssumeRole. Provider diagnostics
are discarded; stdout credentials are size-limited and kept inside the adapter.
Go-managed memory is not a secure-erasure boundary.

The trusted AWS CLI receives structured arguments for AssumeRole at the fixed
regional STS endpoint. It requests 900-second credentials, AWS's minimum session
duration, and supplies no managed session-policy ARNs. Credentials are never
returned or reused. Actual S3 dispatch requires the accepted ASB/capability
deadline and has an additional 30-second adapter deadline. The STS credential
expiration can outlive that local deadline, so the adapter's credential isolation
is part of the trusted boundary. See [AssumeRole limits and behavior](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

## Session-policy boundary

After independently verifying the solution, the adapter emits three statements:

1. Explicitly deny every action other than `s3:GetObject` on every resource.
2. Explicitly deny `s3:GetObject` on every resource outside the verified ARN set.
3. Allow `s3:GetObject` on the verified ARN set.

The compact policy must fit STS's 2,048-character limit; oversized selections
fail before credential acquisition. No truncation or broader fallback occurs.
The generated denies are intentional even though the input profile accepts only
Allow statements. AWS can grant permissions directly to a role session through a
resource policy, where an implicit session-policy deny is insufficient; an
applicable explicit deny takes precedence. See [AWS evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html).

The adapter signs its exact HTTPS GET with SigV4, including owner, ETag, range,
and session-token headers. It uses a fixed virtual-hosted regional S3 endpoint,
does not follow redirects, and disables HTTP connection reuse and HTTP/2 to
avoid automatic retries of an uncertain read. Its canonicalization is checked
against the [published AWS S3 signature vector](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html).
This prevents an application-level automatic redispatch; it does not guarantee
exactly-once network delivery.

This envelope bounds supported IAM permissions. It does not discover current
role policies, SCPs, resource policies or grant relationships. AWS still decides
whether the selected operation is available. ETag and byte-range constraints
are enforced by this executor and signed request, not modeled as separate IAM
permission atoms.

The policy is not a promise that no other AWS API can respond. For example,
[GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
can return caller identity without an Allow, even when explicitly denied. This
executor confines actual calls to its fixed STS/S3 flow and keeps the resulting
credentials private. Local policy-match tests do not imply a denial response
for permission-independent APIs.

## Verification and live gate

Local tests exercise the generated explicit denies against simulated direct
session grants, the published SigV4 vector, malformed profiles, exact request
bindings, credential-source isolation, response limits, redirect refusal and
redacted failures. A composition test wires the actual executor into
`asbbinding.Service` with real Ed25519 ASB proofs, current operator policy and the
durable journal. It checks successful execution, changed resource/arguments,
policy replacement/revocation, the human gate, proof replay and exact result
readback. Only the fake AWS CLI and private test transport replace AWS. No
production transport injection API is exposed.

A lost response remains `UNKNOWN`. S3 GetObject has no downstream idempotency
record that proves whether the original read happened. A later GET cannot
reconcile that event, and the service refuses redispatch. Authoritative operator
evidence is required for reconciliation; this adapter supplies no blind retry
or synthetic success callback.

The live gate is excluded from ordinary tests. It requires an explicit fixture
with existing authorized resources and performs no resource creation:

```sh
ASB_AWS_LIVE_CONFIRM=read-explicit-fixture \
ASB_AWS_LIVE_FIXTURE=/absolute/operator/live-fixture.json \
GOFLAGS=-p=2 GOWORK=off go test -tags awsiam_live \
  ./pkg/leastprivilege/awsiam -run '^TestLiveS3Profile$' -count=1 -v
```

The fixture fields are `specification` (the full JSON above), `resource` (selected
object ARN), `denied_resource` (an explicitly authorized test object outside the
selected set in the same bucket), `arguments` (the exact read arguments),
`cli_path`, and `credentials_file` (both absolute). An empty argument
`profile_digest` is filled from the trusted fixture during setup. The gate
requires an allowed ranged read and an AWS 403 for the outside object. It logs
only the receipt digest. A denied result alone does not identify which AWS
policy caused the denial.

Live AWS conformance remains unverified until this gate runs against an
operator-supplied role, profile, bucket and object fixture. Local tests establish
the adapter's bounded behavior; they do not establish a deployed AWS permission
boundary or cloud-policy completeness.
