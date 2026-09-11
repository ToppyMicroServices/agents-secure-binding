# Human Coordination integration status

This record reconciles `asb-ljs.1` through `asb-ljs.16` with the implementation
prepared for main integration on 10 September 2026. It separates completed
preview behavior from production qualification. A passing local gate does not
by itself establish a merged revision, published release, or deployed service.

## Source revisions

- Coordination implementation and its tests:
  [`19e6382`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/19e6382cfe0278e37d254c8de3d54c4f4a904de1).
- Root and Cocos gRPC repair:
  [`4a05a2d`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/4a05a2d619a53139d3ff9c5c2d601b8e0bae29eb).
- Local approval application:
  [`26bf12d`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/26bf12d874bd77b66e2170eeee8207540806a6ac),
  with shell recovery fixes through
  [`8f1fa52`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/8f1fa52c9b66db491f7d636fd0a9d68d5c772a56).
- Native artifact execution workflow:
  [`ca96d8e`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/ca96d8ea0af741bac2da446033ec810787b30e4e).
- Integration base: main
  [`a794704`](https://github.com/ToppyMicroServices/agents-secure-binding/commit/a794704).

The earlier native artifact checks remain evidence for their exact revisions
and platforms; see [local approval validation](local-human-approval-validation.md).
This integration does not repeat those remote executions by inference.

## Acceptance mapping

Unless stated otherwise, the implementation and named tests below first appear
in `19e6382`. Test names identify exact checks inside the linked package; the
full package suites run under the race detector in the integration gate.

| Issue | Implementation and checked acceptance evidence | Boundary |
| --- | --- | --- |
| `asb-ljs.1` | [Task–Action acceptance](../pkg/taskcoord/actionbinding/acceptance_test.go): `TestServiceAcceptRejectsMissingAndTamperedAuthentication`, `TestMemoryStoreCommitAcceptanceValidatesBeforeDeduplication`; [boundary registry](../testdata/human-coordination-conformance-v1.json). | Initial Action acceptance remains a trusted internal API. No public endpoint accepts caller-built verifier projections. |
| `asb-ljs.2` | [Revocation tests](../pkg/humanrelay/dispatch_revocation_test.go): `TestDispatchCancelsWithoutProviderCallAfterReachabilityWithdrawal`, `TestDispatchGateBlocksRevocationThroughProviderAcknowledgement`. | Consent authorizes scoped contact metadata; exact message approval is a separate, unimplemented capability. |
| `asb-ljs.3` | [Relay tests](../pkg/humanrelay/service_test.go): `TestRelaySupportsBoundaryIntentIDs`, `TestWorkerRejectsBrokerClockRollback`; `TestRelayEventIDGolden`, `TestStorePreservesFirstProviderAcknowledgementTime`, `TestWorkerRejectsMismatchedProviderAcknowledgement`. | Provider acknowledgement does not prove Human receipt or approval. |
| `asb-ljs.4` | [Exact transcript](action-transcript-v1.md), [four golden vectors](../testdata/action-transcript-v1-vectors.json), Go golden and ambiguity tests in `pkg/actionlifecycle` and `pkg/taskcoord/actionbinding`. This integration adds [independent Python recomputation](../scripts/verify-action-transcript-v1.py) to both Human gates. | Four deterministic cross-language vectors; no claim of an independent deployed implementation. |
| `asb-ljs.5` | [HTTP contract tests](../pkg/taskcoord/asbbinding/ingress_contract_test.go): success envelopes, route/method/media errors, `TestIngressStableFailureMatrix`, `TestIngressRedactsRandomAndCommitErrors`; response-schema tests. | Applies to the implemented direct TLS ingress. Relay has no public challenge/execute endpoint. |
| `asb-ljs.6` | [Bilingual registry](human-coordination-conformance-v1.md), machine-readable manifest and `TestHumanCoordinationConformanceManifestV1`. | Unimplemented production and reconciliation requirements remain labeled unavailable. |
| `asb-ljs.7` | `make mac-human-coordination-e2e` runs [the deterministic scenario](../examples/human-coordination-e2e); `mac-human-coordination-e2e` in [main CI](../.github/workflows/main.yaml) validates its report. | The report declares software-only, in-process execution with no live TLS, hardware, or provider. |
| `asb-ljs.8` | [Production qualification](human-coordination-production-v1.md) and [formal model map](../formal/HUMAN_COORDINATION_MAP.md) identify the remaining adapters and exercises. | **Incomplete.** Generic TaskCoord/Task–Action/relay transaction ownership, real multiprocess durability, live failover, backup/restore and provider reconciliation are not qualified. |
| `asb-ljs.9` | [Field semantics](human-coordination-field-semantics-v1.md), schema boundary cases, `TestCanonicalValidationUsesUTF8ByteLimits`, and `FuzzHumanIngressStrictJSONDifferential`. | Standard JSON Schema counts code points; combined semantic validation enforces the documented 256 UTF-8 octet limit. |
| `asb-ljs.10` | The manifest classifies all nine E2E boundaries; the E2E checks profile IDs and evidence sources. [README](../README.md) and package documentation identify trusted internal projections. | Only the Human request and Agent relay profiles are external ASB profiles. Other listed operations stay internal. |
| `asb-ljs.11` | [Clock tests](../pkg/taskcoord/reachability_clock_test.go): nil-clock rejection, typed-nil resolver rejection and exclusive expiry; E2E uses one fixed clock. | Default construction still uses `time.Now`. |
| `asb-ljs.12` | [Acceptance retry tests](../pkg/taskcoord/actionbinding/acceptance_test.go): exact-attempt canonical recovery after expiry, fresh expired-request rejection, cross-proof reconciliation and conflict checks; concurrent retries in `cardinality_test.go`. | Verified for the in-memory reference Store transaction. Restart durability for generic Task–Action acceptance is still part of `asb-ljs.8`; the local SQLite app is a separate application. |
| `asb-ljs.13` | `TestHumanAssuranceVocabulary`, `TestAssuranceProvenanceAcceptsOnlyImplementedProfilePair`, detached audit/delegation provenance and schema spoofing tests. | `gateway-asserted-for-human` is derived from the verified profile. It does not prove presence, UI confirmation, legal consent or a Human-held key. |
| `asb-ljs.14` | [ProVerif queries](../formal/proverif/human_ingress_acceptance.pv), [bounded TLA+ models](../formal/tla/HUMAN_RESULTS.md), reproducible runners and [model-to-Go mapping](../formal/HUMAN_COORDINATION_MAP.md). | Symbolic correspondence and finite safety checks; no machine-checked refinement to a production Store. |
| `asb-ljs.15` | Dedicated `human-coordination-red-team` CI job; [documented misuse/fault/privacy coverage](human-coordination-red-team-tests.md), TLS multiplexing/resumption tests and bounded parser fuzz seeds. | Live telemetry, public outbox projection and provider qualification are not supplied by this gate. Repository ruleset enforcement of this status is a separate integration setting. |
| `asb-ljs.16` | [IETF review proposal](human-coordination-ietf-review.md), `TestHumanCoordinationIETFReviewTopics` and a fresh Datatracker read on 10 September 2026. | Repository review input only; no draft submission, WG adoption, IANA allocation or wire-format freeze. |

## gRPC dependency decision

For the PR #52 integration, both `GOWORK=off` module graphs selected
`google.golang.org/grpc v1.83.1`, and `go mod verify` passed in root and Cocos. The
[GHSA-vp52-pcj8-j9qc advisory](https://github.com/grpc/grpc-go/security/advisories/GHSA-vp52-pcj8-j9qc)
lists versions through 1.83.0 as affected and 1.83.1 as patched. The vulnerable
boundary is the HTTP/2 receive queue: many tiny DATA frames can inflate per-frame
allocation overhead. The selected release enables buffer compaction by default.

The repository does not set the escape-hatch environment variable that disables
compaction. Its deployed environment is outside this check. The selected
module's `Test/RecvBufferCompaction` tests passed, including small-fragment,
large-buffer and explicitly-disabled controls. Existing gRPC client/server
tests check normal API behavior. An exhaustion attack against a deployment was
not performed. No further dependency edit was necessary on this branch.

### Follow-up on 11 September 2026

Both module graphs now select `google.golang.org/grpc v1.83.2` for
[GHSA-2v4p-qf9q-27wj](https://github.com/grpc/grpc-go/security/advisories/GHSA-2v4p-qf9q-27wj).
This advisory covers an xDS routing panic when a request lacks both
`:authority` and `Host`. No repository source calls `xds.NewGRPCServer`;
the affected dependency version was confirmed, while an exploitable deployment
path was not demonstrated.

The [upstream patch release](https://github.com/grpc/grpc-go/releases/tag/v1.83.2)
rejects that request in the HTTP/2 transport and guards the xDS interceptor.
Its missing-header transport and xDS regression tests passed locally with the
race detector, alongside Host normalization, authority precedence, and receive
buffer compaction controls. The same xDS test reproduced the panic in an
isolated 1.83.1 source copy. The update includes the release's required
`x/net` version and dependencies selected by Go. The integration checks below
remain the historical PR #52 results; they are not reassigned to this update.

## Integration checks

The integration used Go 1.26.6, `GOWORK=off`, `GOFLAGS=-p=2` and
`GOMAXPROCS=2`. The low parallelism controlled local build load; it did not change
the security assertions. The following checks passed on the combined working
tree, including this integration's transcript verifier:

- `go test -race -count=1 -timeout=15m` and `go vet` for `./internal/strictjson`,
  `./pkg/actionlifecycle`, `./pkg/humanrelay/...`, `./pkg/operationjournal`,
  `./pkg/taskcoord/...`, `./pkg/production`, `./schemas`,
  `./examples/human-coordination-e2e`, `./internal/humanapp`, `./cmd/asb-human`,
  `./pkg/clients/grpc`, `./internal/runtime/server/grpc`, and `./agent/api/grpc`.
  Sixteen packages passed tests; the runtime gRPC wrapper has no tests. The
  application and CLI suites took 62.690 and 59.886 seconds.
- In `integrations/cocos`, `go test -count=1 ./...` and `go vet ./...`.
- `go mod verify` and `go mod tidy -diff` independently in root and Cocos.
- `go test -count=1 -run '^Test/RecvBufferCompaction' google.golang.org/grpc/internal/transport`.
- `go run golang.org/x/vuln/cmd/govulncheck@latest -scan=package ./...` in both
  modules: no imported-package vulnerabilities. Eight root and three Cocos
  required-module findings remain; this is not a graph-wide zero finding claim.
- `make mac-human-coordination-e2e`: `success=true`, nine classified boundaries,
  and the software-only/non-production flags shown above.
- `go test -run '^$' -fuzz='^FuzzHumanIngressStrictJSONDifferential$' -fuzztime=10s ./pkg/taskcoord/asbbinding`:
  31,279 executions, no failure. This short pass is not a long fuzz campaign.
- `python3 scripts/verify-action-transcript-v1.py`: four exact byte/digest
  matches. Separate temporary mutations of an input, transcript and digest all
  returned failure. `node --test internal/humanapp/web_ui_test.mjs`: nine passes.
- `sh formal/proverif/run_human_ingress.sh`: all six queries true.
  `sh formal/tla/run_human.sh`: both bounded models passed; the exact tool hash
  and state counts are in [the TLA+ rerun record](../formal/tla/HUMAN_RESULTS.md).
- `actionlint` on the main, Security Red Team and Local Human Approval workflows,
  and `sh scripts/check-asb-core-boundary.sh`.

The first sandboxed TCP tests could not bind loopback sockets. They were
re-executed with local socket access; that final run passed. An unscoped
`actionlint` also reports the pre-existing `hal.yml` ShellCheck SC2251 advisory;
the three workflows above pass their scoped syntax checks.

The production profile remains unavailable. Closing a preview implementation
item must not close `asb-ljs.8` or imply a production claim. A main integration
record also does not close default-branch security alerts until the patched
dependency is actually present there.
