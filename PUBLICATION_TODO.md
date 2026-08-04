# Publication TODO

Release blockers and evidence limits for the public draft.

## Repository Identity

Resolved for public v0.5: the repository name, Go module path, imports,
protobuf `go_package` options, examples, and local documentation use
`github.com/thinksyncs/agents-secure-binding`.

## Recorded CI and Red-Team Status

Latest recorded signed implementation checkpoint (GitHub signature status:
verified):

| Commit | Workflow | Run | Result | Date |
| --- | --- | --- | --- | --- |
| `0fe710afd3e50848864f84b64cd45f9064c5a37d` | `CI` | `30875915840` | Success | 2026-08-04 UTC |
| `0fe710afd3e50848864f84b64cd45f9064c5a37d` | `Security Red Team` | `30875915843` | Success | 2026-08-04 UTC |
| `0fe710afd3e50848864f84b64cd45f9064c5a37d` | `Redis Sentinel Failover` | `30875915839` | Success | 2026-08-04 UTC |
| `9684c3d08785bad344cf32cdd812eefd892caccf` | `Proto Consistency` | `30782322014` | Success | 2026-08-03 UTC |

Local pre-publication gate after the README/module-path/runtime hardening work:

| Commit | Scope | Command | Result | Date |
| --- | --- | --- | --- | --- |
| `7c29c48451cea5aeedda42171d28b67e67712a92` plus staged changes | Security red-team gate | `GOTOOLCHAIN=go1.26.0+auto go test -v -race -count=1 ./pkg/agtp ./pkg/atls/identitypolicy ./pkg/clients` | Success | 2026-06-28 14:11 UTC |
| unsigned local worktree after Beads/product-readiness changes | Product-readiness gate | `GOCACHE=/private/tmp/asb-gocache make product-security-gate` | Success; `govulncheck` reported 0 called vulnerabilities | 2026-06-28 16:25 UTC |
| unsigned local worktree after 0-RTT, gateway-route, and appraisal-contract changes | Full Go test gate | `go test -count=1 ./...` | Success | 2026-06-30 08:34 UTC |
| unsigned local worktree after 0-RTT, gateway-route, and appraisal-contract changes | JWT/JWS fuzz gate | `go test -run '^$' -fuzz=FuzzVerifySessionIdentityJWTRejectsMalformedCompactTokens -fuzztime=60s ./pkg/agtp` | Success; 1,252,457 executions | 2026-06-30 08:34 UTC |

This checkpoint is not a formal proof or a broad deployment security claim. The
remote CI and Security Red Team run IDs above record the latest implementation
checkpoint. The product gate is scoped to the Direct-Agent core and reference
adapters. Inherited agent/manager runtime integration tests include VM, sudo,
loopback listener, and Python package-install paths and remain separate
integration coverage.

Hardware-backed attestation replay now has a manual `Hardware Attestation Red
Team` workflow for confidential self-hosted runners. It is not part of the
default GitHub-hosted CI profile, and no successful hardware workflow run is
recorded in this file yet.

## Dependency Alert Status

GitHub Dependabot reports no open alerts for the default branch. The 10 alerts
reported during the publication-prep push are fixed as of 2026-06-28 13:49 UTC.

Current dependency graph checks:

- `google.golang.org/grpc` resolves to `v1.82.1`;
- `github.com/go-jose/go-jose/v4` resolves to `v4.1.4`;
- `go.opentelemetry.io/otel/sdk` resolves to `v1.43.0`;
- `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` resolves to
  `v1.43.0`;
- `github.com/docker/docker` is not present in the current module graph.

## Runtime Plaintext Transport Classification

The remaining `insecure.NewCredentials()` and OTLP `WithInsecure()` uses are
classified as follows:

| Area | Classification | Guardrail |
| --- | --- | --- |
| Unix-socket service clients for log, attestation-service, and computation-runner | Accepted local IPC | Target is constructed as `unix://...`; no TCP fallback. |
| Legacy `pkg/atls` gRPC client path in `pkg/clients/grpc` | Accepted wrapper use | gRPC receives plaintext credentials only because the custom dialer supplies the already accepted package-wrapped TLS connection. |
| Standard gRPC client path in `pkg/clients/grpc` | Fail-closed for remote plaintext | Plaintext is accepted only for Unix socket, `localhost`, or loopback targets. Remote plaintext requires TLS or the accepted package-wrapped TLS path. |
| Agent CVM gRPC server | Fail-closed for public plaintext | Plaintext TCP listeners are accepted only on loopback. Unix sockets remain accepted. |
| Runtime gRPC server wrapper | Fail-closed for public plaintext | Listener without TLS is accepted only for `localhost` or loopback bind hosts. |
| CC attestation-agent clients | Fail-closed for remote plaintext | Plaintext TCP is accepted only on loopback. |
| OTLP/HTTP tracing exporter | Fail-closed for remote HTTP | `http://` is accepted only for `localhost` or loopback collectors. Remote collectors must use `https://`. |

## Experimental Adapter Boundary

`pkg/agtp` and its subpackages are retained as experimental reference adapters
for JWT/JWS, CWT/COSE, response-cache, diversion-policy, and gateway-route
experiments. They are not the Direct-Agent core verifier API.

Public API documentation now fixes this boundary:

- Direct-Agent core: `pkg/clients`, `pkg/atls`, and
  `pkg/atls/identitypolicy`;
- experimental reference adapters: `pkg/agtp`, `pkg/agtp/gatewayroute`, and
  `pkg/agtp/diversionpolicy`;
- out of scope for this repository release: runtime gateway-routed mode.

Future cleanup should move `pkg/agtp` under an `experimental/` tree or split it
into a separate module before making gateway-routed runtime claims.

Do not describe this repository as implementing every binding profile from the
draft. Product claims should say that it implements an experimental
Direct-Agent binding profile based on the core acceptance rules.

## Supported v1 Product Surface

Release `v1.1.0` extends the supported surface and compatibility rules in
`docs/API_COMPATIBILITY.md`. The supported product API is the Direct-Agent v1
subset of `pkg/clients` and `pkg/atls/identitypolicy`, composed through the
attested `production.Profile` or attestation-free
`production.SoftwareOnlyProfile`. Draft-06-inspired v2, `pkg/agtp`, gateway
runtime, inherited Cocos runtime services, the Azure bridge, and hardware
evidence acquisition remain experimental or outside the supported API.

The concrete `protected-change-v1` deployment profile is recorded in
`docs/production-deployment-profile.md`. It includes:

- separate Manager, Agent, and attestation-verifier Ed25519 key roles;
- fresh trust and revocation snapshots with fail-closed source errors;
- a signed attestation result bound to the accepted TLS session, exact action,
  verifier nonce, appraisal policy, and measurement;
- an explicit software-only alternative that retains all non-attestation gates
  and rejects attestation binder material;
- a TLS 1.3 Redis/Valkey `SET NX PX` replay adapter with bounded operations and
  optional same-connection `WAIT` acknowledgement;
- a concrete non-Split-Knowledge HTTPS consumer; and
- positive and negative unit, replay-race, and E2E integration tests.

The profile authenticates signed appraisal results. Hardware-specific evidence
acquisition and appraisal remain deployment responsibilities and are not
implied by the default GitHub-hosted test environment.

The repository Sentinel workflow is real self-operated Redis process evidence,
but does not qualify a managed provider's stable endpoint, persistence
contract, partitions, or SLA. Those remain deployment-specific release gates.

## Inherited Runtime Risk Classification

These items come from inherited Cocos runtime code paths. Profile text does not
resolve them.

| Area | Evidence | Classification | Required disposition |
| --- | --- | --- | --- |
| OCI image handling | `pkg/oci/skopeo.go` no longer passes `--insecure-policy`, `--src-tls-verify=false`, `--dest-tls-verify=false`, or `--tls-verify=false`. | Addressed for the current runtime helper. | Keep skopeo policy and TLS verification enabled by default; do not add an insecure development mode without explicit tests and documentation. |
| Egress proxy policy | `pkg/egress/proxy.go` now defaults to loopback-only destinations and supports an explicit host, host:port, IP, or CIDR allowlist for CONNECT, HTTP, and HTTP/2 paths. | Addressed for the current proxy helper. | Configure `EGRESS_PROXY_ALLOWLIST` or `--allowlist` for non-loopback deployments; store unavailability is not part of this local proxy. |
| SEV-SNP HostData and kernel hashes | Go QEMU launch paths and `hal/cloud/qemu.sh` now reject invalid HostData before launch. `SEVSNPAppraisalContract` defines fail-closed HostData and `kernel-hashes=on` appraisal checks for verifier-policy use. | Addressed for the local code-level appraisal contract; hardware evidence wiring remains deployment validation. | Use the contract with an explicit evidence source. Do not rely on launch flags alone as accepted verifier evidence. |
| Zip extraction | `internal/zip.go` validates archive entry paths before extraction. | Addressed for the current in-memory zip helper. | Continue rejecting absolute paths, `..` traversal, unsafe symlinks, unsupported file types, and paths escaping the extraction root. |

## Evaluation Boundaries

The v0.4 red-team evidence is useful but limited. Before broader public
claims, add or explicitly defer:

- end-to-end application 0-RTT payload behavior beyond the dependency-free
  QUIC/TLS early-data harness;
- broader gRPC deployment pooling beyond the local reuse harness;
- runtime gateway wiring beyond the route-assertion HTTP network harness;
- longer randomized fuzz/property campaigns beyond the 60-second JWT/JWS fuzz
  pass and deterministic invariant matrix;
- hardware-backed confidential-VM attestation replay coverage with a recorded
  successful manual workflow run.
