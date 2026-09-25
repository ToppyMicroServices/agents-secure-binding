# Agent interaction through ASB discovery

This example starts Agent A, a discovery relay, and Agent B as three separate
processes on loopback. Agent A finds Agent B through DHT and gossip, then asks
it to add `7 + 11 + 13`. Agent B verifies a separate ASB task grant and session
proof before returning `31`.

The agents are deterministic reference programs with different identities and
keys. They do not call an LLM or an external service.

## Run

From the repository root, with the configured Go toolchain installed:

```sh
GOWORK=off go run ./examples/agtp-agent-interaction \
  --report /tmp/asb-agent-interaction.json
```

The command prints JSON evidence, exits with zero only when the interaction and
cleanup succeed, and stops its children. The report includes the three process
IDs, the discovered endpoint, authorization decisions, request, and result.
Ports and process IDs vary on each run. A successful result includes:

```json
{
  "passed": true,
  "distinct_processes": true,
  "distinct_tls_keys": true,
  "without_task_proof_status": 401,
  "authorized_status": 200,
  "result": {
    "task_id": "sum-demo-1",
    "agent_id": "agent-b",
    "caller": "agent-a",
    "sum": 31,
    "executions": 1
  }
}
```

This is an excerpt; the actual report also includes discovery and runtime
fields. Temporary role configuration, keys, replay files, and audit logs are
removed after the processes stop. The report contains no keys or tokens. A
forced termination of the parent may leave its private temporary directory;
normal shutdown reports cleanup failures.

## What the run checks

1. Agent A starts with an empty task catalog and only the relay in its routing
   table. All permitted peers are already registered in local trust policy.
2. An ASB-authorized DHT lookup learns Agent B's discovery node through the relay.
3. An ASB-authorized gossip exchange transfers B's task registration. Agent A
   queries its own trusted local catalog and resolves the returned name.
4. Agent A checks the resolved identity and endpoint against its configured
   target and checks B's public-key pin when connecting. There is no endpoint
   fallback when discovery fails.
5. A task request without its ASB proofs receives HTTP 401. A new connection
   with the task-specific grant and a fresh session-bound proof succeeds.
6. B's response identifies A as the caller and reports one execution. The
   orchestrator checks B's process ID against the process it launched.

The local catalog query is not an HTTP `DISCOVER` exchange. DHT and replication
have their own grants; neither grants permission to execute the sum task. The
sum handler reuses `production.SoftwareOnlyProfile` and
`production.SoftwareBindingFromTLS`. The request body, task, actor, destination,
TLS session, and verifier nonce are bound before execution. Replay state uses
a separate file-backed cache on B.

## Validation and limits

```sh
GOWORK=off go test -race -count=1 ./examples/agtp-agent-interaction
GOWORK=off go vet ./examples/agtp-agent-interaction
```

The multiprocess test uses the same role entry point as the standalone command.
Additional tests cover key/grant separation, discovery target selection, input
bounds, and task authorization before execution.

This is one software-only request/response on one host, using fresh demo
identities and preissued, short-lived grants. It does not establish hardware
attestation, independent-vendor interoperability, or operation on separate
LAN/VPC hosts. The response is authenticated by the same pinned TLS connection;
it is not a separately ASB-bound reverse-direction request. The reference task
API does not claim A2A wire conformance.

All children run as the same OS user. Separate process IDs and private config
files do not establish isolation from a compromised process with that user's
permissions. The sum operation has no external side effects. Replay protection
does not provide a durable task outcome journal or general exactly-once
execution; the client does not retry an uncertain result.

See [the LAN/VPC profile](../../docs/agtp-discovery-lan.md) for the discovery
transport's deployment boundaries. A real Agent adapter can replace the bounded
sum handler while retaining its ASB verification gate and defining its own
task authorization and outcome persistence.

## Remote Linux validation

The `ASB Discovery Linux` workflow runs only on Ubuntu. It runs the race tests,
the opt-in local interface test, the standalone interaction, and a separate
network namespace integration test. It retains non-secret evidence for one day.
It does not start the repository's macOS jobs.

The main `CI` workflow also accepts a manual `linux_only=true` input. This runs
the existing Linux lint, module tests, and product checks, including the ordinary
interaction test. Its macOS jobs are skipped for that manual invocation; normal
push and pull-request invocations retain their existing platform coverage.

On a disposable Linux runner with `iproute2` and root access:

```sh
GOWORK=off go test -race -c -o /tmp/asb-interaction.test ./examples/agtp-agent-interaction
sudo env ASB_INTERACTION_NETNS_TEST=1 \
  ASB_INTERACTION_NETNS_REPORT=/tmp/asb-network-namespaces.json \
  /tmp/asb-interaction.test -test.v -test.run '^TestLinuxNamespaceInteraction$'
```

The harness creates three separate network namespaces joined by a temporary
bridge, with fixed private IPs and explicit `/32` host permissions. Each role
keeps its own TLS and signing keys. The harness uses the same ASB discovery and
task handlers as the ordinary example. Its explicit private-network configuration
does not change the default loopback-only command.

The namespace test removes its own network devices and namespaces on exit. It
does not alter the host's default route or firewall, and gives the namespaces
no external gateway. This verifies communication across Linux network stacks
on one host. It does not qualify separate VMs, cloud firewalls, VPN links, or
multi-host credential distribution.

### Linux-only pull request checks

A maintainer can apply the `ci:linux-only` label before pushing a new PR commit
or reopening the PR. The normal pull-request workflows then run their Linux
checks, including every required check, without starting macOS or Windows
runners. Human-approval cross-compilation still runs on Ubuntu for all targets.
Unlabelled PRs and normal pushes retain the full platform matrix.

The `CI` workflow also accepts `linux_only=true` for manual diagnosis. GitHub
does not count `workflow_dispatch` jobs toward required PR status checks, so
use the normal pull-request event when preparing a merge.
