# Agent Runtime Notes

The Agent runtime is inherited implementation code. It is not the core
Direct-Agent verifier API for this repository.

Use it only as an experimental runtime harness around the profile helpers in:

- `pkg/clients`
- `pkg/atls`
- `pkg/atls/identitypolicy`

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `AGENT_LOG_LEVEL` | Agent log level | `debug` |
| `AGENT_VMPL` | VM privilege level for attestation requests | `2` |
| `AGENT_GRPC_HOST` | Agent gRPC bind host | `0.0.0.0` |
| `AGENT_CVM_CA_URL` | Optional CA service URL | empty |
| `AGENT_CVM_ID` | Manager-assigned VM ID used as the Agent RPC audience | empty |
| `AGENT_CERTS_TOKEN` | Certificate request token | empty |
| `AGENT_MAA_URL` | Azure MAA URL | `https://sharedeus2.eus2.attest.azure.net` |
| `ATTESTATION_SERVICE_SOCKET` | Attestation service Unix socket | `/run/agents-secure-binding/attestation.sock` |

Runtime plaintext paths are expected to stay on Unix sockets or loopback unless
TLS or aTLS is explicitly configured.

Agent RPC signatures bind both the Manager-assigned VM ID and the computation
run ID supplied in the CVMS `ComputationRunReq`. CLI users must set
`AGENT_CVM_ID` to the ID returned when creating the VM and
`AGENT_COMPUTATION_ID` to that run-request ID before running `algo`, `data`, or
`result`. The Agent rejects either missing ID and legacy signatures. Update
the CLI and Agent together. A VM cannot start the same run ID twice: Agent
records used VM/run pairs in its persistent storage directory so an old proof
cannot become valid again after a run or process restart. Keep that directory
for the lifetime of the VM ID. It retains one small marker per run. A bind
failure releases its reservation so the same run ID can be retried.
