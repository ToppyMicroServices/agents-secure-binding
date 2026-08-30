# Direct SEV-SNP attestation module

Status: experimental `v0.x`. The deterministic cryptographic tests pass, but
this module has not been qualified on live SNP hardware and is not
production-ready.

This module accepts either a `sevsnp.Attestation` protobuf or an AMD ABI report
with its certificate table. `Verify` checks the certificate chain, report
signature, CRL, local SNP policy, debug state, VMPL, and the caller-supplied
`REPORT_DATA`. The provided `NewKDSGetter` is bounded and restricted to AMD
KDS; callers must select it or inject another reviewed collateral getter.

It does not implement ASB, TLS, EAT, or CoRIM. Those concerns stay in the root
composition layer.

The root A2A tester's `--debug-simple` mode uses signed simulated evidence and
does not import, invoke, or qualify this module.

Run the hardware-independent checks with:

```sh
GOWORK=off go mod tidy -diff
GOWORK=off go mod verify
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
GOWORK=off go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -scan=package ./...
```

The package scan covers imported packages. It does not turn a clean result into
a hardware or production-readiness claim.

Live qualification must use the exact target image, launch policy, AMD product,
endorsement path, and collateral environment.
