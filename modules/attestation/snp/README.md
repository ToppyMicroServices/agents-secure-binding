# Direct SEV-SNP attestation module

Status: experimental `v0.x`. The deterministic cryptographic tests pass, but
this module has not been qualified on live SNP hardware and is not
production-ready.

This module accepts either a `sevsnp.Attestation` protobuf or an AMD ABI report
with its certificate table. `Verify` checks the certificate chain, report
signature, CRL, local SNP policy, debug state, VMPL, and the caller-supplied
`REPORT_DATA`. Its default network getter is bounded and restricted to AMD KDS.

It does not implement ASB, TLS, EAT, or CoRIM. Those concerns stay in the root
composition layer.

Run the hardware-independent checks with:

```sh
GOWORK=off go mod verify
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

Live qualification must use the exact target image, launch policy, AMD product,
endorsement path, and collateral environment.
