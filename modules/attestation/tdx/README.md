# Intel TDX attestation module

Status: experimental `v0.x`. A pinned quote passes real quote authentication
and local-policy validation in deterministic tests. The pinned upstream PCS
fixture is deliberately rejected because its TCB levels do not match that
quote, so there is still no successful strict collateral/CRL fixture or live
TDX run for this change. The module is not production-ready.

This module accepts a raw QuoteV4. `Verify` checks quote authentication,
certificate and PCS collateral, CRL status, local TDX policy, debug state, and
the caller-supplied `REPORT_DATA`. Its default network getter is bounded and
restricted to the exact Intel PCS API and certificate origins required for
collateral and Root CA CRL retrieval. A deployment may inject a reviewed local
collateral getter.

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
../../../scripts/check-attestation-vulnerabilities.sh tdx
```

`go-tdx-guest` requires `x/crypto/cryptobyte`, so the Go vulnerability database
also reports the unmaintained `x/crypto/openpgp` package as the module-only
advisory `GO-2026-5932`. This module does not import `openpgp`, and no fixed
`x/crypto` version exists for that advisory. The vulnerability gate rejects any
future `openpgp` import before running the package scan. It does not suppress
the module-only notice or turn a clean result into a hardware or
production-readiness claim.

Live qualification must use the exact target image, launch policy, Intel
platform, endorsement path, and collateral environment.

A future strict offline success fixture must capture the quote and all four PCS
responses, including issuer-chain headers, as one time-consistent set. Mixing
the pinned quote with unrelated or differently dated collateral would create a
misleading green test.
