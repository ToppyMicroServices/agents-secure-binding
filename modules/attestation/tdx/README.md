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

Run the hardware-independent checks with:

```sh
GOWORK=off go mod verify
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

Live qualification must use the exact target image, launch policy, Intel
platform, endorsement path, and collateral environment.

A future strict offline success fixture must capture the quote and all four PCS
responses, including issuer-chain headers, as one time-consistent set. Mixing
the pinned quote with unrelated or differently dated collateral would create a
misleading green test.
