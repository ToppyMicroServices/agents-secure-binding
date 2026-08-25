# `draft06-v2` full-wire fixture

`draft06-v2-wire.json` is a fixed evidence vector for this repository's
experimental `draft06-v2` profile. It is not an IETF conformance vector.
It starts after TLS 1.3 acceptance: the vector records the accepted endpoint
SPKI and exporter output, not a TLS handshake or certificate chain.

The fixture contains:

- the HTTP method, path, relevant headers, and exact request body bytes;
- the compact JWS authority grant, session proof, and attestation result inside
  those body bytes;
- public verification keys only;
- the endpoint SPKI, TLS exporter output, nonce, and attempt ID used to derive
  the binding;
- canonical task, target, and binding-context bytes with their expected
  digests; and
- the expected application-facing Accepted Assertion.

Binary and exact HTTP-body values use unpadded base64url. Hashes use lowercase
`sha256:` form. All values are synthetic and test-only. The fixture contains no
private key or deployable credential.

Run its verifier with:

```sh
go test -run '^TestDraft06V2FullWireEvidenceFixture$' ./examples/a2a-multiprocess
```

The test uses the production v2 parsers and policy path. It checks both JWS
signatures, reconstructs the canonical contexts and binding hashes, compares
the Accepted Assertion, and rejects a second use of the same verifier nonce.

The separately implemented Python verifier checks the same fixture, including
all three ES256 signatures, without calling the production Go parser:

```sh
python3 interop/draft06-v2/verify_wire_fixture.py \
  examples/a2a-multiprocess/testdata/draft06-v2-wire.json
```

## Multi-host deployment input

`multihost-deployment.example.json` is the input template for running the same
reference roles on separately addressed hosts. It contains no credentials.
The bootstrap command uses its HTTPS hostnames or IP addresses as certificate
SANs and writes role-specific credentials plus a non-secret trust manifest.

An alternate Agent B implementation can use this deployment shape and the
full-wire fixture as an adapter entry point. Neither fixture is evidence that
an independent vendor or a physically separate host was tested. That requires
an actual external deployment and a recorded run.
