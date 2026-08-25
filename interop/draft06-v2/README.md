# draft06-v2 cross-language context vector

This directory holds the repository profile's Appendix B context vector and a
small verifier written with the Python standard library. The verifier rebuilds
the length-prefixed context and attestation input from source values. It then
checks the exact bytes and all four SHA-256 results.

Run it from the repository root:

```sh
python3 interop/draft06-v2/verify_context_vector.py \
  interop/draft06-v2/appendix-b-context.json
```

This is second-language evidence for the fixed byte construction. It is not a
claim of independent-vendor, multi-host, TLS-stack, JWS, or complete protocol
interoperability.

## Full-wire fixture

`verify_wire_fixture.py` independently reads the repository-generated HTTP/JWS
fixture. It rebuilds the task, target, binding, and attestation inputs; checks
the compact JWS payload relations and hashes; and compares the resulting
Accepted Assertion. With OpenSSL, it also verifies the three ES256 signatures
from the public JWKs in the fixture.

```sh
python3 interop/draft06-v2/verify_wire_fixture.py \
  examples/a2a-multiprocess/testdata/draft06-v2-wire.json
```

The script uses only the Python standard library and the system `openssl`
command. `--skip-signatures` is available for environments without OpenSSL and
is reported explicitly in the result. This adds a separately implemented
parser and byte reconstruction, but it remains same-repository evidence rather
than an independent-vendor or live multi-host interoperability result. It
starts from the recorded endpoint SPKI and TLS exporter output; it does not
replay a TLS handshake.
