# GCP firmware policy preparation

Prepare paired direct-SNP appraisal inputs from a Google-signed firmware
endorsement. The command pins the Google production root certificate by SHA-256,
verifies the endorsement signature and validity, and matches the candidate
measurement against the signed value for the expected launch VMSA count.
The candidate measurement alone is never an allowlist.

```sh
go run ./cmd/gcp-firmware-policy \
  -google-root google-production-root.der \
  -endorsement endorsement.binarypb \
  -measurement <48-byte-measurement-in-hex> \
  -launch-vmsas 2 -vmpl 0 -out-dir approved-policy
```

Obtain the root independently from
[Google PKI](https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt).
The command refuses another root, malformed or expired endorsements, debug
policies, unspecified VMSA/VMPL values, and an existing output directory.
It targets AMD Milan. Select VMSA count and VMPL for the intended deployment;
the values above describe the GCP N2D configuration used in PR #75.

## Use both outputs

Pass `approved.corim.cbor` as `-corim-policy` and `platform-policy.json` as
`-platform-policy` to `hardware-attestation-redteam`, together with
`-platform snp -require-full-verification`.

The platform policy keeps the signed guest-policy allowance, exact measurement
and VMPL, AMD certificate verification, and CRL checks. The CoRIM holds the same
approved measurement. Its local SNP policy key means exact equality, so it must
not duplicate an allowance as an exact value. For example, the signed allowance
`0x70000` permits a migration agent; the stricter report value `0x30000` disables
it and is valid under the platform policy. An independently required exact
policy can still be expressed with the existing general CoRIM generator.

This is firmware qualification preparation, not a completed hardware test.
It does not establish application, model, kernel or host-data identity, and does
not invent TCB or guest-SVN floors from the report under test. Deployment owners
must supply those requirements when their threat model needs them. The output
CoRIM is unsigned and must be transported as a trusted verifier input.

Tests use synthetic endorsement certificates and field-appraisal fixtures.
They do not constitute a live AMD or Google trust-chain result.
