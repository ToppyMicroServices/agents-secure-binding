# Azure SEV-SNP attestation bridge

Status: unreleased candidate deployment profile for `protected-change-v1`; a
successful run on an Azure confidential VM and a minor release are required
before it joins the supported product surface.

## Boundary

`production.AzureSNPAttestationBridge` is the relying-party bridge between an
Azure Attestation JWT and `production.AttestationResult`. It does not collect a
quote itself and does not silently enable the inherited Azure runtime fetcher.
The confidential VM obtains the token with Microsoft's guest-attestation
library; the bridge authenticates and appraises that token and signs the
short-lived ASB result.

The deployment has three separate trust domains:

1. Azure Attestation signs the hardware appraisal JWT with RS256.
2. The bridge pins the expected Azure Attestation issuer and a reviewed key
   snapshot from that provider's OpenID metadata.
3. The bridge signs `asb-attestation-result/v1` with its own Ed25519 key. The
   ASB verifier trusts that key only in the attestation-verifier role.

The bridge never follows a token-provided `jku` URL during acceptance. Key
refresh is an administrative operation and must atomically replace the trusted
snapshot after the provider issuer and OpenID metadata endpoint are checked.

## Exact session and action binding

For each accepted TLS session and canonical action:

1. ASB derives `attestation_binder_sha256` from the peer key, TLS exporter,
   canonical action, and verifier nonce.
2. The caller computes
   `production.AzureSNPChallenge(attestation_binder_sha256)`.
3. The confidential workload supplies that ASCII value as the Azure guest
   attestation nonce.
4. The bridge requires the signed token's `nonce` claim to match the challenge
   exactly before it signs an ASB result.

A token collected for another TLS session, action, or verifier nonce therefore
cannot be converted into a result for the current binder. A deployment must
confirm that its chosen Azure guest-attestation API includes the supplied
nonce in the verified token flow; merely copying an unverified request value
into application metadata is insufficient.

## Fixed appraisal

Configure the bridge with exact values, not prefixes or display names:

- Azure Attestation issuer URI;
- enabled RS256 signing-key IDs and RSA public keys;
- accepted `x-ms-policy-hash` values;
- accepted SEV-SNP launch measurements;
- minimum guest SVN;
- debug disabled;
- migration disabled unless the deployment has a separate migration policy;
- maximum Azure token age; and
- a short ASB result TTL.

The bridge accepts the documented nested guest-attestation claim layout and a
direct top-level SEV-SNP layout. It rejects missing or ambiguous security
claims. It does not infer defaults for debug, migration, SVN, measurement, or
policy hash.

## Real-hardware qualification

Run this qualification on an Azure AMD SEV-SNP confidential VM with vTPM and
Secure Boot enabled:

1. Install Microsoft's supported guest-attestation package and workload
   integration.
2. Generate an ASB binder for one real mTLS session and canonical protected
   action, then compute its Azure challenge.
3. Request an Azure Attestation token with that challenge.
4. Verify it through `AzureMAATokenVerifier` and issue the ASB result through
   `AzureSNPAttestationBridge`.
5. Complete the protected-change request and record only non-sensitive
   fingerprints, measurement, policy ID, provider issuer, key ID, and time.
6. Repeat with a second session and require rejection of the first token under
   the second binder.

The negative run must also reject a wrong issuer, unknown or disabled MAA key,
expired or stale token, wrong policy hash, wrong launch measurement, low guest
SVN, debug enabled, migration enabled, and bridge-key revocation.

Do not upload raw tokens, TPM keys, TLS private keys, Redis credentials, or
bridge private keys as CI artifacts. Azure resource creation and the hardware
run are deployment operations with account and cost implications; default
GitHub-hosted runners do not qualify as hardware evidence.

## Operations

Keep the bridge Ed25519 key in an HSM or managed KMS signer in production.
`AzureSNPAttestationBridge.Signer` accepts a standard `crypto.Signer`; local
tests use an ephemeral Ed25519 key, while a production service supplies its
KMS/HSM-backed adapter. A long-lived production service must not load the raw
bridge private key from application configuration.

Rotate MAA and bridge keys with an overlap window: add the new key, verify live
traffic and negative tests, switch issuance, then disable the old key. A
provider-token verification outage or unavailable key snapshot fails closed;
there is no software-only attestation fallback.

Primary references:

- <https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-vms>
- <https://learn.microsoft.com/en-us/azure/attestation/claim-sets>
- <https://learn.microsoft.com/en-us/rest/api/attestation/metadata-configuration/get?view=rest-attestation-2022-08-01>
