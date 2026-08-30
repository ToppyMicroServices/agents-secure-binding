# CoRIM Generator (veraison/corim)

This package provides CoRIM (Concise Reference Integrity Manifest) generation using the standard [veraison/corim](https://github.com/veraison/corim) library.

## Overview

The `corimgen` package generates CoRIM containers for local SNP and TDX
attestation policy. The container and CoMID encoding use the `veraison/corim`
implementation of RFC 9393. The SNP/TDX measurement-key mapping is an ASB-local
appraisal profile, not an IETF-assigned interoperability profile.

## Features

- **SNP Support**: Generate keyed constraints for measurement, guest SVN, host data, policy, and minimum launch TCB
- **TDX Support**: Generate CoRIM for Intel TDX with MRTD, MRSEAM, and RTMRs
- **COSE Signing**: Optional COSE_Sign1 signing with crypto.Signer keys
- **Defaults**: Sensible defaults for testing and development

## Usage

### Basic Usage (Unsigned)

```go
import "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"

opts := corimgen.Options{
    Platform:    "snp",
    Measurement: "abc123...", // hex-encoded
    Product:     "Milan",
    SVN:         1,
}

corimBytes, err := corimgen.GenerateCoRIM(opts)
```

### With Signing

```go
import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    
    "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/corimgen"
)

// Generate signing key
privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

opts := corimgen.Options{
    Platform:    "snp",
    Measurement: "abc123...",
    SVN:         1,
    SigningKey:  privateKey, // COSE signing
}

signedCorimBytes, err := corimgen.GenerateCoRIM(opts)
```

### TDX with RTMRs

```go
opts := corimgen.Options{
    Platform:    "tdx",
    Measurement: "91eb2b44...", // MRTD
    MrSeam:      "5b38e33a...", // MRSEAM
    RTMRs:       "ce0891f4...,062ac322...,5fd86e8c...,00000000...", // comma-separated
}

corimBytes, err := corimgen.GenerateCoRIM(opts)
```

## Options

| Field | Type | Description |
|-------|------|-------------|
| `Platform` | string | Platform type: "snp" or "tdx" |
| `Measurement` | string | Hex-encoded measurement (MRTD for TDX, measurement for SNP) |
| `Product` | string | SNP processor product name (e.g., "Milan", "Genoa") |
| `SVN` | uint64 | Exact SNP guest SVN; unsupported for TDX |
| `Policy` | uint64 | Exact nonzero SNP policy flags |
| `RTMRs` | string | TDX Runtime Measurement Registers (comma-separated hex) |
| `MrSeam` | string | TDX SEAM module measurement (hex) |
| `HostData` | string | Exact 32-byte SNP host data (64 hex characters) |
| `LaunchTCB` | uint64 | Component-wise minimum SNP launch TCB when nonzero |
| `SigningKey` | crypto.Signer | Optional COSE signing key (ES256) |

## Defaults

The package provides sensible defaults for testing:

### SNP
- `SNPDefaultMeasurement`: 48-byte zero measurement
- `SNPDefaultVmpl`: VMPL level 2

### TDX
- `TDXDefaultMrTd`: Default MRTD value
- `TDXDefaultMrSeam`: Default MRSEAM value
- `TDXDefaultRTMRs`: Default RTMR values (4 registers)

## Implementation Details

### CoRIM Structure

Generated CoRIM contains:
- **CoRIM ID**: Unique identifier (`platform-corim-{uuid}`)
- **CoMID Tags**: One or more CoMID tags with:
  - **Tag Identity**: Unique tag ID and version
  - **Environment**: Platform class (UUID) and optional instance (product)
  - **Reference Values**: Measurements with repository-local unsigned-integer
    keys. SNP uses `0x1000`-`0x1003`; TDX uses `0x2000`, `0x2001`, and
    `0x2010`-`0x2013`. These values are not IETF-assigned code points.

The matching appraisers reject unkeyed, unknown, duplicate, and unsupported
constraints. TDX TCB policy remains in the platform JSON policy as
`minimum_tee_tcb_svn`; it is not represented by the scalar `SVN` option.

### Signing

When `SigningKey` is provided:
1. Creates unsigned CoRIM
2. Wraps in COSE_Sign1 message
3. Signs with ES256 algorithm (ECDSA P-256)
4. Returns signed CBOR bytes

### Verification

To verify a signed CoRIM:
```go
import (
    "crypto/ecdsa"
    "github.com/veraison/corim/corim"
)

var signedCorim corim.SignedCorim
err := signedCorim.FromCOSE(signedBytes)

publicKey := privateKey.Public().(*ecdsa.PublicKey)
err = signedCorim.Verify(publicKey)
```

## Testing

Run tests:
```bash
go test ./pkg/attestation/corimgen/... -v
```

## Integration

This package is used by:
- `pkg/attestation/generator` - Backward-compatible wrapper
- `cli` - CoRIM generation commands
- `manager` - Dynamic CoRIM policy generation

## References

- [RFC 9393 - CoRIM](https://datatracker.ietf.org/doc/rfc9393/)
- [veraison/corim](https://github.com/veraison/corim)
- [COSE (RFC 9052)](https://datatracker.ietf.org/doc/rfc9052/)
