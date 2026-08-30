# CoRIM Generator Package

The `generator` package provides a unified interface for generating CoRIM (Concise Reference Integrity Manifest) attestation policies for different TEE platforms.

## Overview

This package consolidates CoRIM generation logic for SNP and TDX platforms, providing consistent defaults and behavior that matches legacy attestation policy generation scripts.

## Features

- **Platform Support**: SNP (AMD SEV-SNP) and TDX (Intel TDX)
- **Legacy Defaults**: Maintains compatibility with legacy Rust SNP and Go TDX policy scripts
- **Flexible Configuration**: Supports custom measurements, policies, and platform-specific parameters
- **CBOR Output**: Generates CoRIM in CBOR format for standardized attestation

## Usage

### Basic Example

```go
import "github.com/ToppyMicroServices/agents-secure-binding/v2/pkg/attestation/generator"

// Generate SNP CoRIM with defaults
opts := generator.Options{
    Platform: "snp",
    Product:  "Milan",
}
corimBytes, err := generator.GenerateCoRIM(opts)
if err != nil {
    // handle error
}
```

### SNP with Custom Values

```go
opts := generator.Options{
    Platform:    "snp",
    Measurement: "abc123...", // hex string
    Product:     "Genoa",
    SVN:         1,
    Policy:      0x30000,
    HostData:    "0000000000000000000000000000000000000000000000000000000000000000",
    LaunchTCB:   1,
}
corimBytes, err := generator.GenerateCoRIM(opts)
```

### TDX with Custom Values

```go
opts := generator.Options{
    Platform:    "tdx",
    Measurement: "def456...", // MRTD hex string
    RTMRs:       "rtmr0,rtmr1,rtmr2,rtmr3", // comma-separated hex
    MrSeam:      "789abc...", // hex string
}
corimBytes, err := generator.GenerateCoRIM(opts)
```

## Options

### Common Fields
- `Platform` (string): Platform type - "snp" or "tdx"
- `Measurement` (string): Hex-encoded measurement (defaults provided if empty)

### SNP-Specific Fields
- `SVN` (uint64): Exact guest SVN when nonzero
- `Product` (string): Processor product name (e.g., "Milan", "Genoa")
- `Policy` (uint64): SNP policy flags
- `HostData` (string): Exact 32-byte host data (64 hex characters)
- `LaunchTCB` (uint64): Minimum launch TCB version

### TDX-Specific Fields
- `RTMRs` (string): Comma-separated hex-encoded RTMRs
- `MrSeam` (string): Hex-encoded MRSEAM value

## Default Values

### SNP Defaults
- Measurement: 48 bytes of zeros (if not provided)
- Product: "Milan"
- SVN: omitted when 0
- Policy: 0

### TDX Defaults
- Measurement (MRTD): `000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000`
- MRSEAM: `2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656`
- RTMRs: Four 48-byte zero values

TDX does not accept the scalar `SVN` option. Configure the 16-byte
`minimum_tee_tcb_svn` in the TDX platform policy instead.

The generated CoMID uses repository-local unsigned-integer measurement keys so
the appraiser can distinguish SNP and TDX fields. These keys are not
IETF-assigned values or a general interoperability profile.

## Integration

This package is used by:
- **CLI**: `agents-secure-binding-cli policy create-corim snp/tdx` commands
- **Manager**: Dynamic CoRIM generation in `FetchAttestationPolicy`
- **Scripts**: `scripts/corim_gen` standalone tool

## See Also

- [CoRIM Package](../corim/README.md)
- [IGVM Measure Package](../igvmmeasure/README.md)
