# Agent CLI

This repository contains the command-line interface (CLI) tool for interacting with the Agent and manager service. The CLI allows you to perform various tasks such as running computations, uploading algorithm and datasets, and retrieving results.

## Build

From the project root:

```bash
make cli
```

This builds `build/agents-secure-binding-cli` for the current OS and CPU.
Install the Go version required by the root `go.mod`; Rust and SVSM are needed
only for the optional IGVM helper below. Override `GOOS` / `GOARCH` explicitly
when cross-compiling. Local builds omit Git metadata; release builders can
set `GO_BUILD_FLAGS=-buildvcs=true` and supply `VERSION` / `COMMIT` as needed.

## Usage

#### Get attestation
Retrieves attestation information from the SEV guest and saves it to a file.
To retrieve attestation from agent, use the following command:
```bash
./build/agents-secure-binding-cli attestation get '<report_data>'
```

#### Validate attestation
Validates the retrieved attestation information against a specified policy and checks its authenticity.
To validate and verify attestation from agent, use the following command:
```bash
./build/agents-secure-binding-cli attestation validate '<attestation>' --report_data '<report_data>'
```
##### Flags
- --config: Path to a JSON file containing the validation configuration. This can be used to override individual flags.
- --report_data: Hex-encoded string representing the attestation report data. (Required for the validate command)
- --host_data: Hex-encoded string representing the expected HOST_DATA field.
- --family_id: Hex-encoded string representing the expected FAMILY_ID field.
- --image_id: Hex-encoded string representing the expected IMAGE_ID field.
- --report_id: Hex-encoded string representing the expected REPORT_ID field.
- --report_id_ma: Hex-encoded string representing the expected REPORT_ID_MA field.
- --measurement: Hex-encoded string representing the expected MEASUREMENT field.
- --chip_id: Hex-encoded string representing the expected CHIP_ID field.
- --minimum_tcb: Minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.
- --minimum_launch_tcb: Minimum acceptable value for LAUNCH_TCB.
- --minimum_guest_svn: Minimum acceptable SnpPolicy.
- --minimum_build: Minimum 8-bit build number for AMD-SP firmware.
- --check_crl: Download and check the CRL for revoked certificates (default: false).
- --disallow_network: If true, disallows network downloads for verification (default: false).
- --timeout: Duration to continue retrying failed HTTP requests (default: 2 minutes).
- --max_retry_delay: Maximum duration to wait between HTTP request retries (default: 30 seconds).
- --require_author_key: Require that AUTHOR_KEY_EN is set to 1 (default: false).
- --require_id_block: Require that the VM was launched with an ID_BLOCK signed by a trusted key (default: false).
- --permit_provisional_software: Allow provisional firmware (default: false).
- --platform_info: Maximum acceptable PLATFORM_INFO field bit-wise (optional).
- --minimum_version: Minimum AMD-SP firmware API version (major.minor) (optional).
- --trusted_author_keys: Paths to x.509 certificates of trusted author keys (optional).
- --trusted_author_key_hashes: Hex-encoded SHA-384 hashes of trusted author keys (optional).
- --trusted_id_keys: Paths to x.509 certificates of trusted identity keys (optional).
- --trusted_id_key_hashes: Hex-encoded SHA-384 hashes of trusted identity keys (optional).
- --product: AMD product name for the chip that generated the attestation report (optional).
- --stepping: Machine stepping for the chip that generated the attestation report (optional).
- --CA_bundles_paths: Paths to CA bundles for the AMD product (optional).
- --CA_bundles: PEM format CA bundles for the AMD product (optional).

#### Upload Algorithm

To upload an algorithm, use the following command:

```bash
./build/agents-secure-binding-cli algo /path/to/algorithm <private_key_file_path>
```

##### Flags
- -a, --algorithm string        Algorithm type to run (default "bin")
-     --args stringArray        Arguments to pass to the algorithm
-     --python-runtime string   Python runtime to use (default "python3")
- -r, --requirements string     Python requirements file

#### Upload Dataset

To upload a dataset, use the following command:

```bash
./build/agents-secure-binding-cli data /path/to/dataset.csv <private_key_file_path>
```

Users can also upload directories which will be compressed on transit. Once received by agent they will be stored as compressed files or decompressed if the user passed the decompression argument.

##### Flags
- -d, --decompress   Decompress the dataset on agent



#### Retrieve result

To retrieve the computation result, use the following command:

```bash
./build/agents-secure-binding-cli result <private_key_file_path>
```

#### Checksum
When defining the manifest dataset and algorithm checksums are required. This can be done as below:

```bash
./build/agents-secure-binding-cli checksum <path_to_dataset_or_algorithm>
```

#### Measure IGVM file
Run these commands from the ASB repository root, both on the host machine and in the VM.

`igvmmeasure` calculates the launch measurement for an IGVM file and can generate a signed version. It ensures integrity by precomputing the expected launch digest, which can be verified against the attestation report. The tool parses IGVM directives, outputs the measurement as a hex string, or creates a signed file for verification at guest launch.

This helper is optional and is not built by `make`, `make cli`, or `make manager`.
Prepare a clean local [SVSM checkout](https://github.com/coconut-svsm/svsm) at an
independently reviewed commit, including its pinned submodules and the Rust
build prerequisites documented by that revision. Replace both values below:

```bash
make build-igvm \
  IGVM_SOURCE_DIR=/absolute/path/to/reviewed-svsm \
  IGVM_SOURCE_REVISION=REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT
```

The target requires the exact lowercase commit ID and rejects a mismatched or
dirty checkout and missing or mismatched submodules. It does not clone, pull,
or update source. No default SVSM revision is implied. The helper is installed
as `build/igvmmeasure`; `IGVM_BINARY_PATH` can select an already built helper
elsewhere. The upstream Rust build may need to download its declared build
dependencies.

##### Example
We measure an IGVM file using our measure command, run:

```bash
./build/agents-secure-binding-cli igvmmeasure /path/to/igvm/file
```

The tool will parse the directives in the IGVM file, calculate the launch measurement, and output the computed digest. If successful, it prints the measurement to standard output.

Here is a sample output
```
91c4929bec2d0ecf11a708e09f0a57d7d82208bcba2451564444a4b01c22d047995ca27f9053f86de4e8063e9f810548
```
