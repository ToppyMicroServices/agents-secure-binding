# Execution bundle hash v1

The manifest `algorithm.hash` commits to the inputs that determine algorithm
execution. Producers should compute it with `agent.AlgorithmCommitment`, which
applies the v1 encoding when the algorithm uses a runtime type other than
`bin`, has arguments, or has a requirements file.

The v1 input is a length-prefixed sequence:

1. the domain string `asb.execution-bundle.v1`;
2. `algo_type`;
3. the number of arguments, followed by each argument in order;
4. the algorithm program bytes; and
5. the requirements-file bytes, including their exact whitespace.

The digest is SHA3-256 over that sequence. Length prefixes prevent two
different field sequences from producing the same encoded input. Argument
order is significant.

For compatibility, a `bin` algorithm with no arguments and no requirements
continues to use `SHA3-256(program)`. This exception is safe because the program
is the only execution input in that case. All other legacy program-only hashes
are rejected.

The upload metadata must contain the same `algo_type` and ordered `algo_args`
as the manifest. A mismatch is rejected before the program is stored or run.
OCI-loaded algorithms use the same commitment and include the extracted
`requirements.txt` bytes when present.

The current OCI execution path supports one executable program plus an optional
`requirements.txt`. Multi-file runtime packages are not part of this profile;
supporting them requires committing to and provisioning the complete package.

Dataset hashes are unchanged and continue to commit to the dataset bytes.
