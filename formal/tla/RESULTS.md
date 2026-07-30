# Recorded TLA+ verification result

This file records bounded model-checking evidence for `DurableGate.cfg`. It
does not claim an unbounded proof or formal equivalence with the Go
implementation.

## Toolchain

- TLA+ tools release: v1.7.4
- TLC: 2.19, 8 August 2024
- Java: OpenJDK 21.0.12
- `tla2tools.jar` SHA-1:
  `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`

The jar checksum matches the checksum published with the official TLA+ v1.7.4
release.

## Commands

Syntax and semantic analysis:

```sh
/opt/homebrew/opt/openjdk@21/bin/java \
  -cp /private/tmp/tla2tools-1.7.4.jar \
  tla2sany.SANY formal/tla/DurableGate.tla
```

Bounded exhaustive model check:

```sh
TLA2TOOLS_JAR=/private/tmp/tla2tools-1.7.4.jar \
  JAVA_BIN=/opt/homebrew/opt/openjdk@21/bin/java \
  sh formal/tla/run.sh
```

## Configuration

- replay keys: 2
- authorizations: 1
- lease tokens: 2
- event identifiers: 3
- logical time values: 3 (`0..2`)
- maximum audit sequence length: 5
- deadlock checking: disabled intentionally for this bounded safety model

## Result

The SANY analysis completed without an error. TLC checked all invariants in
`DurableGate.cfg` without finding a violation:

- states generated: 7,692,655
- distinct states: 1,555,674
- search depth: 47
- states left on queue: 0
- workers: 1
- elapsed time: 44 seconds
- fingerprint index: 101
- seed: `-6283031415273992745`

TLC reported an estimated missed-state probability of `5.2E-7`
(optimistic calculation) and `8.4E-8` based on the actual fingerprints.

These values were reproduced locally on 2026-07-30. Assumptions and uncovered
implementation obligations are listed in `README.md`.
