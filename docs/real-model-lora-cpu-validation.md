# Real model and LoRA validation on Mac CPU

On 2026-10-16 JST (2026-10-15 UTC), the real-model system suite passed all
13 cases: two accepted A2A round trips and eleven expected rejections.
Both agents ran on one Mac using CPU inference. Runtime source was unchanged
from `2f547ae147b130ff26fea63c478124c0b3894f10`.

The recorded machine-readable results are in
[real-model-lora-cpu-validation.json](real-model-lora-cpu-validation.json).
Full logs, manifests, training records, the adapter, script snapshots, and
checksums are preserved locally in the evidence bundle described below.

## Model and approval

The base was the official pretrained
[SmolLM2-135M-Instruct checkpoint](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/tree/12fd25f77366fa6b3b4b768ec3050bf629380bac),
revision `12fd25f77366fa6b3b4b768ec3050bf629380bac`. Its 269,060,552-byte
Safetensors file has SHA-256
`5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c`.
All six upstream model/config/tokenizer files matched their pinned sizes and
hashes before training and after the system suite.

Agent A used the base-only manifest. Agent B used the same base plus an ordinary
PEFT LoRA trained locally on four harmless question/answer examples. Six CPU
optimizer steps updated 15,360 LoRA parameters in the last two layers. Frozen
base tensor hashes stayed equal; the base checkpoint was never re-saved.
The saved adapter contained 6,144 nonzero LoRA B elements. Reloaded tensors
matched the saved tensors exactly, including dtype. The maximum logit change
from the base was 0.3125 on the recorded probe; trained versus reloaded logits
had zero difference.

The test-only approval fixed these manifest digests before any mutation:

- Base: `sha256:105205faa4787f5acbe7a18f6b4ee5e94c4036990c138470692abe815fc67483`
- Base + LoRA: `sha256:e40275b80ce9d1892e255ac65823b417d2ef169b384f41a792fe5da6cc70187e`

This approval records fixture identity for the test. It is not a production
approval or a behavioral safety assessment.

## System results

| Case | Expected and observed | Seconds |
| --- | --- | ---: |
| Approved base / base + LoRA, v1 | A2A allowed; nonempty outputs from both agents | 17.890 |
| Approved base / base + LoRA, draft06-v2 | A2A allowed; nonempty outputs from both agents | 23.932 |
| Base weight byte changed | Agent B rejected the digest mismatch | 0.667 |
| LoRA weight byte changed | Agent B rejected the digest mismatch | 0.982 |
| Tokenizer byte changed | Agent B rejected the digest mismatch | 1.029 |
| Model configuration byte changed | Agent B rejected the digest mismatch | 0.236 |
| Adapter configuration byte changed | Agent B rejected the digest mismatch | 1.142 |
| Chat template changed | Agent B rejected the digest mismatch | 0.973 |
| Declared LoRA weights missing | Agent B rejected the missing regular file | 0.987 |
| Adapter removed from manifest | Agent B rejected the changed manifest | 0.182 |
| Adapter added to base-only manifest | Agent B rejected the changed manifest | 0.183 |
| Adapter changed and its manifest entry rehashed | Agent B rejected the manifest against the original approval pin | 0.225 |
| Agent A's approved manifest changed | Agent A rejected it before the conversation | 6.933 |

Positive checks required exit code 0, the expected observed protocol profile,
one passing A2A scenario, Agent B readiness, and nonempty generated text from
both agents. Negative checks required a nonzero exit and the specific artifact
configuration error, an `ERROR` report with zero passed scenarios, and no
conversation output. A generic startup failure could not pass a rejection
case. Agent B rejection cases also required its readiness marker to be absent.
For negative cases, `PASS` means that the expected rejection occurred.

The rejection phase is established by the exact configuration error and the
runtime's validation-before-launch ordering. No inference counter was
instrumented. All mutations were restored, and the final manifest, file size,
file hash, and Python executable checks passed.

## Environment and reproduction

Tested: macOS 26.7.1 arm64; CPU; Python 3.14.6; Go 1.26.9;
PyTorch 2.14.1; Transformers 5.19.0; PEFT 0.21.2; Safetensors 0.8.0;
tokenizers 0.23.3; huggingface-hub 2.2.0 for preparation.

With those dependencies installed in a virtual environment, run from the
repository root. Use a new absolute output directory for each preparation and
system run:

```sh
/path/to/venv/bin/python -B scripts/prepare-real-model-lora.py \
  --output /absolute/path/to/new-fixture
/path/to/venv/bin/python -B scripts/test-real-model-lora.py \
  --config /absolute/path/to/new-fixture/test-config.json \
  --output /absolute/path/to/new-fixture/results
```

Preparation downloads about 271 MB and trains the small adapter on CPU. The
system runner builds the A2A CLI and runs the suite with local sockets. It
temporarily modifies only the disposable fixture; it must not target a model
directory used by another process. The expected digests stay fixed throughout
the negative cases. Undeclared source files are omitted by the runtime rather
than rejected; the adapter-addition case therefore changes the manifest.

The first preparation attempt exposed a dtype mismatch between PEFT's default
FP32 adapter promotion and the managed runtime's BF16 load. Its strict reload
equality check failed. The fixture preparation now uses
`autocast_adapter_dtype=False`, matching the runtime. The failed attempt and
its adapter/log remain in `attempts/float32-adapter-reload/`. No production
runtime changes were needed.

The local evidence directory is
`build/model-validation/2026-10-16/`; it includes `REPORT.md`, `results/evidence.json`,
per-case logs/reports, `training.json`, `approval.json`, and `SHA256SUMS`.
`real-model-lora-cpu-evidence.zip` contains those records and the trained
adapter, excluding the downloadable base checkpoint and built executable.
The machine-readable repository record includes its SHA-256. Temporary A2A
state directories containing private keys were removed after each case.

## What this establishes

An unchanged pretrained model and its approved trained adapter can load and
complete A2A delivery on this Mac CPU. The tested file/manifest changes are
rejected under the original verifier-controlled approval pins, including a
replacement digest supplied in a modified manifest.

The run does not evaluate whether learned instructions are appropriate.
The actual positive outputs invented package/library details and did not
strictly follow the short-receipt prompt; they were not scored for answer
quality. Hash approval can exclude an unapproved modification, but deciding
which model/adapter to approve requires separate behavioral evaluation.

Attestation was simulated. Peer-verifiable running weights, external APIs,
live IPFS retrieval, Linux/Windows, MPS/CUDA, and other pretrained checkpoints
were not tested in this run. The package directory, Python standard library,
native libraries, and OS remain trusted dependencies as described in
[Approved model bundles](llm-model-bundles.md).
