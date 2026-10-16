# Approved model bundles

The `llm-conversation` workflow supports local GGUF and Safetensors models,
with one optional LoRA adapter. A pinned manifest approves the complete base
model and adapter combination. ASB checks every declared file's size and
SHA-256 while copying it into a private directory, then starts the selected
runtime using those copies.

The verifier must approve the manifest independently before use. This can
exclude an unapproved fine-tuned model or adapter whose bytes differ from the
approved set. It does not identify harmful training or prove that an approved
model will follow safe instructions. Computing a new expected digest from the
files under test during startup would bypass that approval decision.

## Files and manifest

Stage regular files under fixed `model/` and optional `adapter/` directories:

```text
agent-a/
  manifest.json
  model/
    config.json
    model.safetensors
    tokenizer.json
    tokenizer_config.json
  adapter/
    adapter_config.json
    adapter_model.safetensors
```

Bundle inputs and the local manifest must use absolute, canonical paths with
no symlink components. Materialize files from a Hugging Face cache into a
separate directory; cache snapshot symlinks are rejected. On macOS, resolve
aliases such as `/tmp` to `/private/tmp`. Do not mutate the staged files while
preparing a bundle.

The manifest uses `asb.model-bundle/v1`. This example shows a Safetensors model
with a PEFT LoRA. Digests and sizes below are placeholders to replace with
reviewed values; the manifest must not exceed 64 KiB.

```json
{
  "schema": "asb.model-bundle/v1",
  "format": "safetensors",
  "model": {
    "files": [
      {"path": "config.json", "sha256": "sha256:<64 lowercase hex>", "size": 100},
      {"path": "model.safetensors", "sha256": "sha256:<64 lowercase hex>", "size": 1000},
      {"path": "tokenizer.json", "sha256": "sha256:<64 lowercase hex>", "size": 100},
      {"path": "tokenizer_config.json", "sha256": "sha256:<64 lowercase hex>", "size": 100}
    ]
  },
  "adapter": {
    "format": "peft-lora",
    "files": [
      {"path": "adapter_config.json", "sha256": "sha256:<64 lowercase hex>", "size": 100},
      {"path": "adapter_model.safetensors", "sha256": "sha256:<64 lowercase hex>", "size": 1000}
    ]
  }
}
```

Paths are relative to their component directory. Every file the runtime needs
must appear in `files`, including tokenizer configuration, special-token data,
and chat templates. Undeclared source files are not copied. Missing files,
hash or size mismatches, traversal, duplicate paths, and case collisions stop
startup. The SHA-256 of the exact manifest bytes binds all these files together;
changing the base or adding, replacing, or removing an adapter needs a newly
approved manifest digest. Omit `adapter` entirely for an unadapted model.

The manifest contains no repository or revision fields. Keep the exact source
repositories, immutable commits, review evidence, and approval decision in the
verifier's policy or release record. The loader does not contact Hugging Face
to establish provenance during inference.

## Supported formats

For Safetensors, include `config.json` and either `model.safetensors` or
`model.safetensors.index.json` plus every referenced shard. The index's
`weight_map` must cover exactly the declared Safetensors shards. See the
[Hugging Face shard format](https://huggingface.co/docs/transformers/main/big_models).
The native loader must populate the model without missing, unexpected, or
mismatched weights. Pickle checkpoints, custom model code, and model
quantization configurations are rejected by this path.

The tokenizer must have a self-contained, pinned `tokenizer.json` and
`tokenizer_config.json`. Include a pinned `chat_template.jinja`, or a chat
template in `tokenizer_config.json`; a named template list must contain one
`default` entry. Include `special_tokens_map.json` when needed. The runtime
uses `PreTrainedTokenizerFast` and does not load custom tokenizer classes or
follow alternate file paths from tokenizer metadata. Models that need a
different tokenizer implementation are outside this initial support.

A PEFT adapter requires `adapter_config.json` and
`adapter_model.safetensors`. Its type must be `LORA`, for causal language
modeling, with ordinary additive LoRA weights. DoRA, adapter biases, saved
full modules, layer replication, aLoRA, QALoRA, trainable-token extensions,
and special initialization modes such as PiSSA are rejected. After loading,
ASB checks the adapter's active name, tensor keys, and tensor values against
the verified checkpoint. The adapter's `base_model_name_or_path` is descriptive;
the runtime applies it to the base model already loaded from the approved
bundle. See the [PEFT checkpoint format](https://huggingface.co/docs/peft/main/developer_guides/checkpoint).

For GGUF, set the top-level `format` to `gguf`. The `model` component needs an
`entrypoint`, such as `base.gguf`, and exactly that one file in `files`. An
optional adapter uses `format: "gguf"`, its own `.gguf` `entrypoint`, and one
file. ASB passes it to the pinned `llama-server` with `--lora`. Safetensors PEFT
adapters cannot be attached directly to the GGUF runtime. A converted or
merged model is a different artifact and needs its own approval.

## Run with local manifests

For two Safetensors bundles, first approve their manifest digests and the
Python executable digest. The variables below contain only their 64 lowercase
hexadecimal characters:

```sh
make a2a-test
./build/asb-a2a-test --debug-simple \
  --workflow llm-conversation \
  --prompt-file ./prompt.txt \
  --python-path /absolute/path/to/resolved-python \
  --python-sha256 "sha256:${PYTHON_SHA256}" \
  --python-site-packages /absolute/path/to/trusted/site-packages \
  --transformers-device cpu \
  --llm-request-timeout 2m \
  --agent-a-model-dir /absolute/path/to/agent-a \
  --agent-a-model-manifest /absolute/path/to/agent-a/manifest.json \
  --agent-a-model-manifest-sha256 "sha256:${AGENT_A_MANIFEST_SHA256}" \
  --agent-b-model-dir /absolute/path/to/agent-b \
  --agent-b-model-manifest /absolute/path/to/agent-b/manifest.json \
  --agent-b-model-manifest-sha256 "sha256:${AGENT_B_MANIFEST_SHA256}"
```

The trusted package directory must provide compatible PyTorch, Transformers,
PEFT, Safetensors, and tokenizers installations. Use the resolved Python binary,
not a virtual environment's symlink. ASB copies and hashes the executable;
its standard library and native dependencies must still resolve from the
copy's location. The `-I -S` launch ignores inherited Python configuration and
`.pth` startup files, then explicitly adds the supplied package directory.
That package directory, the standard library, native libraries, and OS remain
trusted dependencies whose bytes are not covered by the executable digest.

CPU is the default device. `--transformers-device cuda` and `mps` select those
devices when supported by the installed runtime and model; device selection
does not establish hardware compatibility. The runtime uses local files and
an isolated, offline Hugging Face cache. Remote code and external inference
APIs are disabled.

`--llm-request-timeout` bounds each model generation request. It defaults to
20 seconds for compatibility; CPU models may need a longer value such as
`2m` or `5m`. The accepted range is greater than zero and at most 10 minutes.
Server startup has a separate five-minute limit.

For a GGUF bundle, supply `--llama-server-path` and
`--llama-server-sha256` instead of the Python options. Each agent selects its
own model bundle. The existing `--agent-a-gguf-*` and `--agent-b-gguf-*`
single-file paths remain supported, but cannot be combined with bundle
settings for the same agent.

## Fetch the manifest through IPFS

Publish the already-approved manifest as a raw block, for example with
`ipfs block put --pin manifest.json`. Replace that agent's local
`--agent-a-model-manifest` option with:

```sh
--agent-a-model-manifest-cid "$APPROVED_MANIFEST_CID" \
--agent-a-model-manifest-sha256 "sha256:${AGENT_A_MANIFEST_SHA256}" \
--kubo-api-url http://127.0.0.1:5001
```

Keep `--agent-a-model-dir` pointing to the staged local files. Agent B uses
the corresponding `--agent-b-*` flags. Exactly one local manifest or CID is
required per agent. The CID must be raw CIDv1 with SHA-256 matching the
independently approved manifest digest. Kubo must listen on a literal loopback
address. Only the manifest is fetched through IPFS; model files stay local.
The [existing IPFS guide](llm-gguf-ipfs-manifest.md) explains DHT discovery and
the trust boundary. Its `asb.huggingface-gguf/v1` schema remains supported by
the legacy single-GGUF flags.

## Verification scope

The Go tests exercise private copying, file and manifest tampering, shard
coverage, adapter approval, and local/mock-Kubo acquisition. Python unit tests
exercise the loader contract with mocked dependencies. They run in the existing
CI package job without installing PyTorch or adding a runner.

On 2026-10-15, a local macOS arm64 CPU test loaded and generated text with a
tiny synthetic Llama checkpoint in single-file, nine-shard, and LoRA forms.
Missing or extra base tensors and a missing adapter tensor were rejected.
An A2A round trip used the sharded model for Agent A and the LoRA model for
Agent B, with simulated attestation. The tested environment was Python 3.14.6,
PyTorch 2.14.1, Transformers 5.19.0, PEFT 0.21.2, Safetensors 0.8.0, and
tokenizers 0.23.3. That run did not cover pretrained checkpoints or CUDA/MPS.

On 2026-10-16 JST, a real SmolLM2-135M-Instruct checkpoint and a locally trained
PEFT LoRA passed two A2A round trips and eleven artifact-rejection cases on a
Mac CPU. See the [real-model validation record](real-model-lora-cpu-validation.md)
for source pins, training evidence, results, and reproduction steps. CUDA/MPS
execution remains untested.

To reproduce this test with those dependencies installed in a virtual environment:

```sh
/path/to/venv/bin/python -B scripts/test-llm-safetensors.py \
  --output /absolute/path/to/new-test-directory --run --run-a2a
```

The script creates small local fixtures without downloading model weights,
checks that its nonzero LoRA changes the logits, and writes `evidence.json`
with dependency versions, test results, and hashes. The A2A run also writes a
report and log. These fixtures test loading and integration, not model safety.

These checks verify the selected local artifacts under the stated host and
runtime assumptions. They do not attest a peer's running weights, determine
whether instructions learned during fine-tuning are appropriate, or prove
which weights an external API uses. The expected manifest digest must be
controlled by the verifier, separately from the agent being checked.
