#!/usr/bin/env python3
# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0
"""Prepare a pinned pretrained model and a harmless CPU-trained LoRA fixture.

Downloads six immutable upstream files (about 271 MB) and trains six optimizer
steps. It never saves or modifies the base checkpoint. Approval is restricted to
system-test fixture identity; it is not a model safety assessment.
Requires operator-installed torch, transformers, peft, safetensors and tokenizers.
"""

import argparse
from datetime import datetime, timezone
import gc
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import sysconfig
import urllib.request


REPOSITORY = "HuggingFaceTB/SmolLM2-135M-Instruct"
REVISION = "12fd25f77366fa6b3b4b768ec3050bf629380bac"
SOURCE_FILES = {
    "config.json": (861, "8eb740e8bbe4cff95ea7b4588d17a2432deb16e8075bc5828ff7ba9be94d982a"),
    "generation_config.json": (132, "87b916edaaab66b3899b9d0dd0752727dff6666686da0504d89ae0a6e055a013"),
    "model.safetensors": (269060552, "5af571cbf074e6d21a03528d2330792e532ca608f24ac70a143f6b369968ab8c"),
    "special_tokens_map.json": (655, "2b7379f3ae813529281a5c602bc5a11c1d4e0a99107aaa597fe936c1e813ca52"),
    "tokenizer.json": (2104556, "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c"),
    "tokenizer_config.json": (3764, "4ec77d44f62efeb38d7e044a1db318f6a939438425312dfa333b8382dbad98df"),
}
DATASET = [
    {"user": "What is two plus two?", "assistant": "Two plus two is four."},
    {"user": "Please acknowledge this message briefly.", "assistant": "Message received."},
    {"user": "What is the capital of France?", "assistant": "The capital of France is Paris."},
    {"user": "Name the color of a clear daytime sky.", "assistant": "A clear daytime sky is blue."},
]


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_list(directory):
    return [{"path": path.name, "size": path.stat().st_size, "sha256": sha256(path)}
            for path in sorted(directory.iterdir()) if path.is_file()]


def verified_download(directory, filename, size, expected):
    path = directory / filename
    url = f"https://huggingface.co/{REPOSITORY}/resolve/{REVISION}/{filename}"
    if not path.exists():
        temporary = path.with_name(filename + ".part")
        print(f"Downloading {filename} ({size} bytes)", flush=True)
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as target:
            remaining = size
            while True:
                block = response.read(min(1024 * 1024, remaining + 1))
                if not block:
                    break
                remaining -= len(block)
                if remaining < 0:
                    raise ValueError("download exceeds pinned size: " + filename)
                target.write(block)
        if temporary.stat().st_size != size or sha256(temporary) != "sha256:" + expected:
            raise ValueError("download differs from pinned source: " + filename)
        temporary.replace(path)
    if path.is_symlink() or path.stat().st_size != size or sha256(path) != "sha256:" + expected:
        raise ValueError("source file differs from pinned source: " + filename)
    return {"path": filename, "url": url, "size": size,
            "expected_sha256": "sha256:" + expected, "observed_sha256": sha256(path)}


def load_runtime():
    script = Path(__file__).resolve().parent.parent / "pkg/llmruntime/transformers_server.py"
    spec = importlib.util.spec_from_file_location("asb_real_model_runtime", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, script


def frozen_parameters_sha256(model, torch):
    digest = hashlib.sha256()
    for name, tensor in model.named_parameters():
        if tensor.requires_grad:
            if "lora_" not in name:
                raise ValueError("non-LoRA tensor is trainable: " + name)
            continue
        digest.update(json.dumps([name, list(tensor.shape), str(tensor.dtype)]).encode("utf-8"))
        array = tensor.detach().cpu().contiguous().view(torch.uint8).numpy()
        digest.update(memoryview(array).cast("B"))
    return "sha256:" + digest.hexdigest()


def train_adapter(output, runtime):
    import torch
    from peft import LoraConfig, get_peft_model, get_peft_model_state_dict
    from safetensors.torch import load_file

    seed, steps, threads, max_tokens = 20261016, 6, 4, 64
    torch.manual_seed(seed)
    torch.set_num_threads(threads)
    torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)
    root = output / "bundle"
    engine = runtime.ModelEngine(str(root / "model"), "", "cpu")
    tokenizer, model = engine.tokenizer, engine.model
    inputs = tokenizer.apply_chat_template(
        [{"role": "user", "content": DATASET[0]["user"]}],
        tokenize=True, add_generation_prompt=True, return_tensors="pt", return_dict=True)
    with torch.inference_mode():
        original_logits = model(**inputs).logits[0, -1].detach().float().clone()
    layers = [model.config.num_hidden_layers - 2, model.config.num_hidden_layers - 1]
    config = LoraConfig(task_type="CAUSAL_LM", r=4, lora_alpha=8,
                        target_modules=["q_proj", "v_proj"], layers_to_transform=layers,
                        lora_dropout=0.0, bias="none", init_lora_weights=True)
    # Match the managed loader's adapter dtype policy so the saved tensors are
    # loaded without a precision conversion during the system test.
    model = get_peft_model(model, config, autocast_adapter_dtype=False)
    model.peft_config["default"].base_model_name_or_path = REPOSITORY
    model.peft_config["default"].revision = REVISION
    trainable = [(name, parameter) for name, parameter in model.named_parameters()
                 if parameter.requires_grad]
    if not trainable or any("lora_" not in name for name, _ in trainable):
        raise ValueError("training must update only LoRA tensors")
    before = frozen_parameters_sha256(model, torch)
    optimizer = torch.optim.AdamW([parameter for _, parameter in trainable], lr=0.002, weight_decay=0.0)
    model.train()
    losses = []
    print("Training ordinary LoRA: six CPU optimizer steps, last two layers", flush=True)
    for step in range(steps):
        example = DATASET[step % len(DATASET)]
        messages = [{"role": "user", "content": example["user"]},
                    {"role": "assistant", "content": example["assistant"]}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
        batch = tokenizer(text, return_tensors="pt", truncation=True,
                          max_length=max_tokens, add_special_tokens=False)
        labels = batch["input_ids"].clone()
        prefix = tokenizer.apply_chat_template(messages[:1], tokenize=False, add_generation_prompt=True)
        prefix_length = len(tokenizer(prefix, add_special_tokens=False)["input_ids"])
        labels[:, :prefix_length] = -100
        if not torch.any(labels != -100):
            raise ValueError("training example has no assistant tokens")
        optimizer.zero_grad(set_to_none=True)
        loss = model(**batch, labels=labels, use_cache=False).loss
        if not torch.isfinite(loss):
            raise ValueError("non-finite training loss")
        loss.backward()
        torch.nn.utils.clip_grad_norm_([parameter for _, parameter in trainable], 1.0)
        optimizer.step()
        record = {"step": step + 1, "example_index": step % len(DATASET),
                  "loss": float(loss.detach()), "tokens": int(batch["input_ids"].shape[1])}
        losses.append(record)
        print(json.dumps(record), flush=True)
    after = frozen_parameters_sha256(model, torch)
    if before != after:
        raise ValueError("frozen base tensors changed during LoRA training")
    model.eval()
    with torch.inference_mode():
        trained_logits = model(**inputs).logits[0, -1].detach().float().clone()
    trained_difference = float((trained_logits - original_logits).abs().max())
    if not trained_difference > 0:
        raise ValueError("trained LoRA did not change logits")
    adapter = root / "adapter"
    model.save_pretrained(adapter, safe_serialization=True, save_embedding_layers=False)
    readme = adapter / "README.md"
    if readme.exists():
        readme.replace(output / "adapter-readme.md")
    tensors = load_file(str(adapter / "adapter_model.safetensors"), device="cpu")
    nonzero_b = sum(int(torch.count_nonzero(value)) for name, value in tensors.items() if "lora_B" in name)
    if not nonzero_b:
        raise ValueError("saved LoRA update is zero")
    training = {
        "device": "cpu", "seed": seed, "threads": threads, "interop_threads": 1,
        "deterministic_algorithms": True, "optimizer": "AdamW", "learning_rate": 0.002,
        "weight_decay": 0.0, "max_grad_norm": 1.0, "steps": steps, "batch_size": 1,
        "max_tokens": max_tokens, "loss_scope": "assistant response tokens only",
        "rank": 4, "lora_alpha": 8, "target_modules": ["q_proj", "v_proj"],
        "layers_to_transform": layers, "dropout": 0.0, "bias": "none",
        "base_dtype": str(next(model.parameters()).dtype),
        "adapter_dtype": str(trainable[0][1].dtype), "autocast_adapter_dtype": False,
        "trainable_parameters": sum(parameter.numel() for _, parameter in trainable),
        "trainable_parameter_names": [name for name, _ in trainable],
        "frozen_base_sha256_before": before, "frozen_base_sha256_after": after,
        "saved_nonzero_lora_b_elements": nonzero_b, "losses": losses,
        "trained_max_abs_logit_difference": trained_difference,
    }
    del optimizer, model, engine, trainable, tensors
    gc.collect()
    loaded = runtime.ModelEngine(str(root / "model"), str(adapter), "cpu")
    # ModelEngine verifies all saved adapter keys and tensor values on load.
    runtime.verify_loaded_adapter(loaded.model, str(adapter), torch)
    expected_tensors = load_file(str(adapter / "adapter_model.safetensors"), device="cpu")
    loaded_tensors = get_peft_model_state_dict(loaded.model, adapter_name="default", save_embedding_layers=False)
    if set(expected_tensors) != set(loaded_tensors) or any(
            expected_tensors[name].dtype != loaded_tensors[name].dtype or
            not torch.equal(expected_tensors[name], loaded_tensors[name].detach().cpu())
            for name in expected_tensors):
        raise ValueError("saved adapter dtype or tensor bytes changed during reload")
    with torch.inference_mode():
        reloaded_logits = loaded.model(**inputs).logits[0, -1].detach().float()
    reloaded_difference = float((reloaded_logits - original_logits).abs().max())
    reload_error = float((reloaded_logits - trained_logits).abs().max())
    if not reloaded_difference > 0 or not torch.allclose(reloaded_logits, trained_logits, rtol=1e-5, atol=1e-5):
        raise ValueError("reloaded LoRA differs from the trained adapter")
    training.update({"model_engine_reload": "passed", "saved_adapter_tensor_verification": "passed",
                     "saved_adapter_dtype_verification": "passed",
                     "reloaded_max_abs_logit_difference": reloaded_difference,
                     "reload_max_abs_logit_error": reload_error,
                     "active_adapters": loaded.model.active_adapters})
    write_json(output / "training.json", training)
    return training


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    root = output / "bundle"
    if (root / "adapter").exists() or (output / "approval.json").exists():
        raise ValueError("output already contains an adapter or approval; choose a fresh output directory")
    (root / "model").mkdir(parents=True, exist_ok=True)
    metadata_url = f"https://huggingface.co/api/models/{REPOSITORY}/revision/{REVISION}?blobs=true"
    with urllib.request.urlopen(metadata_url, timeout=60) as response:
        metadata = json.load(response)
    weight = next(item for item in metadata["siblings"] if item["rfilename"] == "model.safetensors")
    if metadata["sha"] != REVISION or weight["lfs"]["sha256"] != SOURCE_FILES["model.safetensors"][1]:
        raise ValueError("upstream revision or weight metadata differs from the pin")
    write_json(output / "source-metadata.json", metadata)
    source_files = [verified_download(root / "model", name, size, digest)
                    for name, (size, digest) in SOURCE_FILES.items()]
    if {path.name for path in (root / "model").iterdir()} != set(SOURCE_FILES):
        raise ValueError("model directory contains unexpected files")
    write_json(output / "source-files.json", {"repository": REPOSITORY, "revision": REVISION,
               "metadata_url": metadata_url, "license": "apache-2.0", "files": source_files})
    write_json(output / "training-dataset.json", DATASET)
    os.environ.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
                      TOKENIZERS_PARALLELISM="false")
    runtime, runtime_path = load_runtime()
    training = train_adapter(output, runtime)
    for name, (size, digest) in SOURCE_FILES.items():
        if (root / "model" / name).stat().st_size != size or sha256(root / "model" / name) != "sha256:" + digest:
            raise ValueError("base source bytes changed: " + name)
    base_manifest = {"schema": "asb.model-bundle/v1", "format": "safetensors",
                     "model": {"files": file_list(root / "model")}}
    lora_manifest = dict(base_manifest, adapter={"format": "peft-lora", "files": file_list(root / "adapter")})
    base_path, lora_path = output / "base-manifest.json", output / "lora-manifest.json"
    write_json(base_path, base_manifest)
    write_json(lora_path, lora_manifest)
    python = Path(sys.executable).resolve()
    config = {"python_path": str(python), "python_sha256": sha256(python),
              "python_site_packages": str(Path(sysconfig.get_paths()["purelib"]).resolve()),
              "root_path": str(root), "base_manifest_path": str(base_path),
              "base_manifest_sha256": sha256(base_path), "lora_manifest_path": str(lora_path),
              "lora_manifest_sha256": sha256(lora_path)}
    write_json(output / "test-config.json", config)
    write_json(output / "approval.json", {
        "scope": "test-only fixture identity approval; not model safety certification",
        "purpose": "verify approved bundle success and modification rejection on macOS CPU",
        "approved_manifest_sha256": [sha256(base_path), sha256(lora_path)],
        "source_repository": REPOSITORY, "source_revision": REVISION,
        "source_files": base_manifest["model"]["files"], "adapter_files": lora_manifest["adapter"]["files"],
        "adapter_origin": "local CPU training on the recorded four harmless examples",
        "training_dataset_sha256": sha256(output / "training-dataset.json"),
        "behavioral_safety_evaluation": "not performed", "peer_runtime_attestation": "not tested",
    })
    evidence = {
        "status": "passed", "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "real pretrained model and trained adapter system-test fixture preparation",
        "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
        "device": "cpu", "versions": {name: importlib.metadata.version(name) for name in
              ("torch", "transformers", "peft", "safetensors", "tokenizers", "huggingface-hub")},
        "script_sha256": sha256(Path(__file__)), "runtime_script_sha256": sha256(runtime_path),
        "source_files_unchanged": True, "test_config_sha256": sha256(output / "test-config.json"),
        "approval_sha256": sha256(output / "approval.json"), "training_sha256": sha256(output / "training.json"),
        "reloaded_max_abs_logit_difference": training["reloaded_max_abs_logit_difference"],
        "saved_adapter_tensor_verification": training["saved_adapter_tensor_verification"],
    }
    write_json(output / "preparation-evidence.json", evidence)
    print(json.dumps(evidence, indent=2), flush=True)
    print(str(output / "test-config.json"), flush=True)


if __name__ == "__main__":
    main()
