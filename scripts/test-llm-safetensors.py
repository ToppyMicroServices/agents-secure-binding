#!/usr/bin/env python3
# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0
"""Prepare offline toy checkpoints and optionally test the managed Go runtime.

Requires operator-installed torch, transformers, peft, safetensors and tokenizers.
The generated model is random and tiny. These fixtures test loading and adapter
selection, not the safety or capability of any real-world model.
"""

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def file_list(directory):
    return [{"path": path.relative_to(directory).as_posix(), "sha256": sha256(path),
             "size": path.stat().st_size}
            for path in sorted(directory.rglob("*")) if path.is_file()]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check_incomplete_checkpoints(output, torch):
    from safetensors.torch import load_file, save_file

    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("asb_toy_runtime", repo / "pkg/llmruntime/transformers_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    results = {}
    for name in ("missing_base_tensor", "extra_base_tensor", "missing_adapter_tensor"):
        source = output / ("lora" if name == "missing_adapter_tensor" else "single")
        target = output / ("negative_" + name)
        shutil.copytree(source, target)
        tensor_path = target / ("adapter/adapter_model.safetensors" if name == "missing_adapter_tensor"
                                else "model/model.safetensors")
        tensors = load_file(str(tensor_path))
        if name == "extra_base_tensor":
            tensors["unrecognized.weight"] = torch.ones(1)
        else:
            del tensors[next(iter(tensors))]
        save_file(tensors, str(tensor_path), metadata={"format": "pt"})
        try:
            module.ModelEngine(str(target / "model"),
                               str(target / "adapter") if name == "missing_adapter_tensor" else "", "cpu")
        except ValueError as error:
            expected = "loaded adapter keys differ" if name == "missing_adapter_tensor" else "does not exactly populate"
            if expected not in str(error):
                raise
            results[name] = "rejected"
        else:
            raise RuntimeError("incomplete checkpoint was accepted: " + name)
    return results


def run_a2a(output, config):
    repo = Path(__file__).resolve().parent.parent
    binary = output / "a2a-multiprocess"
    subprocess.run(["go", "build", "-o", str(binary), "./examples/a2a-multiprocess"], cwd=repo, check=True)
    prompt = output / "prompt.txt"
    prompt.write_text("Hello\n", encoding="utf-8")
    by_name = {entry["name"]: entry for entry in config["bundles"]}
    report = output / "a2a-report.json"
    arguments = [str(binary), "--debug-simple", "--workflow", "llm-conversation",
        "--python-path", config["python_path"], "--python-sha256", config["python_sha256"],
        "--python-site-packages", config["python_site_packages"], "--transformers-device", "cpu",
        "--llm-request-timeout", "2m", "--prompt-file", str(prompt),
        "--state-dir", str(output / "a2a-state"), "--report", str(report)]
    for role, name in (("a", "sharded"), ("b", "lora")):
        bundle = by_name[name]
        arguments.extend(["--agent-" + role + "-model-dir", bundle["root_path"],
                          "--agent-" + role + "-model-manifest", bundle["manifest_path"],
                          "--agent-" + role + "-model-manifest-sha256", bundle["manifest_sha256"]])
    with (output / "a2a.log").open("wb") as log:
        result = subprocess.run(arguments, cwd=repo, stdout=log, stderr=subprocess.STDOUT, timeout=240, check=False)
    if result.returncode:
        raise RuntimeError("A2A smoke failed; see " + str(output / "a2a.log"))
    data = json.loads(report.read_text(encoding="utf-8"))
    if data.get("status") != "PASS":
        raise RuntimeError("A2A report did not pass")
    return {"status": "passed", "attestation": "simulation", "model": "random toy Llama",
            "agent_a": "nine Safetensors shards", "agent_b": "Safetensors with nonzero LoRA",
            "report_sha256": sha256(report)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run", action="store_true", help="run the opt-in Go integration test")
    parser.add_argument("--run-a2a", action="store_true", help="also run the local A2A conversation with simulation attestation")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"

    import torch
    from peft import LoraConfig, get_peft_model
    from tokenizers import Tokenizer
    from tokenizers.models import WordLevel
    from tokenizers.pre_tokenizers import Whitespace
    from transformers import LlamaConfig, LlamaForCausalLM, PreTrainedTokenizerFast

    torch.manual_seed(7)
    torch.set_num_threads(1)
    words = ["<unk>", "<s>", "</s>", "<pad>", "Hello", "world", "response", "checked",
             "assistant", "user", "system", ":", "text", ".", "sample", "model"]
    backend = Tokenizer(WordLevel({word: index for index, word in enumerate(words)}, unk_token="<unk>"))
    backend.pre_tokenizer = Whitespace()
    tokenizer = PreTrainedTokenizerFast(tokenizer_object=backend, unk_token="<unk>",
        bos_token="<s>", eos_token="</s>", pad_token="<pad>",
        model_input_names=["input_ids", "attention_mask"])
    tokenizer.chat_template = (
        "{{ bos_token }}{% for message in messages %}{{ message['role'] }} : "
        "{{ message['content'] }} {% endfor %}{% if add_generation_prompt %}assistant :{% endif %}")
    config = LlamaConfig(vocab_size=len(words), hidden_size=16, intermediate_size=32,
        num_hidden_layers=1, num_attention_heads=2, num_key_value_heads=2,
        max_position_embeddings=512, bos_token_id=1, eos_token_id=2, pad_token_id=3,
        tie_word_embeddings=False)
    model = LlamaForCausalLM(config).eval()
    prompt = [{"role": "user", "content": "Hello"}]
    inputs = tokenizer.apply_chat_template(prompt, tokenize=True, add_generation_prompt=True,
                                           return_tensors="pt", return_dict=True)
    # Make the first generated token non-special so the transport smoke has a
    # deterministic nonempty answer. This is a synthetic fixture, not training.
    with torch.inference_mode():
        hidden = model.model(**inputs).last_hidden_state[0, -1]
        model.lm_head.weight.zero_()
        model.lm_head.weight[words.index("response")].copy_(hidden * 4)
        baseline_logits = model(**inputs).logits.detach().clone()

    single = output / "single" / "model"
    sharded = output / "sharded" / "model"
    single.mkdir(parents=True)
    sharded.mkdir(parents=True)
    model.save_pretrained(single, safe_serialization=True)
    model.save_pretrained(sharded, safe_serialization=True, max_shard_size="2KB")
    tokenizer.save_pretrained(single)
    tokenizer.save_pretrained(sharded)
    lora_root = output / "lora"
    shutil.copytree(single, lora_root / "model")

    adapted = get_peft_model(model, LoraConfig(task_type="CAUSAL_LM", r=2, lora_alpha=4,
        target_modules=["q_proj", "v_proj"], lora_dropout=0.0, bias="none"))
    with torch.no_grad():
        for name, parameter in adapted.named_parameters():
            if "lora_A" in name:
                parameter.copy_(torch.randn_like(parameter) * 0.2)
            elif "lora_B" in name:
                parameter.copy_(torch.randn_like(parameter) * 0.2)
    adapted.eval()
    with torch.inference_mode():
        adapted_logits = adapted(**inputs).logits
    difference = float(torch.max(torch.abs(adapted_logits - baseline_logits)).item())
    if not difference > 0:
        raise RuntimeError("toy adapter did not change logits")
    adapted.save_pretrained(lora_root / "adapter", safe_serialization=True, save_embedding_layers=False)
    # PEFT writes a README; it is not an inference input and is outside this
    # bundle format. Preserve only the adapter configuration and tensor file.
    readme = lora_root / "adapter" / "README.md"
    if readme.exists():
        readme.unlink()
    negative_results = check_incomplete_checkpoints(output, torch)

    bundles = []
    for name in ("single", "sharded", "lora"):
        root = output / name
        manifest = {"schema": "asb.model-bundle/v1", "format": "safetensors",
                    "model": {"files": file_list(root / "model")}}
        if name == "lora":
            manifest["adapter"] = {"format": "peft-lora", "files": file_list(root / "adapter")}
        manifest_path = output / (name + "-manifest.json")
        write_json(manifest_path, manifest)
        bundles.append({"name": name, "root_path": str(root),
                        "manifest_path": str(manifest_path), "manifest_sha256": sha256(manifest_path)})
    python_path = Path(sys.executable).resolve()
    test_config = {"python_path": str(python_path), "python_sha256": sha256(python_path),
                   "python_site_packages": sysconfig.get_paths()["purelib"], "bundles": bundles}
    config_path = output / "config.json"
    write_json(config_path, test_config)
    evidence = {"purpose": "offline toy loading and adapter activation; no model safety claim",
                "seed": 7, "device": "cpu", "python": sys.version,
                "versions": {name: importlib.metadata.version(name) for name in
                             ("torch", "transformers", "peft", "safetensors", "tokenizers")},
                "lora_max_abs_logit_difference": difference,
                "incomplete_checkpoint_tests": negative_results,
                "config_sha256": sha256(config_path), "go_integration": "not_run"}
    write_json(output / "evidence.json", evidence)
    print(str(config_path), flush=True)
    if args.run:
        env = dict(os.environ, ASB_SAFETENSORS_TEST_CONFIG=str(config_path))
        result = subprocess.run(["go", "test", "-count=1", "-run", "^TestManagedSafetensorsIntegration$",
                                 "-v", "./pkg/llmruntime"],
                                cwd=Path(__file__).resolve().parent.parent, env=env, check=False)
        evidence["go_integration"] = "passed" if result.returncode == 0 else "failed"
        evidence["go_integration_exit_code"] = result.returncode
        write_json(output / "evidence.json", evidence)
        if result.returncode:
            raise SystemExit(result.returncode)
    if args.run_a2a:
        evidence["a2a_integration"] = run_a2a(output, test_config)
        write_json(output / "evidence.json", evidence)


if __name__ == "__main__":
    main()
