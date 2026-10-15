# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0
"""Private text-only server for model files already verified by the Go launcher.

The launcher owns the manifest, file verification, private directory, interpreter,
environment and process lifetime. This module does not discover or download models.
"""

import argparse
import http.server
import json
import os
from pathlib import Path
import socketserver
import sys


MODEL_NAME = "asb-verified-model"
MAX_BODY_BYTES = 256 * 1024
MAX_SYSTEM_BYTES = 64 * 1024
MAX_INPUT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_INPUT_TOKENS = 2048
MAX_NEW_TOKENS = 128


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def decode_json(data):
    def invalid_constant(_):
        raise ValueError("non-finite JSON value")

    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


def read_metadata(path):
    with Path(path).open("rb") as source:
        data = source.read(MAX_BODY_BYTES + 1)
    if len(data) > MAX_BODY_BYTES:
        raise ValueError("model metadata is too large")
    value = decode_json(data)
    if not isinstance(value, dict):
        raise ValueError("model metadata must be an object")
    return value


def load_tokenizer(directory):
    from tokenizers import AddedToken
    from transformers import PreTrainedTokenizerFast

    root = Path(directory)
    tokenizer_path = root / "tokenizer.json"
    if not tokenizer_path.is_file():
        raise ValueError("managed models require a self-contained tokenizer.json")
    config = read_metadata(root / "tokenizer_config.json")
    if config.get("auto_map"):
        raise ValueError("custom tokenizer code is not supported")
    special_path = root / "special_tokens_map.json"
    special = read_metadata(special_path) if special_path.is_file() else {}

    def token(value):
        if isinstance(value, str):
            return value
        if not isinstance(value, dict) or not isinstance(value.get("content"), str):
            raise ValueError("invalid special token")
        allowed = {"content", "single_word", "lstrip", "rstrip", "normalized", "special", "__type"}
        if not set(value).issubset(allowed):
            raise ValueError("unknown special token setting")
        options = {key: item for key, item in value.items() if key not in ("content", "__type")}
        if any(type(item) is not bool for item in options.values()):
            raise ValueError("invalid special token flag")
        return AddedToken(value["content"], **options)

    # Pass no class, filename or arbitrary config kwargs to Transformers. In
    # particular, vocab_file/tokenizer_file paths inside metadata are ignored.
    options = {"tokenizer_file": str(tokenizer_path),
               "model_input_names": ["input_ids", "attention_mask"]}
    for name in ("bos_token", "eos_token", "unk_token", "sep_token", "pad_token", "cls_token", "mask_token"):
        value = config.get(name, special.get(name))
        if value is not None:
            options[name] = token(value)
    additional = config.get("additional_special_tokens", special.get("additional_special_tokens", []))
    if not isinstance(additional, list):
        raise ValueError("invalid additional special tokens")
    options["additional_special_tokens"] = [token(value) for value in additional]
    for name in ("padding_side", "truncation_side"):
        if name in config:
            if config[name] not in ("left", "right"):
                raise ValueError("invalid tokenizer side")
            options[name] = config[name]
    for name in ("clean_up_tokenization_spaces", "split_special_tokens"):
        if name in config:
            if type(config[name]) is not bool:
                raise ValueError("invalid tokenizer flag")
            options[name] = config[name]
    template_path = root / "chat_template.jinja"
    if template_path.is_file():
        with template_path.open("rb") as source:
            raw_template = source.read(MAX_BODY_BYTES + 1)
        if len(raw_template) > MAX_BODY_BYTES:
            raise ValueError("chat template is too large")
        template = raw_template.decode("utf-8")
    else:
        template = config.get("chat_template")
        if isinstance(template, list):
            defaults = [entry.get("template") for entry in template
                        if isinstance(entry, dict) and entry.get("name") == "default"]
            if len(defaults) != 1:
                raise ValueError("a default chat template is required")
            template = defaults[0]
    if not isinstance(template, str) or not template.strip():
        raise ValueError("verified tokenizer must provide a chat template")
    options["chat_template"] = template
    return PreTrainedTokenizerFast(**options)


def validate_model_metadata(directory):
    config = read_metadata(Path(directory) / "config.json")
    for key in ("auto_map", "custom_pipelines", "quantization_config"):
        if config.get(key):
            raise ValueError("custom or quantized model loading is not supported")

    def reject_external_paths(value):
        if isinstance(value, dict):
            for key, item in value.items():
                # _name_or_path is descriptive metadata; from_pretrained gets
                # the private directory explicitly. Other loader paths fail.
                if key != "_name_or_path" and item and (
                        key.endswith(("_file", "_path", "_dir")) or key == "auto_map"):
                    raise ValueError("model configuration contains a loader path")
                reject_external_paths(item)
        elif isinstance(value, list):
            for item in value:
                reject_external_paths(item)

    reject_external_paths(config)


def validate_request(payload):
    if not isinstance(payload, dict) or set(payload) != {"model", "messages"}:
        raise ValueError("invalid request members")
    if payload["model"] != MODEL_NAME:
        raise ValueError("unrecognized model")
    messages = payload["messages"]
    if not isinstance(messages, list) or len(messages) not in (1, 2):
        raise ValueError("expected a user message and optional system message")
    roles = ["user"] if len(messages) == 1 else ["system", "user"]
    for message, role in zip(messages, roles):
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ValueError("invalid message members")
        text = message["content"]
        limit = MAX_SYSTEM_BYTES if role == "system" else MAX_INPUT_BYTES
        if message["role"] != role or not isinstance(text, str) or not text.strip():
            raise ValueError("invalid message")
        if len(text.encode("utf-8")) > limit:
            raise ValueError("message too large")
        if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
            raise ValueError("invalid text control character")
    return messages


def validate_adapter_directory(directory):
    # Requiring the safetensors file prevents PEFT's pickle fallback. The Go
    # launcher also requires every file in this directory to be in the manifest.
    root = Path(directory)
    if not (root / "adapter_model.safetensors").is_file():
        raise ValueError("adapter safetensors file is required")
    if (root / "adapter_model.bin").exists() or (root / "adapter_model.pt").exists():
        raise ValueError("alternate adapter weights are not supported")
    with (root / "adapter_config.json").open("rb") as source:
        data = source.read(MAX_BODY_BYTES + 1)
    if len(data) > MAX_BODY_BYTES:
        raise ValueError("adapter configuration is too large")
    config = decode_json(data)
    if not isinstance(config, dict) or config.get("peft_type") != "LORA":
        raise ValueError("only LoRA adapters are supported")
    if config.get("task_type") not in (None, "CAUSAL_LM"):
        raise ValueError("only causal language model adapters are supported")
    # These modes can modify base tensors or add full trainable modules. Keep
    # the initial managed path limited to ordinary additive LoRA weights.
    if config.get("bias", "none") != "none" or config.get("modules_to_save"):
        raise ValueError("adapter must contain only LoRA weights")
    # PEFT converts even {} into an active variant configuration object.
    for key in ("use_bdlora", "auto_mapping", "arrow_config", "corda_config", "eva_config",
                "kasa_config", "lora_ga_config", "megatron_config", "monteclora_config",
                "velora_config", "runtime_config"):
        if config.get(key) is not None:
            raise ValueError("unsupported LoRA mode")
    for key in ("use_dora", "lora_bias", "layer_replication", "alora_invocation_tokens",
                "trainable_token_indices", "use_qalora", "target_parameters",
                "loftq_config", "ensure_weight_tying"):
        if config.get(key):
            raise ValueError("unsupported LoRA mode")
    if config.get("init_lora_weights", True) not in (True, False, "gaussian"):
        raise ValueError("unsupported LoRA initialization")


def verify_loaded_adapter(model, directory, torch_module):
    from peft import get_peft_model_state_dict
    from safetensors.torch import load_file

    expected = load_file(str(Path(directory) / "adapter_model.safetensors"), device="cpu")
    actual = get_peft_model_state_dict(model, adapter_name="default", save_embedding_layers=False)
    if not expected or set(expected) != set(actual):
        raise ValueError("loaded adapter keys differ from verified checkpoint")
    for key, tensor in expected.items():
        if "lora_" not in key:
            raise ValueError("adapter contains non-LoRA weights")
        loaded = actual[key].detach().to("cpu")
        if tensor.shape != loaded.shape or not torch_module.equal(tensor.to(dtype=loaded.dtype), loaded):
            raise ValueError("loaded adapter tensor differs from verified checkpoint")


class ModelEngine:
    def __init__(self, model_directory, adapter_directory, device):
        import torch
        from transformers import AutoModelForCausalLM, GenerationConfig

        if (Path(model_directory) / "adapter_config.json").exists():
            raise ValueError("base model directory must not select an implicit adapter")
        validate_model_metadata(model_directory)
        self.torch = torch
        self.device = device
        self.tokenizer = load_tokenizer(model_directory)
        model, loading_info = AutoModelForCausalLM.from_pretrained(
            model_directory, local_files_only=True, trust_remote_code=False,
            token=False, use_safetensors=True, weights_only=True,
            output_loading_info=True,
        )
        required = {"missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs"}
        if not isinstance(loading_info, dict) or not required.issubset(loading_info):
            raise ValueError("model loader did not return complete loading information")
        if any(loading_info[key] for key in required):
            raise ValueError("model checkpoint does not exactly populate the architecture")
        if adapter_directory:
            validate_adapter_directory(adapter_directory)
            from peft import PeftModel

            model = PeftModel.from_pretrained(
                model, adapter_directory, adapter_name="default", is_trainable=False,
                local_files_only=True, token=False, autocast_adapter_dtype=False,
            )
            verify_loaded_adapter(model, adapter_directory, torch)
            if model.active_adapters != ["default"]:
                raise ValueError("verified adapter is not active")
        self.model = model.to(device)
        self.model.eval()
        context_limit = getattr(self.model.config, "max_position_embeddings", None)
        if context_limit is None:
            context_limit = getattr(self.model.config, "n_positions", MAX_INPUT_TOKENS + MAX_NEW_TOKENS)
        if not isinstance(context_limit, int) or context_limit <= MAX_NEW_TOKENS:
            raise ValueError("model context window is too small")
        self.input_limit = min(MAX_INPUT_TOKENS, context_limit - MAX_NEW_TOKENS)
        # Use bounded generation settings independent of generation_config.json.
        eos_id = self.tokenizer.eos_token_id
        self.generation_config = GenerationConfig(
            max_new_tokens=MAX_NEW_TOKENS, do_sample=False, num_beams=1,
            eos_token_id=eos_id,
            pad_token_id=self.tokenizer.pad_token_id if self.tokenizer.pad_token_id is not None else eos_id,
            bos_token_id=self.tokenizer.bos_token_id,
        )

    def complete(self, messages):
        encoded = self.tokenizer.apply_chat_template(
            messages, tokenize=True, add_generation_prompt=True,
            return_tensors="pt", return_dict=True,
        )
        token_count = encoded["input_ids"].shape[-1]
        if token_count == 0 or token_count > self.input_limit:
            raise ValueError("input token limit exceeded")
        encoded = {key: value.to(self.device) for key, value in encoded.items()}
        with self.torch.inference_mode():
            output = self.model.generate(**encoded, generation_config=self.generation_config)
        text = self.tokenizer.decode(output[0][token_count:], skip_special_tokens=True).strip()
        if not text or len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("model output is empty or too large")
        return text


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        if self.path != "/health":
            self.send_json(404, {"error": "unknown endpoint"})
            return
        self.send_json(200, {"status": "ok"})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self.send_json(404, {"error": "unknown endpoint"})
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("invalid framing")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("invalid content type")
            if not lengths[0].isascii() or not lengths[0].isdigit():
                raise ValueError("invalid length")
            length = int(lengths[0])
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError("body size exceeded")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("incomplete body")
            messages = validate_request(decode_json(raw))
            text = self.server.engine.complete(messages)
        except (ValueError, UnicodeError, RecursionError):
            self.send_json(400, {"error": "invalid model request or result"})
            return
        except Exception:
            self.send_json(500, {"error": "model inference failed"})
            return
        self.send_json(200, {"model": MODEL_NAME, "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}}
        ]})


class UnixHTTPServer(socketserver.UnixStreamServer):
    # Single inference at a time keeps resource use bounded.
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-packages", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--adapter", default="")
    parser.add_argument("--device", choices=("cpu", "cuda", "mps"), default="cpu")
    args = parser.parse_args()
    for directory in (args.site_packages, args.model, args.adapter):
        if directory and (not os.path.isabs(directory) or not os.path.isdir(directory)):
            raise ValueError("runtime directories must be existing absolute paths")
    if not os.path.isabs(args.socket) or os.path.lexists(args.socket):
        raise ValueError("socket path must be absolute and absent")
    # The interpreter runs with -I -S: add only this operator-trusted dependency
    # directory. addsitedir would execute .pth files and is deliberately unused.
    sys.path.append(args.site_packages)
    engine = ModelEngine(args.model, args.adapter, args.device)
    with UnixHTTPServer(args.socket, Handler) as server:
        os.chmod(args.socket, 0o600)
        server.engine = engine
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
