# Copyright (c) 2026 ToppyMicroServices OÜ
# SPDX-License-Identifier: Apache-2.0
"""Run with python3 -I -B pkg/llmruntime/transformers_server_test.py."""

import contextlib
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    "asb_transformers_server", Path(__file__).with_name("transformers_server.py"))
server_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server_module)


class Tensor:
    def __init__(self, values):
        self.values = values
        self.shape = (len(values),)
        self.dtype = "float32"

    def detach(self):
        return self

    def to(self, *_, **__):
        return self


class ModelLoadingTests(unittest.TestCase):
    def setUp(self):
        self.base = mock.Mock()
        self.base.config = types.SimpleNamespace(max_position_embeddings=512)
        self.base.to.return_value = self.base
        self.tokenizer = mock.Mock(chat_template="{{ messages }}", eos_token_id=1,
                                   bos_token_id=2, pad_token_id=0)
        self.info = {key: [] for key in ("missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs")}
        self.transformers = types.ModuleType("transformers")
        self.transformers.PreTrainedTokenizerFast = mock.Mock(return_value=self.tokenizer)
        self.transformers.AutoModelForCausalLM = mock.Mock()
        self.transformers.AutoModelForCausalLM.from_pretrained.side_effect = lambda *a, **k: (self.base, self.info)
        self.transformers.GenerationConfig = mock.Mock(side_effect=lambda **kwargs: types.SimpleNamespace(**kwargs))
        self.torch = types.ModuleType("torch")
        self.torch.equal = lambda a, b: a.values == b.values
        self.torch.inference_mode = contextlib.nullcontext
        self.peft = types.ModuleType("peft")
        self.peft.PeftModel = mock.Mock()
        self.adapted = mock.Mock(active_adapters=["default"])
        self.adapted.config = self.base.config
        self.adapted.to.return_value = self.adapted
        self.peft.PeftModel.from_pretrained.return_value = self.adapted
        self.peft.get_peft_model_state_dict = mock.Mock(return_value={"x.lora_A.weight": Tensor([1, 2])})
        self.safetensors = types.ModuleType("safetensors")
        self.safetensors_torch = types.ModuleType("safetensors.torch")
        self.safetensors_torch.load_file = mock.Mock(return_value={"x.lora_A.weight": Tensor([1, 2])})
        self.tokenizers = types.ModuleType("tokenizers")
        self.tokenizers.AddedToken = mock.Mock(side_effect=lambda content, **kwargs: content)
        patcher = mock.patch.dict(sys.modules, {"torch": self.torch, "transformers": self.transformers,
            "peft": self.peft, "tokenizers": self.tokenizers,
            "safetensors": self.safetensors, "safetensors.torch": self.safetensors_torch})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.model_path = str(Path(self.temp.name) / "model")
        Path(self.model_path).mkdir()
        (Path(self.model_path) / "config.json").write_text('{"model_type":"llama"}', encoding="utf-8")
        (Path(self.model_path) / "tokenizer.json").write_text("{}", encoding="utf-8")
        (Path(self.model_path) / "tokenizer_config.json").write_text(
            '{"chat_template":"{{ messages }}","eos_token":"</s>"}', encoding="utf-8")
        self.adapter = Path(self.temp.name) / "adapter"
        self.adapter.mkdir()
        (self.adapter / "adapter_model.safetensors").write_bytes(b"mock-checkpoint")
        self.write_config({"peft_type": "LORA", "task_type": "CAUSAL_LM", "bias": "none"})

    def write_config(self, value):
        (self.adapter / "adapter_config.json").write_text(json.dumps(value), encoding="utf-8")

    def test_base_loader_disables_remote_code_downloads_and_pickle(self):
        engine = server_module.ModelEngine(self.model_path, "", "cpu")
        self.transformers.AutoModelForCausalLM.from_pretrained.assert_called_once_with(
            self.model_path, local_files_only=True, trust_remote_code=False, token=False,
            use_safetensors=True, weights_only=True, output_loading_info=True)
        self.transformers.PreTrainedTokenizerFast.assert_called_once_with(
            tokenizer_file=str(Path(self.model_path) / "tokenizer.json"),
            model_input_names=["input_ids", "attention_mask"], eos_token="</s>",
            additional_special_tokens=[], chat_template="{{ messages }}")
        self.peft.PeftModel.from_pretrained.assert_not_called()
        self.base.eval.assert_called_once_with()
        self.assertEqual(engine.generation_config.max_new_tokens, 128)
        self.assertFalse(engine.generation_config.do_sample)

    def test_incomplete_or_extra_base_weights_fail(self):
        for key in self.info:
            with self.subTest(key=key):
                self.info[key] = ["tensor.weight"]
                with self.assertRaises(ValueError):
                    server_module.ModelEngine(self.model_path, "", "cpu")
                self.info[key] = []
        del self.info["missing_keys"]
        with self.assertRaises(ValueError):
            server_module.ModelEngine(self.model_path, "", "cpu")

    def test_pinned_chat_template_required(self):
        (Path(self.model_path) / "tokenizer_config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            server_module.ModelEngine(self.model_path, "", "cpu")
        self.transformers.AutoModelForCausalLM.from_pretrained.assert_not_called()

    def test_tokenizer_metadata_cannot_redirect_file_loading(self):
        config = {"chat_template": "{{ messages }}", "tokenizer_file": "/outside/tokenizer.json",
                  "vocab_file": "../vocab.txt", "merges_file": "https://example.invalid/merges",
                  "tokenizer_class": "CustomTokenizer"}
        (Path(self.model_path) / "tokenizer_config.json").write_text(json.dumps(config), encoding="utf-8")
        server_module.ModelEngine(self.model_path, "", "cpu")
        self.transformers.PreTrainedTokenizerFast.assert_called_once_with(
            tokenizer_file=str(Path(self.model_path) / "tokenizer.json"),
            model_input_names=["input_ids", "attention_mask"], additional_special_tokens=[],
            chat_template="{{ messages }}")

    def test_custom_and_external_model_loading_config_fails(self):
        for config in ({"auto_map": {"AutoModel": "other.Model"}},
                       {"quantization_config": {"quant_method": "bitsandbytes"}},
                       {"nested": {"checkpoint_path": "/outside/checkpoint"}}):
            (Path(self.model_path) / "config.json").write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                server_module.ModelEngine(self.model_path, "", "cpu")
        self.transformers.AutoModelForCausalLM.from_pretrained.assert_not_called()

    def test_implicit_base_adapter_fails(self):
        (Path(self.model_path) / "adapter_config.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            server_module.ModelEngine(self.model_path, "", "cpu")
        self.transformers.AutoModelForCausalLM.from_pretrained.assert_not_called()

    def test_verified_adapter_is_loaded_and_selected(self):
        engine = server_module.ModelEngine(self.model_path, str(self.adapter), "mps")
        self.peft.PeftModel.from_pretrained.assert_called_once_with(
            self.base, str(self.adapter), adapter_name="default", is_trainable=False,
            local_files_only=True, token=False, autocast_adapter_dtype=False)
        self.assertIs(engine.model, self.adapted)
        self.adapted.to.assert_called_once_with("mps")
        self.adapted.eval.assert_called_once_with()

    def test_missing_extra_and_changed_adapter_tensors_fail(self):
        for actual in ({}, {"different.lora_A.weight": Tensor([1, 2])},
                       {"x.lora_A.weight": Tensor([9, 2])},
                       {"x.lora_A.weight": Tensor([1])}):
            with self.subTest(keys=list(actual)):
                self.peft.get_peft_model_state_dict.return_value = actual
                with self.assertRaises(ValueError):
                    server_module.ModelEngine(self.model_path, str(self.adapter), "cpu")

    def test_inactive_adapter_fails(self):
        self.adapted.active_adapters = []
        with self.assertRaises(ValueError):
            server_module.ModelEngine(self.model_path, str(self.adapter), "cpu")

    def test_alternate_weights_and_unsupported_adapter_modes_fail(self):
        for config in ({"peft_type": "IA3"}, {"peft_type": "LORA", "bias": "all"},
                       {"peft_type": "LORA", "use_dora": True},
                       {"peft_type": "LORA", "modules_to_save": ["lm_head"]},
                       {"peft_type": "LORA", "init_lora_weights": "pissa"}):
            self.write_config(config)
            with self.assertRaises(ValueError):
                server_module.ModelEngine(self.model_path, str(self.adapter), "cpu")
        self.write_config({"peft_type": "LORA"})
        (self.adapter / "adapter_model.bin").write_bytes(b"not allowed")
        with self.assertRaises(ValueError):
            server_module.ModelEngine(self.model_path, str(self.adapter), "cpu")
        self.peft.PeftModel.from_pretrained.assert_not_called()

    def test_token_limit_is_checked_before_generation(self):
        engine = server_module.ModelEngine(self.model_path, "", "cpu")
        self.tokenizer.apply_chat_template.return_value = {
            "input_ids": types.SimpleNamespace(shape=(1, 385))}
        with self.assertRaises(ValueError):
            engine.complete([{"role": "user", "content": "input"}])
        self.base.generate.assert_not_called()

    def test_empty_variant_configuration_is_rejected(self):
        for key in ("arrow_config", "use_bdlora", "velora_config", "monteclora_config", "kasa_config"):
            with self.subTest(key=key):
                self.write_config({"peft_type": "LORA", key: {}})
                with self.assertRaisesRegex(ValueError, "unsupported LoRA mode"):
                    server_module.validate_adapter_directory(str(self.adapter))
        self.write_config({"peft_type": "LORA", "loftq_config": {}})
        server_module.validate_adapter_directory(str(self.adapter))

    def test_generation_uses_only_fixed_configuration(self):
        engine = server_module.ModelEngine(self.model_path, "", "cpu")
        tensor = mock.MagicMock()
        tensor.shape = (1, 4)
        tensor.to.return_value = tensor
        self.tokenizer.apply_chat_template.return_value = {"input_ids": tensor}
        self.base.generate.return_value = [[0, 1, 2, 3, 4]]
        self.tokenizer.decode.return_value = " output "
        messages = [{"role": "user", "content": "input"}]
        self.assertEqual(engine.complete(messages), "output")
        self.tokenizer.apply_chat_template.assert_called_once_with(messages, tokenize=True,
            add_generation_prompt=True, return_tensors="pt", return_dict=True)
        self.base.generate.assert_called_once_with(input_ids=tensor, generation_config=engine.generation_config)
        self.tokenizer.decode.assert_called_once_with([4], skip_special_tokens=True)


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=3)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="asb-py-", dir="/tmp")
        self.path = str(Path(self.temp.name) / "s")
        self.server = server_module.UnixHTTPServer(self.path, server_module.Handler)
        self.server.engine = mock.Mock()
        self.server.engine.complete.return_value = "checked response"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp.cleanup()

    def request(self, method, path, payload=None):
        connection = UnixConnection(self.path)
        try:
            body = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_health_and_chat(self):
        status, health = self.request("GET", "/health")
        self.assertEqual((status, health), (200, {"status": "ok"}))
        request = {"model": server_module.MODEL_NAME, "messages": [
            {"role": "system", "content": "system"}, {"role": "user", "content": "hello"}]}
        status, result = self.request("POST", "/v1/chat/completions", request)
        self.assertEqual(status, 200)
        self.assertEqual(result["choices"][0]["message"]["content"], "checked response")
        self.server.engine.complete.assert_called_once_with(request["messages"])

    def test_request_cannot_select_weights_templates_or_adapters(self):
        base = {"model": server_module.MODEL_NAME, "messages": [{"role": "user", "content": "hi"}]}
        for key, value in (("model", "other"), ("adapter", "/tmp/evil"),
                           ("chat_template", "replacement"), ("max_tokens", 99999),
                           ("stream", True), ("tools", [])):
            with self.subTest(key=key):
                request = dict(base)
                request[key] = value
                self.assertEqual(self.request("POST", "/v1/chat/completions", request)[0], 400)
        self.server.engine.complete.assert_not_called()

    def test_duplicate_json_bad_roles_and_multimodal_messages_fail(self):
        invalid = [
            '{"model":"asb-verified-model","model":"asb-verified-model","messages":[]}',
            {"model": server_module.MODEL_NAME, "messages": [{"role": "assistant", "content": "hi"}]},
            {"model": server_module.MODEL_NAME, "messages": [{"role": "user", "content": [{"type": "image_url"}]}]},
            {"model": server_module.MODEL_NAME, "messages": [{"role": "user", "content": "x" * (server_module.MAX_INPUT_BYTES + 1)}]},
        ]
        for request in invalid:
            self.assertEqual(self.request("POST", "/v1/chat/completions", request)[0], 400)
        self.server.engine.complete.assert_not_called()

    def test_adapter_update_endpoints_do_not_exist(self):
        for path in ("/v1/load_lora_adapter", "/v1/unload_lora_adapter", "/update_weights"):
            self.assertEqual(self.request("POST", path, {})[0], 404)
        self.server.engine.complete.assert_not_called()

    def test_duplicate_length_and_chunked_framing_fail(self):
        for extra in ("Content-Length: 2\r\n", "Transfer-Encoding: chunked\r\n"):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(self.path)
                raw = ("POST /v1/chat/completions HTTP/1.0\r\nContent-Type: application/json\r\n"
                       "Content-Length: 2\r\n" + extra + "\r\n{}")
                connection.sendall(raw.encode())
                self.assertIn(b" 400 ", connection.recv(4096).split(b"\r\n", 1)[0])
        self.server.engine.complete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
