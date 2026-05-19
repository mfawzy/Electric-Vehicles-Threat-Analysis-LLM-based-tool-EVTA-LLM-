import sys
import types
from pathlib import Path


def install_mock_transformers():
    module = types.ModuleType("transformers")

    class DummyTokenizer:
        @classmethod
        def from_pretrained(cls, model_name):
            return cls()

        def __call__(self, prompt, return_tensors="pt"):
            self.last_prompt = prompt
            return {"input_ids": DummyTensor([1, 2, 3]), "prompt_text": prompt}

        def decode(self, token_ids, skip_special_tokens=True):
            if isinstance(token_ids, list):
                return "Mock Qwen context: feature row reviewed successfully."
            return "Mock Qwen context: feature row reviewed successfully."

    class DummyModel:
        @classmethod
        def from_pretrained(cls, model_name):
            return cls()

        def generate(self, **inputs):
            return [DummyTensor([1, 2, 3, 4, 5])]

    class DummyTensor(list):
        @property
        def shape(self):
            return (1, len(self))

        def __getitem__(self, item):
            if isinstance(item, slice):
                return list(super().__getitem__(item))
            return super().__getitem__(item)

    module.AutoTokenizer = DummyTokenizer
    module.AutoModelForCausalLM = DummyModel
    sys.modules["transformers"] = module


install_mock_transformers()

from ev_ids_sentinel.cli import main

sys.argv = [
    "ev-ids-sentinel",
    "--mode",
    "offline",
    "--input",
    "dual_mode_test.pcap",
    "--output",
    "ev_ids_sentinel_validation_llm.csv",
    "--enable-llm-context",
    "--llm-model-name",
    "Qwen/Qwen2.5-7B-Instruct",
    "--binary-label",
    "attack",
    "--multiclass-label",
    "port_scan",
]
raise SystemExit(main())
