import json
from pathlib import Path
from typing import Dict, Optional

from .constants import DEFAULT_LLM_MAX_NEW_TOKENS, DEFAULT_LLM_MODEL_NAME
from .models import LLMContextConfig


def _normalize_value(value):
    if isinstance(value, float):
        return round(value, 6)
    return value


class LocalQwenContextGenerator:
    def __init__(self, config: LLMContextConfig | None = None):
        self.config = config or LLMContextConfig()
        self._tokenizer = None
        self._model = None

    def enabled(self) -> bool:
        return bool(self.config and self.config.enabled)

    def _ensure_model(self) -> None:
        if self._tokenizer is not None and self._model is not None:
            return
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "LLM-context generation requires transformers and torch. Install them first, then try again."
            ) from exc

        raw_model_name = (self.config.model_name or DEFAULT_LLM_MODEL_NAME).strip()
        model_path = Path(raw_model_name).expanduser()
        is_local_path = model_path.exists()
        model_source = str(model_path) if is_local_path else raw_model_name

        tokenizer_kwargs = {"local_files_only": is_local_path}
        model_kwargs = {
            "local_files_only": is_local_path,
            "low_cpu_mem_usage": True,
        }

        if torch.cuda.is_available():
            model_kwargs["torch_dtype"] = torch.float16
            model_kwargs["device_map"] = "auto"
        else:
            model_kwargs["torch_dtype"] = torch.float32

        try:
            self._tokenizer = AutoTokenizer.from_pretrained(model_source, **tokenizer_kwargs)
            self._model = AutoModelForCausalLM.from_pretrained(model_source, **model_kwargs)
        except Exception as exc:  # pragma: no cover
            guidance = [
                f"Failed to load local Qwen model from '{model_source}'.",
                "If Qwen is already installed on your device, enter the local model folder path instead of the Hugging Face model ID.",
                "If you want to use the Hugging Face ID, ensure internet access, enough disk space, and enough RAM/VRAM for the configured Qwen model.",
                "For Windows CPU-only systems, start with Qwen2.5-0.5B-Instruct or another small local model path and keep max_new_tokens modest.",
                f"Original error: {exc}",
            ]
            raise RuntimeError(" ".join(guidance)) from exc

    def build_prompt(self, row: Dict[str, object]) -> str:
        payload = {
            key: _normalize_value(value)
            for key, value in row.items()
            if key != "llm_context"
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
        return (
            "You are EV-IDS Sentinel, an Electric Vehicle network-security analysis assistant. "
            "Read the following IDS feature row and write a concise analyst context for EV cybersecurity monitoring. "
            "Summarize what the traffic pattern suggests, mention the strongest indicators, "
            "and state any uncertainty. Keep the answer factual, compact, and suitable for one CSV cell.\n\n"
            f"Feature row:\n{serialized}\n\n"
            "LLM context:"
        )

    def generate_context(self, row: Dict[str, object]) -> str:
        if not self.enabled():
            return ""
        self._ensure_model()
        prompt = self.build_prompt(row)
        inputs = self._tokenizer(prompt, return_tensors="pt")
        outputs = self._model.generate(**inputs, max_new_tokens=self.config.max_new_tokens or DEFAULT_LLM_MAX_NEW_TOKENS)
        generated_tokens = outputs[0][inputs["input_ids"].shape[1]:]
        text = self._tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()
        if text:
            return " ".join(text.split())
        full_text = self._tokenizer.decode(outputs[0], skip_special_tokens=True)
        if full_text.startswith(prompt):
            full_text = full_text[len(prompt):]
        return " ".join(full_text.strip().split())


def apply_llm_context(
    row: Dict[str, object],
    generator: Optional[LocalQwenContextGenerator] = None,
) -> Dict[str, object]:
    row["llm_context"] = generator.generate_context(row) if generator and generator.enabled() else ""
    return row
