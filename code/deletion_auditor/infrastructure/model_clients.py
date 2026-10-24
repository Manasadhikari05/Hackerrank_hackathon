"""Optional model clients. Nothing here runs unless an API key is configured in the environment."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from ..interfaces.ml import ModelClient, ModelUsage


class OpenAIModelClient(ModelClient):
    """OpenAI-compatible chat client (works with any endpoint speaking that API).

    Reads ``OPENAI_API_KEY`` (and optionally ``OPENAI_BASE_URL``) from the environment; keys are
    never passed as arguments, logged, or written to disk.
    """

    def __init__(self, model: str, temperature: float = 0.0):
        from openai import OpenAI  # imported lazily so the dependency stays optional

        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set")
        self._client = OpenAI()
        self._model = model
        self._temperature = temperature
        self._usage = ModelUsage(provider="openai-compatible", model=model)

    @property
    def usage(self) -> ModelUsage:
        return self._usage

    def generate(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            temperature=self._temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        u = resp.usage
        self._usage.calls += 1
        if u is not None:
            self._usage.input_tokens += u.prompt_tokens
            self._usage.output_tokens += u.completion_tokens
        return resp.choices[0].message.content or ""

    def structured_generate(self, prompt: str) -> dict[str, Any]:
        return parse_json_object(self.generate(prompt))


class ScriptedModelClient(ModelClient):
    """Deterministic test double: returns canned responses and counts calls like a real client."""

    def __init__(self, responses: list[str] | None = None, model: str = "scripted"):
        self._responses = list(responses or [])
        self._usage = ModelUsage(provider="test", model=model)
        self.prompts: list[str] = []

    @property
    def usage(self) -> ModelUsage:
        return self._usage

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        self._usage.calls += 1
        self._usage.input_tokens += len(prompt.split())
        if not self._responses:
            raise RuntimeError("no scripted response left")
        reply = self._responses.pop(0)
        self._usage.output_tokens += len(reply.split())
        return reply

    def structured_generate(self, prompt: str) -> dict[str, Any]:
        return parse_json_object(self.generate(prompt))


def parse_json_object(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        raise ValueError("model output contains no JSON object")
    try:
        value = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"model output is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("model output JSON is not an object")
    return value
