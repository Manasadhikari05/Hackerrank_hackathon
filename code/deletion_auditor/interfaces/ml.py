"""Model-facing contracts. Optional: the pipeline runs fully deterministically without them."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..domain.models import DeletionRequest, IntentDecision


@dataclass
class ModelUsage:
    provider: str
    model: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    per_call: list[dict[str, Any]] = field(default_factory=list)


class ModelClient(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Free-form completion."""

    @abstractmethod
    def structured_generate(self, prompt: str) -> dict[str, Any]:
        """Completion parsed as a JSON object. Raises ValueError on unparsable output."""

    @property
    @abstractmethod
    def usage(self) -> ModelUsage:
        """Cumulative token usage, for usage_report.md."""


class IntentClassifier(ABC):
    @abstractmethod
    def classify(self, request: DeletionRequest) -> IntentDecision:
        """Decide whether request_text authorises deletion."""
