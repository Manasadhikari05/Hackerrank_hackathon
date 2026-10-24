"""Output contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..domain.models import AuditResult


class OutputWriter(ABC):
    @abstractmethod
    def write(self, results: list[AuditResult], path: Path) -> None:
        """Persist results."""

    @abstractmethod
    def get_schema(self) -> dict[str, Any]:
        """Describe the produced columns (used by the output-schema validator)."""
