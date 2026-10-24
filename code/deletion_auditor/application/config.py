"""Run configuration. Paths resolve relative to the repository root, so runs work from any cwd."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class AppConfig:
    dataset_dir: Path = field(default_factory=lambda: REPO_ROOT / "dataset")
    requests_file: str = "deletion_requests.csv"
    output_path: Path = field(default_factory=lambda: REPO_ROOT / "output.csv")
    run_log_path: Path | None = field(default_factory=lambda: REPO_ROOT / "runs" / "run_log.jsonl")
    enable_ocr: bool = True
    # LLM use is opt-in: AUDIT_USE_LLM=1 and OPENAI_API_KEY must both be set.
    use_llm: bool = field(default_factory=lambda: os.environ.get("AUDIT_USE_LLM") == "1")
    llm_model: str = field(default_factory=lambda: os.environ.get("AUDIT_LLM_MODEL", "gpt-4o-mini"))

    @property
    def requests_path(self) -> Path:
        return self.dataset_dir / self.requests_file
