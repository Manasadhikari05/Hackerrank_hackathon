"""Structured execution log (JSON lines). Contains case ids and counts only - no personal data."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RunLogger:
    def __init__(self, path: Path | None):
        self._path = Path(path) if path else None
        self._events: list[dict[str, Any]] = []

    def log(self, event: str, details: dict[str, Any]) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event, **details}
        self._events.append(entry)

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def save_report(self, path: Path | None = None) -> Path | None:
        target = Path(path) if path else self._path
        if target is None:
            return None
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            for e in self._events:
                fh.write(json.dumps(e, sort_keys=True, default=str) + "\n")
        return target
