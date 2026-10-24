"""CSV output writer (UML: CsvOutputWriter)."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ..domain.catalog import case_sort_key
from ..domain.models import AuditResult
from ..interfaces.output import OutputWriter

OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")


def serialize_steps(result: AuditResult) -> str:
    """Deterministic compact JSON, keys sorted (matches sample_output.csv formatting)."""
    return json.dumps([s.to_dict() for s in result.steps], sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class CsvOutputWriter(OutputWriter):
    def write(self, results: list[AuditResult], path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(results, key=lambda r: case_sort_key(r.case_id))
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(OUTPUT_COLUMNS)
            for r in ordered:
                writer.writerow([r.case_id, r.status.value, serialize_steps(r)])
        tmp.replace(path)  # atomic: a crashed run never leaves a half-written output.csv

    def get_schema(self) -> dict[str, Any]:
        return {"columns": list(OUTPUT_COLUMNS), "steps_json": "JSON array of step objects"}
