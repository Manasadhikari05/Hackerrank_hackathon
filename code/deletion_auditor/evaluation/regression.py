"""Regression metrics (UML: RegressionEvaluator).

Metrics, matching the evaluation_report.md requirements:

* case accuracy      - deletion_status equal;
* step P/R/F1        - steps matched as whole objects (step_no ignored), and as (operation, system, resource);
* field accuracy     - for steps matched on (operation, system, resource), share of equal fields;
* sequence accuracy  - the full steps_json array equal (order and step numbers included).
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FIELDS = ("step_no", "phase", "state", "evidence_id")


def _load(path: Path) -> dict[str, tuple[str, list[dict[str, Any]]]]:
    with Path(path).open(newline="", encoding="utf-8") as fh:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}


def _full(step: dict[str, Any]) -> tuple:
    return tuple(sorted((k, v) for k, v in step.items() if k != "step_no"))


def _key(step: dict[str, Any]) -> tuple:
    return (step.get("operation"), step.get("system_id"), step.get("resource_id"))


@dataclass
class CaseComparison:
    case_id: str
    expected_status: str
    predicted_status: str
    expected_steps: list[dict[str, Any]]
    predicted_steps: list[dict[str, Any]]

    @property
    def status_ok(self) -> bool:
        return self.expected_status == self.predicted_status

    @property
    def sequence_ok(self) -> bool:
        return self.status_ok and self.expected_steps == self.predicted_steps

    def missing(self) -> list[tuple]:
        return sorted((Counter(map(_key, self.expected_steps)) - Counter(map(_key, self.predicted_steps))).elements())

    def extra(self) -> list[tuple]:
        return sorted((Counter(map(_key, self.predicted_steps)) - Counter(map(_key, self.expected_steps))).elements())


@dataclass
class RegressionReport:
    cases: list[CaseComparison] = field(default_factory=list)

    def _prf(self, fn) -> dict[str, float]:
        tp = fp = fn_ = 0
        for c in self.cases:
            e, p = Counter(map(fn, c.expected_steps)), Counter(map(fn, c.predicted_steps))
            hit = sum((e & p).values())
            tp += hit
            fp += sum(p.values()) - hit
            fn_ += sum(e.values()) - hit
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn_) if tp + fn_ else 1.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn_}

    @property
    def metrics(self) -> dict[str, Any]:
        n = len(self.cases) or 1
        field_hits = Counter()
        field_total = 0
        for c in self.cases:
            pred = {_key(s): s for s in c.predicted_steps}
            for s in c.expected_steps:
                p = pred.get(_key(s))
                if p is None:
                    continue
                field_total += 1
                for f in FIELDS:
                    field_hits[f] += int(p.get(f) == s.get(f))
        confusion = Counter((c.expected_status, c.predicted_status) for c in self.cases)
        return {
            "cases": len(self.cases),
            "case_status_accuracy": sum(c.status_ok for c in self.cases) / n,
            "sequence_accuracy": sum(c.sequence_ok for c in self.cases) / n,
            "step_exact": self._prf(_full),
            "step_key": self._prf(_key),
            "field_accuracy": {f: (field_hits[f] / field_total if field_total else 1.0) for f in FIELDS},
            "matched_steps": field_total,
            "confusion": {f"{e}->{p}": v for (e, p), v in sorted(confusion.items())},
        }

    def failures(self) -> list[CaseComparison]:
        return [c for c in self.cases if not c.sequence_ok]


class RegressionEvaluator:
    def evaluate(self, predictions: Path, answers: Path) -> RegressionReport:
        pred, gold = _load(predictions), _load(answers)
        report = RegressionReport()
        for case_id in sorted(gold, key=lambda c: (len(c), c)):
            g_status, g_steps = gold[case_id]
            p_status, p_steps = pred.get(case_id, ("<missing>", []))
            report.cases.append(CaseComparison(case_id, g_status, p_status, g_steps, p_steps))
        return report
