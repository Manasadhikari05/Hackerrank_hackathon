"""Validators for the submission contract.

Every rule below cites its source. Validators return a list of human-readable violations;
:func:`validate_output_file` aggregates them and raises :class:`OutputValidationError`, so a
non-conforming output.csv can never be produced silently.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..domain.catalog import OPERATION_SPECS, PHASE_ORDER, case_sort_key
from ..domain.enums import AuditStatus, Operation, StepPhase
from ..domain.models import AuditResult, DeletionRequest

STEP_KEYS = frozenset({"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"})
OUTPUT_HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {s.value for s in AuditStatus}


class OutputValidationError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        preview = "\n".join(f"  - {e}" for e in errors[:25])
        more = f"\n  ... and {len(errors) - 25} more" if len(errors) > 25 else ""
        super().__init__(f"{len(errors)} output contract violation(s):\n{preview}{more}")


@dataclass
class EvidenceCatalog:
    """Every participant-visible evidence id with the time it became available."""

    times: dict[str, datetime] = field(default_factory=dict)

    def add(self, evidence_id: str, available_at: datetime) -> None:
        self.times[evidence_id] = available_at


class StepOrderValidator:
    """problem_statement.md 'Rules': phase order, then operation table order, then system_id, resource_id;
    step numbers consecutive from 1."""

    def validate(self, steps: list[dict[str, Any]], case_id: str = "") -> list[str]:
        errors = []
        for i, step in enumerate(steps, start=1):
            if step.get("step_no") != i:
                errors.append(f"{case_id}: step {i} has step_no={step.get('step_no')!r} (must be consecutive from 1)")
                break
        keys = []
        for step in steps:
            try:
                op = Operation(step["operation"])
                phase = StepPhase(step["phase"])
            except (KeyError, ValueError):
                return errors  # schema validator reports unknown values
            keys.append((PHASE_ORDER[phase], OPERATION_SPECS[op].order, step.get("system_id", ""), step.get("resource_id", "")))
        if keys != sorted(keys):
            errors.append(f"{case_id}: steps are not in phase/operation/system/resource order")
        seen = set()
        for step in steps:
            ident = (step.get("operation"), step.get("system_id"), step.get("resource_id"))
            if ident in seen:
                errors.append(f"{case_id}: duplicate step {ident}")
            seen.add(ident)
        return errors


class EvidenceReferenceValidator:
    """AGENTS.md 6.6: findings and COMPLETE verifications cite a real file_id/activity_id/audit_id
    captured at or before audit_at; remediation and INCOMPLETE verifications use ""."""

    def __init__(self, catalog: EvidenceCatalog):
        self._catalog = catalog

    def validate(self, status: str, steps: list[dict[str, Any]], audit_at: datetime | None, case_id: str = "") -> list[str]:
        errors = []
        for step in steps:
            ev = step.get("evidence_id")
            phase = step.get("phase")
            must_cite = phase == StepPhase.FINDING.value or (
                status == AuditStatus.COMPLETE.value and phase == StepPhase.VERIFICATION.value
            )
            if must_cite:
                if not ev:
                    errors.append(f"{case_id}: step {step.get('step_no')} ({phase}) must cite evidence")
                    continue
                when = self._catalog.times.get(ev)
                if when is None:
                    errors.append(f"{case_id}: step {step.get('step_no')} cites unknown evidence {ev!r}")
                elif audit_at is not None and when > audit_at:
                    errors.append(f"{case_id}: step {step.get('step_no')} cites {ev} captured after audit_at")
            elif ev != "":
                errors.append(f"{case_id}: step {step.get('step_no')} ({phase}) must use an empty evidence_id")
        return errors


class DecisionInvariantValidator:
    """problem_statement.md 'Required Output' + 6.5: status/step consistency."""

    def validate(self, status: str, steps: list[dict[str, Any]], case_id: str = "") -> list[str]:
        errors = []
        phases = [s.get("phase") for s in steps]
        if status == AuditStatus.NOT_APPLICABLE.value and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have steps_json=[]")
        if status == AuditStatus.COMPLETE.value:
            if any(p != StepPhase.VERIFICATION.value for p in phases):
                errors.append(f"{case_id}: COMPLETE may contain verification steps only")
            if not steps:
                # A COMPLETE row must *prove* the required state; an empty array proves nothing.
                errors.append(f"{case_id}: COMPLETE must contain at least one evidence-backed verification step")
        if status == AuditStatus.INCOMPLETE.value:

            def resources(phase: StepPhase) -> set[tuple]:
                return {(s.get("system_id"), s.get("resource_id")) for s in steps if s.get("phase") == phase.value}

            fixed = resources(StepPhase.REMEDIATION)
            found = resources(StepPhase.FINDING)
            verified = resources(StepPhase.VERIFICATION)
            # An INCOMPLETE row may have no finding (insufficient evidence), but every remediation
            # must answer a cited finding and every finding/remediation must be verified.
            for res in sorted(found - fixed):
                errors.append(f"{case_id}: finding {res} has no remediation step")
            for res in sorted(fixed - found):
                errors.append(f"{case_id}: remediation {res} has no supporting finding")
            for res in sorted(fixed - verified):
                errors.append(f"{case_id}: remediated {res} has no verification step")
        return errors

    def validate_result(self, result: AuditResult) -> list[str]:
        """Model-level invariants on top of the row checks."""
        errors = self.validate(result.status.value, [s.to_dict() for s in result.steps], result.case_id)
        open_items = [a for a in result.findings if not a.compliant]
        if result.status == AuditStatus.COMPLETE:
            if open_items:
                errors.append(f"{result.case_id}: marked COMPLETE with {len(open_items)} unresolved item(s)")
            if any(not a.proven for a in result.findings):
                errors.append(f"{result.case_id}: marked COMPLETE with unproven assessment(s)")
        if result.status == AuditStatus.INCOMPLETE and not open_items and not result.decision.insufficient_evidence:
            errors.append(f"{result.case_id}: INCOMPLETE without a violation must be flagged insufficient evidence")
        return errors


class OutputSchemaValidator:
    """problem_statement.md 'Required Output' + 'Allowed Operations'."""

    def validate_step(self, step: Any, case_id: str) -> list[str]:
        if not isinstance(step, dict):
            return [f"{case_id}: step is not a JSON object"]
        errors = []
        keys = set(step)
        if keys != STEP_KEYS:
            errors.append(f"{case_id}: step keys {sorted(keys)} != {sorted(STEP_KEYS)}")
        if not isinstance(step.get("step_no"), int) or isinstance(step.get("step_no"), bool):
            errors.append(f"{case_id}: step_no must be an integer")
        for k in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
            if k in step and not isinstance(step[k], str):
                errors.append(f"{case_id}: {k} must be a string")
        try:
            op = Operation(step.get("operation"))
        except ValueError:
            return errors + [f"{case_id}: unsupported operation {step.get('operation')!r}"]
        spec = OPERATION_SPECS[op]
        if step.get("phase") != spec.phase.value:
            errors.append(f"{case_id}: {op.value} must be in phase {spec.phase.value}, got {step.get('phase')!r}")
        if step.get("state") != spec.state:
            errors.append(f"{case_id}: {op.value} must have state {spec.state}, got {step.get('state')!r}")
        if not step.get("system_id") or not step.get("resource_id"):
            errors.append(f"{case_id}: system_id and resource_id must be non-empty")
        return errors

    def validate_rows(self, header: list[str], rows: list[dict[str, str]], expected_case_ids: Iterable[str]) -> list[str]:
        errors = []
        if header != OUTPUT_HEADER:
            errors.append(f"header must be {OUTPUT_HEADER}, got {header}")
        expected = list(expected_case_ids)
        ids = [r.get("case_id", "") for r in rows]
        if len(rows) != len(expected):
            errors.append(f"expected {len(expected)} rows, found {len(rows)}")
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            errors.append(f"duplicate case_ids: {dupes[:10]}")
        missing = sorted(set(expected) - set(ids))
        extra = sorted(set(ids) - set(expected))
        if missing:
            errors.append(f"missing case_ids: {missing[:10]}")
        if extra:
            errors.append(f"unexpected case_ids: {extra[:10]}")
        if ids != sorted(ids, key=case_sort_key):
            errors.append("rows are not sorted by case_id")
        for r in rows:
            if r.get("deletion_status") not in STATUSES:
                errors.append(f"{r.get('case_id')}: invalid deletion_status {r.get('deletion_status')!r}")
        return errors


def parse_steps(raw: str, case_id: str) -> tuple[list[dict[str, Any]] | None, list[str]]:
    try:
        steps = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, [f"{case_id}: steps_json is not valid JSON ({exc})"]
    if not isinstance(steps, list):
        return None, [f"{case_id}: steps_json must be a JSON array"]
    return steps, []


def validate_rows(
    header: list[str],
    rows: list[dict[str, str]],
    requests: list[DeletionRequest],
    catalog: EvidenceCatalog | None,
) -> list[str]:
    schema = OutputSchemaValidator()
    order = StepOrderValidator()
    invariants = DecisionInvariantValidator()
    refs = EvidenceReferenceValidator(catalog) if catalog is not None else None
    audit_at = {r.case_id: r.audit_at for r in requests}
    errors = schema.validate_rows(header, rows, [r.case_id for r in requests])
    for row in rows:
        cid = row.get("case_id", "")
        steps, errs = parse_steps(row.get("steps_json", ""), cid)
        errors += errs
        if steps is None:
            continue
        for step in steps:
            errors += schema.validate_step(step, cid)
        if any(not isinstance(s, dict) for s in steps):
            continue
        errors += order.validate(steps, cid)
        errors += invariants.validate(row.get("deletion_status", ""), steps, cid)
        if refs:
            errors += refs.validate(row.get("deletion_status", ""), steps, audit_at.get(cid), cid)
    return errors


def validate_output_file(
    path: Path,
    requests: list[DeletionRequest],
    catalog: EvidenceCatalog | None = None,
) -> None:
    """Fail loudly (OutputValidationError) if the written file breaks any mandatory requirement."""
    path = Path(path)
    if not path.exists():
        raise OutputValidationError([f"output file not found: {path}"])
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        rows = list(reader)
    errors = validate_rows(header, rows, requests, catalog)
    if errors:
        raise OutputValidationError(errors)
