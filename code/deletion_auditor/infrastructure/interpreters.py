"""Evidence interpreters: unstructured text -> EvidenceRecords.

``RuleBasedInterpreter`` is deterministic and is the default. ``LLMEvidenceInterpreter`` is an
optional fallback; its output is filtered so it can only reference resource ids and identifiers
that literally occur in the source text (no invented evidence).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone

from ..domain.catalog import system_for_resource
from ..domain.enums import DataCategory, EvidenceType, ResourceState
from ..domain.identifiers import tokens_from_text
from ..domain.models import EvidenceFile, EvidenceRecord
from ..interfaces.ml import ModelClient
from ..interfaces.processing import EvidenceInterpreter
from .record_builder import RESOURCE_ID_RE, build_record

log = logging.getLogger(__name__)

PANEL_MARKER = "[[DETAIL PANEL]]"
STATE_WORDS = ("NOT_FOUND", "FOUND", "IDENTIFIABLE", "REDACTED", "ANONYMIZED", "ACTIVE", "BLOCKED", "DISABLED")
CATEGORY_RE = re.compile(r"\b(" + "|".join(c.value for c in DataCategory) + r")\b")
RETAIN_RE = re.compile(r"retain(?:ed)?\s+until\s+(\d{1,2}\s+[A-Za-z]{3}\s+\d{4})", re.I)


def _evidence_type(evidence: EvidenceFile) -> EvidenceType:
    return {
        "pdf": EvidenceType.PDF,
        "png": EvidenceType.IMAGE,
        "jpg": EvidenceType.IMAGE,
        "jpeg": EvidenceType.IMAGE,
        "webp": EvidenceType.IMAGE,
    }.get(evidence.extension, EvidenceType.TEXT)


class RuleBasedInterpreter(EvidenceInterpreter):
    """Two modes:

    * line mode - delimited listings (handover notes) where each line names one resource;
    * document mode - business documents/screens about a single subject, where the resource id
      and the identifiers appear on different lines.

    ``aliases`` maps business references (e.g. ``NST-2026-0718-1842`` or ``delivery_confirmation_19.pdf``)
    to resource ids; it is built from data-catalog activity rows, never from labels.
    """

    def __init__(self, aliases: dict[str, tuple[str, str]] | None = None):
        # alias -> (resource_id, system_id)
        self._aliases = aliases or {}

    def set_aliases(self, aliases: dict[str, tuple[str, str]]) -> None:
        self._aliases = dict(aliases)

    def interpret(self, raw_content: str, evidence: EvidenceFile) -> list[EvidenceRecord]:
        raw_content, _, panel = raw_content.partition(PANEL_MARKER)
        records = self._interpret_text(raw_content, evidence)
        panel_record = self._panel_record(panel, evidence) if panel.strip() else None
        if panel_record is not None:
            # The detail panel describes the selected record precisely; it replaces the coarse
            # whole-page reading of that same record.
            records = [r for r in records if r.resource_id != panel_record.resource_id] + [panel_record]
        return records

    def _panel_record(self, panel: str, evidence: EvidenceFile) -> EvidenceRecord | None:
        """Selected-record detail panel of an admin console: first line names the record, then
        labelled fields. Only states the screen actually shows are recorded; anything else stays unknown."""
        lines = [ln.strip(" '‘’|") for ln in panel.splitlines() if ln.strip()]
        if not lines:
            return None
        head = RESOURCE_ID_RE.search(lines[0].replace(" ", "_")) or RESOURCE_ID_RE.search(lines[0])
        if not head:
            return None
        rid = head.group(0)
        text = " ".join(lines[1:]).lower()
        fields: dict[str, object] = {"resource_id": rid, "content": " ".join(lines[1:])}
        status = re.search(r"\bstatus\s+([a-z ]+?)(?:\s+owner|\s+destination|\s+selector|$)", text)
        status_word = status.group(1).strip() if status else ""
        if rid.startswith("data_flow_"):
            if re.search(r"paused|disabled|stopped|inactive", status_word):
                fields["enabled"] = False
            elif re.search(r"healthy|active|running|enabled", status_word):
                fields["enabled"] = True
        elif rid.startswith("export_"):
            if re.search(r"\bexpired\b|\bdeleted\b|revoked", text):
                fields["available"] = False
            elif re.search(r"ready for download|\bready\b|available", text):
                fields["available"] = True
        elif rid.startswith("backup_"):
            if re.search(r"restore (?:is )?blocked|deletion block(?:ed)?|restore disabled", text):
                fields["restore_allowed"] = False
            elif re.search(r"restore (?:is )?allowed|restorable|restore enabled", text):
                fields["restore_allowed"] = True
            # otherwise the screen does not show restore controls: restore state stays unknown
        return build_record(fields, evidence, _evidence_type(evidence), source="ocr:detail_panel")

    def _interpret_text(self, raw_content: str, evidence: EvidenceFile) -> list[EvidenceRecord]:
        lines = [ln.strip() for ln in raw_content.splitlines() if ln.strip()]
        delimited = [ln for ln in lines if "|" in ln and RESOURCE_ID_RE.search(ln)]
        if delimited:
            return [r for r in (self._line_record(ln, evidence) for ln in delimited) if r]
        return self._document_records(raw_content, evidence)

    def _line_record(self, line: str, evidence: EvidenceFile) -> EvidenceRecord | None:
        parts = [p.strip() for p in line.lstrip("-* ").split("|")]
        rid_match = RESOURCE_ID_RE.search(line)
        if not rid_match:
            return None
        fields: dict[str, object] = {"resource_id": rid_match.group(0)}
        content_parts = []
        for part in parts:
            upper = part.upper()
            if upper in STATE_WORDS:
                fields["result"] = upper
            elif CATEGORY_RE.fullmatch(upper):
                fields["record_type"] = upper
            elif re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:]+Z", part):
                fields["observed_at"] = part
            elif part == rid_match.group(0) or part == system_for_resource(rid_match.group(0)):
                continue
            else:
                content_parts.append(part)
        fields["content"] = " ".join(content_parts)
        return build_record(fields, evidence, _evidence_type(evidence), source="text:line")

    def _document_records(self, text: str, evidence: EvidenceFile) -> list[EvidenceRecord]:
        found: dict[str, str | None] = {}
        for m in RESOURCE_ID_RE.finditer(text):
            found[m.group(0)] = None
        origin_system = evidence.origin
        for alias, (rid, system) in self._aliases.items():
            # Aliases such as "user_17" are only meaningful on screens of the owning system.
            if alias in text and (not alias.startswith("user_") or system == origin_system):
                found.setdefault(rid, alias)
        if not found:
            return []
        doc_tokens = tokens_from_text(text)
        emails = {t for t in doc_tokens if t.startswith("email:")}
        users = {t for t in doc_tokens if t.startswith("user:")}
        single_subject = len(emails) <= 1 and len(users) <= 1
        category = None
        if re.search(r"attachment|\.pdf\b", text, re.I) and evidence.origin in ("support_platform", "object_storage"):
            category = DataCategory.SUPPORT_ATTACHMENT
        retention = None
        rm = RETAIN_RE.search(text)
        if rm:
            try:
                retention = datetime.strptime(rm.group(1), "%d %b %Y").replace(tzinfo=timezone.utc)
            except ValueError:
                retention = None
        records = []
        for rid in sorted(found):
            if single_subject:
                content = text
            else:
                content = " ".join(ln for ln in text.splitlines() if rid in ln)
            fields: dict[str, object] = {"resource_id": rid, "content": content}
            if category and rid.startswith(("support_", "object_")):
                fields["record_type"] = category.value
            if retention and rid.startswith("audit_record_"):
                fields["retention_until"] = retention.strftime("%Y-%m-%dT%H:%M:%SZ")
            rec = build_record(fields, evidence, _evidence_type(evidence), source="text:document")
            if rec:
                records.append(rec)
        return records


class LLMEvidenceInterpreter(EvidenceInterpreter):
    """Optional model-backed interpreter, used only when a rule-based pass finds nothing.

    Anti-hallucination guard: every returned resource id and identifier must occur verbatim in
    ``raw_content``; anything else is dropped.
    """

    PROMPT = (
        'You extract facts from a business document. Return JSON: {"records": [{"resource_id": str, '
        '"state": "PRESENT"|"ABSENT", "identifiers": [str]}]}. Only use resource ids and '
        "identifiers that appear verbatim in the document. Document:\n"
    )

    def __init__(self, client: ModelClient, fallback: EvidenceInterpreter):
        self._client = client
        self._fallback = fallback

    def interpret(self, raw_content: str, evidence: EvidenceFile) -> list[EvidenceRecord]:
        records = self._fallback.interpret(raw_content, evidence)
        if records:
            return records
        try:
            payload = self._client.structured_generate(self.PROMPT + raw_content[:6000])
        except (ValueError, RuntimeError) as exc:
            log.warning("LLM interpretation failed for %s: %s", evidence.file_id, exc)
            return []
        out = []
        for item in payload.get("records", []) if isinstance(payload, dict) else []:
            rid = str(item.get("resource_id", ""))
            if not rid or rid not in raw_content or not RESOURCE_ID_RE.fullmatch(rid):
                continue
            idents = [i for i in item.get("identifiers", []) if isinstance(i, str) and i in raw_content]
            state = "NOT_FOUND" if str(item.get("state")).upper() == "ABSENT" else "FOUND"
            rec = build_record(
                {"resource_id": rid, "result": state, "content": " ".join(idents)},
                evidence,
                _evidence_type(evidence),
                source="llm",
            )
            if rec:
                out.append(rec)
        return out


def serialize_records(records: list[EvidenceRecord]) -> str:
    return json.dumps([r.to_dict() for r in records], sort_keys=True)


__all__ = ["RuleBasedInterpreter", "LLMEvidenceInterpreter", "ResourceState", "serialize_records"]
