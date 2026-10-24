"""Concrete evidence extractors, one per format (UML: Text/Pdf/ImageOcr/Json/SqlSnapshot + Log).

Each extractor is defensive: malformed content yields ``[]`` plus a logged warning, never an
exception, so one corrupt file cannot abort a 518-case run.
"""

from __future__ import annotations

import io
import json
import logging
import re
import sqlite3
from dataclasses import replace
from typing import Any

from ..domain.enums import EvidenceType, ResourceState
from ..domain.models import EvidenceFile, EvidenceRecord, parse_ts
from ..interfaces.processing import EvidenceExtractor, EvidenceInterpreter
from .record_builder import KNOWN_SYSTEMS, build_record

log = logging.getLogger(__name__)


class JsonExtractor(EvidenceExtractor):
    """Walks any JSON document; every object holding a ``resource_id`` becomes a record."""

    CONTEXT_TIME_KEYS = ("captured_at", "recorded_at", "exported_at")
    CONTEXT_SYSTEM_KEYS = ("data_store", "system", "source_system")

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension == "json"

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        try:
            doc = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning("json evidence %s unreadable: %s", evidence.file_id, exc)
            return []
        records: list[EvidenceRecord] = []
        self._walk(doc, evidence, None, None, None, "", records)
        return records

    def _walk(self, node: Any, evidence, system, ts, section_capture, path, out) -> None:
        if isinstance(node, dict):
            for key in self.CONTEXT_TIME_KEYS:
                parsed = parse_ts(node.get(key)) if isinstance(node.get(key), str) else None
                if parsed:
                    ts = parsed
                    break
            # Bundles embed snapshot sections with their own capture time. That explicit stamp is
            # when this part of the evidence was captured (never later than the file itself).
            section = parse_ts(node.get("captured_at")) if isinstance(node.get("captured_at"), str) else None
            if section and section <= evidence.captured_at:
                section_capture = section
            for key in self.CONTEXT_SYSTEM_KEYS:
                if node.get(key) in KNOWN_SYSTEMS:
                    system = node[key]
            if "resource_id" in node:
                rec = build_record(node, evidence, EvidenceType.JSON, default_system=system, default_time=ts, source=path)
                if rec and section_capture and section_capture < evidence.captured_at:
                    rec = replace(rec, section_captured_at=section_capture)
                if rec:
                    out.append(rec)
                return
            for key, value in node.items():
                child_system = key if key in KNOWN_SYSTEMS else system
                self._walk(value, evidence, child_system, ts, section_capture, f"{path}/{key}", out)
        elif isinstance(node, list):
            for item in node:
                self._walk(item, evidence, system, ts, section_capture, path, out)


class SqlSnapshotExtractor(EvidenceExtractor):
    """Executes the SQL export in an in-memory SQLite database and reads every table.

    Primary and replica tables are all read; replication drift shows up as the same
    resource_id observed in a replica table but not in the primary one.
    """

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension == "sql"

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(content.decode("utf-8"))
        except (sqlite3.Error, UnicodeDecodeError) as exc:
            log.warning("sql evidence %s failed to load: %s", evidence.file_id, exc)
            conn.close()
            return []
        captured = evidence.captured_at
        records: list[EvidenceRecord] = []
        try:
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            for table in tables:
                cur = conn.execute(f'SELECT * FROM "{table}"')
                cols = [c[0] for c in cur.description]
                if "resource_id" not in cols:
                    continue
                for row in cur.fetchall():
                    fields = dict(zip(cols, row, strict=True))
                    # Row update time is not observation time; the snapshot is.
                    fields.pop("updated_at", None)
                    rec = build_record(fields, evidence, EvidenceType.SQL, default_time=captured, source=f"sql:{table}")
                    if rec:
                        records.append(rec)
        finally:
            conn.close()
        return records


class LogExtractor(EvidenceExtractor):
    """Parses key=value, JSON-line, syslog and nested ``message="..."`` log dialects.

    Lines sharing a trace id are merged so that a ``*_started`` line carrying the lookup key
    and a ``*_completed`` line carrying the resource id form one observation.
    """

    TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
    KV_RE = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S+)')
    TRACE_RE = re.compile(r"\b((?:tr|rb)-[\w-]+)\b")
    SYSLOG_RE = re.compile(r"^\S+\s+<\d+>\d+\s+\S+\s+(\S+)\s+(\S+)")
    BRACKET_RE = re.compile(r"^\S+\s+\[(\w+)\]\s+\[([\w.-]+)\]\s+\[([\w-]+)\]\s+(\w+):")
    # Only query keys travel between lines of a trace; outcome fields (result, rows, ...) of
    # auxiliary lines such as cache_lookup must never leak into the record observation.
    CONTEXT_KEYS = frozenset(
        {"lookup_key", "match_key", "correlation_key", "subject_key", "scan_key", "subject_ref", "query", "service"}
    )

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension == "log"

    def parse_line(self, line: str) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        m = self.TS_RE.match(line)
        if m:
            fields["timestamp"] = m.group(1)
        brace = line.find("{")
        if brace != -1 and line.rstrip().endswith("}"):
            try:
                fields.update({k.lower(): v for k, v in json.loads(line[brace:]).items()})
                return fields
            except json.JSONDecodeError:
                pass
        sm = self.SYSLOG_RE.match(line)
        if sm:
            fields["service"] = sm.group(1)
            fields["trace_id"] = sm.group(2)
        bm = self.BRACKET_RE.match(line)
        if bm:
            fields["level"], fields["service"], fields["trace_id"], fields["event"] = bm.groups()
        for key, raw in self.KV_RE.findall(line):
            value = raw[1:-1].replace('\\"', '"') if raw.startswith('"') else raw
            if key == "message" and "=" in value:
                fields.update(self.parse_line(value))
                continue
            fields[key.lower()] = value
        return fields

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        text = content.decode("utf-8", errors="replace")
        groups: dict[str, list[dict[str, Any]]] = {}
        standalone: list[dict[str, Any]] = []
        for raw in text.splitlines():
            if not raw.strip():
                continue
            fields = self.parse_line(raw)
            trace = fields.get("trace_id") or fields.get("requestid")
            if not trace:
                tm = self.TRACE_RE.search(raw)
                trace = tm.group(1) if tm else None
            if trace:
                groups.setdefault(trace, []).append(fields)
            elif "resource_id" in fields:
                standalone.append(fields)

        records: list[EvidenceRecord] = []
        for trace, lines in groups.items():
            context: dict[str, Any] = {}
            for f in lines:
                for k, v in f.items():
                    if k in self.CONTEXT_KEYS:
                        context.setdefault(k, v)
            # One observation per resource per trace; later lines refine earlier ones.
            merged: dict[str, dict[str, Any]] = {}
            outcome: dict[str, bool] = {}
            for f in lines:
                rid = f.get("resource_id")
                if not rid:
                    continue
                merged.setdefault(rid, {}).update(f)
                outcome[rid] = outcome.get(rid, False) or bool(self.OUTCOME_RE.search(str(f.get("event", ""))))
            for rid, f in merged.items():
                rec = self._record({**context, **f}, evidence, f"log:{trace}", outcome[rid])
                if rec:
                    records.append(rec)
        for f in standalone:
            rec = self._record(f, evidence, "log:line", bool(self.OUTCOME_RE.search(str(f.get("event", "")))))
            if rec:
                records.append(rec)
        return records

    # A completed read/query/scan returning the record proves it exists unless the line itself
    # carries an absence signal (rows=0, http 404, result=miss), which build_record applies.
    OUTCOME_RE = re.compile(r"(_completed|_pii_scan|_read|record_lookup|_identity_scan)$")

    def _record(self, fields: dict[str, Any], evidence: EvidenceFile, source: str, outcome: bool) -> EvidenceRecord | None:
        default_state = ResourceState.PRESENT if outcome else ResourceState.UNKNOWN
        return build_record(
            fields,
            evidence,
            EvidenceType.LOG,
            default_time=parse_ts(fields.get("timestamp")) or evidence.captured_at,
            default_state=default_state,
            source=source,
        )


class TextExtractor(EvidenceExtractor):
    """Plain-text business records; parsing is delegated to an EvidenceInterpreter."""

    def __init__(self, interpreter: EvidenceInterpreter):
        self._interpreter = interpreter

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension in ("txt", "text", "md")

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        return self._interpreter.interpret(content.decode("utf-8", errors="replace"), evidence)


class PdfExtractor(EvidenceExtractor):
    def __init__(self, interpreter: EvidenceInterpreter):
        self._interpreter = interpreter

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension == "pdf"

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        try:
            from PyPDF2 import PdfReader
        except ImportError:  # pragma: no cover - dependency documented in requirements.txt
            log.warning("PyPDF2 not installed; skipping %s", evidence.file_id)
            return []
        try:
            reader = PdfReader(io.BytesIO(content))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as exc:  # PyPDF2 raises many exception types on corrupt input
            log.warning("pdf evidence %s unreadable: %s", evidence.file_id, exc)
            return []
        return self._interpreter.interpret(text, evidence)


class ImageOcrExtractor(EvidenceExtractor):
    """Screenshots are OCR'd with Tesseract. Degrades to [] when Tesseract is unavailable."""

    EXTENSIONS = ("png", "jpg", "jpeg", "webp")

    def __init__(self, interpreter: EvidenceInterpreter, ocr=None):
        self._interpreter = interpreter
        self._ocr = ocr or self._tesseract

    @staticmethod
    def _tesseract(content: bytes) -> str:
        import pytesseract
        from PIL import Image

        return pytesseract.image_to_string(Image.open(io.BytesIO(content)))

    def supports(self, evidence: EvidenceFile) -> bool:
        return evidence.extension in self.EXTENSIONS

    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        try:
            text = self._ocr(content)
        except Exception as exc:  # missing binary, unreadable image, ...
            log.warning("OCR failed for %s: %s", evidence.file_id, exc)
            return []
        return self._interpreter.interpret(text, evidence)
