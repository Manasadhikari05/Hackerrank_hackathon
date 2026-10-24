"""Format extractors: JSON, SQL (replica drift), five log dialects, text listings, PDF, OCR."""

import io
import json

import pytest

from deletion_auditor.domain.enums import DataCategory, ResourceState
from deletion_auditor.infrastructure.extractors import (
    ImageOcrExtractor,
    JsonExtractor,
    LogExtractor,
    PdfExtractor,
    SqlSnapshotExtractor,
    TextExtractor,
)
from deletion_auditor.infrastructure.interpreters import RuleBasedInterpreter
from tests.conftest import make_file, ts


def test_json_bundle_section_capture_and_system_context():
    doc = {
        "exported_at": "2026-09-17T12:00:00Z",
        "snapshots": [
            {
                "captured_at": "2026-09-15T12:00:00Z",
                "data_store": "account_service",
                "records": [{"resource_id": "account_5", "customer_reference": "user_5", "email": "a@b.com"}],
            }
        ],
    }
    f = make_file("ev_b", "x.json", captured="2026-09-17T12:00:00Z")
    (r,) = JsonExtractor().extract(f, json.dumps(doc).encode())
    assert r.observed_at == ts("2026-09-15T12:00:00Z")
    assert r.section_captured_at == ts("2026-09-15T12:00:00Z")
    assert r.captured_at == ts("2026-09-17T12:00:00Z")


def test_json_malformed_returns_empty():
    assert JsonExtractor().extract(make_file(), b"{not json") == []


SQL = b"""
CREATE TABLE customer_data_primary (resource_id TEXT, email TEXT, updated_at TEXT);
CREATE TABLE customer_data_read_replica (resource_id TEXT, email TEXT, updated_at TEXT);
INSERT INTO customer_data_read_replica VALUES ('account_9','a@b.com','2026-01-01T00:00:00Z');
"""


def test_sql_reads_replica_rows_missing_from_primary():
    (r,) = SqlSnapshotExtractor().extract(make_file(path="x.sql"), SQL)
    assert r.resource_id == "account_9" and r.state == ResourceState.PRESENT and r.source.endswith("read_replica")
    assert r.observed_at == ts("2026-09-10T00:00:00Z")  # snapshot time, not row update time


def test_sql_broken_script_returns_empty():
    assert SqlSnapshotExtractor().extract(make_file(path="x.sql"), b"CREATE TABLE (((") == []


LOGS = {
    "kv": 'T level=INFO service=account_service trace_id=tr-1 event=profile_lookup_started lookup_key="a@b.com"\n'
    "T level=DEBUG service=account_service trace_id=tr-1 event=cache_lookup result=miss\n"
    "T level=INFO service=account_service trace_id=tr-1 resource_id=account_1 event=profile_lookup_completed rows=0 http_status=404",
    "json": 'T {"service":"search_service","trace_id":"tr-2","event":"index_query_started","match_key":"a@b.com"}\n'
    'T {"service":"search_service","trace_id":"tr-2","resource_id":"search_1","event":"index_query_completed","result":"hit"}',
    "syslog": 'T <15>1 node-1 support_platform tr-3 - - level=WARN resource_id="support_1" event="message_pii_scan" matched_value="a@b.com"',
    "bracket": 'T [WARN] [integration_service] [tr-4] connector_heartbeat: resource_id="data_flow_1" enabled="true" correlation_key="a@b.com"',
    "nested": 'T requestId=tr-5 level=INFO function=backup_service message="resource_id=\\"backup_1\\" event=\\"restore_authorization_completed\\" decision=\\"deny\\" subject_key=\\"a@b.com\\""',
}


@pytest.mark.parametrize("dialect", sorted(LOGS))
def test_log_dialects_link_and_interpret(dialect):
    text = "\n".join(line.replace("T ", "2026-09-10T08:00:00Z ", 1) for line in LOGS[dialect].splitlines())
    records = LogExtractor().extract(make_file(path="x.log"), text.encode())
    assert len(records) == 1
    r = records[0]
    assert "email:a@b.com" in r.identifiers
    expected = {
        "kv": lambda r: r.state == ResourceState.ABSENT,  # cache miss on a sibling line must not leak
        "json": lambda r: r.state == ResourceState.PRESENT,
        "syslog": lambda r: r.state == ResourceState.PRESENT and "email" in r.exposed_kinds,
        "bracket": lambda r: r.flow_enabled is True,
        "nested": lambda r: r.restore_allowed is False,
    }[dialect]
    assert expected(r)


def test_text_listing_lines():
    text = (
        "HANDOVER\n"
        "- 2026-10-01T12:00:00Z | analytics_platform | analytics_1 | ANALYTICS_PROFILE | IDENTIFIABLE | a@b.com\n"
        "- 2026-10-01T12:00:00Z | account_service | account_1 | USER_PROFILE | NOT_FOUND | a@b.com\n"
        "- 2026-10-01T12:00:00Z | analytics_platform | analytics_2 | ANALYTICS_PROFILE | ANONYMIZED | no direct identifier\n"
    )
    recs = {r.resource_id: r for r in TextExtractor(RuleBasedInterpreter()).extract(make_file(path="h.txt"), text.encode())}
    assert recs["analytics_1"].exposed_kinds and recs["analytics_1"].category == DataCategory.ANALYTICS_PROFILE
    assert recs["account_1"].state == ResourceState.ABSENT
    assert recs["analytics_2"].anonymized_marker and not recs["analytics_2"].exposed_kinds


def test_document_mode_uses_aliases_and_single_subject_identifiers():
    interp = RuleBasedInterpreter({"NST-2026-0001": ("export_42", "export_service")})
    text = "CUSTOMER STATEMENT\nStatement NST-2026-0001\nCustomer Ana Lima\nuser_18\nana@example.com\n"
    (r,) = interp.interpret(text, make_file(path="s.pdf", origin="account_history_service"))
    assert r.resource_id == "export_42" and "email:ana@example.com" in r.identifiers


def test_user_alias_only_applies_on_owning_system_screens():
    interp = RuleBasedInterpreter({"user_17": ("tombstone_17", "identity_service")})
    assert interp.interpret("user_17", make_file(origin="analytics_platform")) == []
    assert interp.interpret("user_17", make_file(origin="identity_service"))[0].resource_id == "tombstone_17"


def _pdf_bytes(text: str) -> bytes:
    """Minimal single-page PDF with one line of Helvetica text (no extra dependencies)."""
    content = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode()
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + obj + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    return out.getvalue()


def test_pdf_attachment_extraction():
    pdf = _pdf_bytes("Attachment support_001 for priya@example.com")
    (r,) = PdfExtractor(RuleBasedInterpreter()).extract(make_file(path="a.pdf", origin="support_platform"), pdf)
    assert r.resource_id == "support_001" and r.category == DataCategory.SUPPORT_ATTACHMENT


def test_pdf_corrupt_returns_empty():
    assert PdfExtractor(RuleBasedInterpreter()).extract(make_file(path="a.pdf"), b"%PDF-garbage") == []


def test_ocr_extractor_with_injected_engine():
    fake_ocr = lambda content: "Pulse Analytics\nuser_20 - analytics_7438 - omar@example.com"  # noqa: E731
    (r,) = ImageOcrExtractor(RuleBasedInterpreter(), ocr=fake_ocr).extract(make_file(path="s.png"), b"img")
    assert r.resource_id == "analytics_7438" and r.has_user_reference and "email" in r.exposed_kinds


def test_ocr_failure_degrades_gracefully():
    def broken(_):
        raise OSError("tesseract missing")

    assert ImageOcrExtractor(RuleBasedInterpreter(), ocr=broken).extract(make_file(path="s.png"), b"img") == []
