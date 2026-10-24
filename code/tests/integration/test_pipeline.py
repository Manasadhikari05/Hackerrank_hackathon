"""Integration + edge cases: the real components wired together on the fictional custom dataset."""

import csv
import json

import pytest

from deletion_auditor.application import AppConfig, AuditApplication
from deletion_auditor.evaluation import RegressionEvaluator
from deletion_auditor.infrastructure.repositories import MalformedInputError
from deletion_auditor.validation import OutputValidationError
from tests.conftest import CUSTOM_EXPECTED


def run(dataset, tmp_path, **kw):
    cfg = AppConfig(
        dataset_dir=dataset,
        output_path=tmp_path / "out.csv",
        run_log_path=tmp_path / "run.jsonl",
        enable_ocr=False,
        use_llm=False,
        **kw,
    )
    app = AuditApplication(cfg)
    return app, app.run()


def rows(path):
    with open(path, newline="") as fh:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}


def test_custom_cases_match_hand_written_expectations(custom_dataset, tmp_path):
    _, summary = run(custom_dataset, tmp_path)
    report = RegressionEvaluator().evaluate(tmp_path / "out.csv", CUSTOM_EXPECTED)
    assert not summary.errors
    assert report.metrics["sequence_accuracy"] == 1.0, [(c.case_id, c.missing(), c.extra()) for c in report.failures()]


def test_run_log_has_no_personal_data(custom_dataset, tmp_path):
    run(custom_dataset, tmp_path)
    text = (tmp_path / "run.jsonl").read_text()
    assert "@" not in text and "summary" in text


def test_post_audit_recreation_is_ignored(custom_dataset, tmp_path):
    run(custom_dataset, tmp_path)
    status, steps = rows(tmp_path / "out.csv")["cc_3"]
    assert status == "COMPLETE" and all(s["evidence_id"] != "ev_c05" for s in steps)


def test_missing_evidence_file_is_skipped_not_fatal(custom_dataset, tmp_path):
    (custom_dataset / "evidence/logs/backup_restore_trace_20260912.log").unlink()
    app, summary = run(custom_dataset, tmp_path)
    assert not summary.errors
    assert app.build().evidence_collector.stats["unreadable_files"] == 1
    status, steps = rows(tmp_path / "out.csv")["cc_1"]
    assert status == "INCOMPLETE" and not any(s["resource_id"] == "backup_7101" for s in steps)


def test_unsupported_format_is_reported(custom_dataset, tmp_path):
    (custom_dataset / "evidence/records/extra.xlsx").write_bytes(b"PK")
    with open(custom_dataset / "evidence_files.csv", "a") as fh:
        fh.write("ev_x,evidence/records/extra.xlsx,finance,2026-09-01T00:00:00Z\n")
    app, summary = run(custom_dataset, tmp_path)
    assert app.build().evidence_collector.stats["unsupported_files"] == 1 and not summary.errors


def test_corrupt_evidence_does_not_abort(custom_dataset, tmp_path):
    (custom_dataset / "evidence/records/service_resource_export_20260910.json").write_text("{broken")
    _, summary = run(custom_dataset, tmp_path)
    assert summary.cases == 5 and not summary.errors


def test_malformed_requests_fail_fast(custom_dataset, tmp_path):
    p = custom_dataset / "deletion_requests.csv"
    p.write_text("case_id,email\ncc_1,a@b.com\n")
    with pytest.raises(MalformedInputError):
        run(custom_dataset, tmp_path)


def test_duplicate_case_ids_fail_fast(custom_dataset, tmp_path):
    p = custom_dataset / "deletion_requests.csv"
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines + [lines[1]]) + "\n")
    with pytest.raises(MalformedInputError):
        run(custom_dataset, tmp_path)


def test_validator_blocks_bad_output(custom_dataset, tmp_path, monkeypatch):
    from deletion_auditor.infrastructure import output_writer

    monkeypatch.setattr(output_writer, "serialize_steps", lambda r: "not-json")
    with pytest.raises(OutputValidationError):
        run(custom_dataset, tmp_path)


def test_decoy_identity_is_not_linked(custom_dataset, tmp_path):
    run(custom_dataset, tmp_path)
    _, steps = rows(tmp_path / "out.csv")["cc_4"]
    assert "search_7504" not in {s["resource_id"] for s in steps}


def test_unlinkable_subject_is_incomplete_not_complete(custom_dataset, tmp_path):
    """Regression for the reported bug: no admissible evidence -> INCOMPLETE,[] (never COMPLETE,[])."""
    run(custom_dataset, tmp_path)
    assert rows(tmp_path / "out.csv")["cc_5"] == ("INCOMPLETE", [])


def test_requested_after_audit_is_rejected(custom_dataset, tmp_path):
    p = custom_dataset / "deletion_requests.csv"
    p.write_text(
        p.read_text().replace(
            "cc_2,tomas.novak@example.net,2026-09-02T10:00:00Z", "cc_2,tomas.novak@example.net,2026-09-30T10:00:00Z"
        )
    )
    with pytest.raises(MalformedInputError, match="requested_at after audit_at"):
        run(custom_dataset, tmp_path)


def test_evidence_file_captured_after_audit_cannot_add_findings(custom_dataset, tmp_path):
    """A post-audit file that newly links a present record to the subject must not change cc_3."""
    (custom_dataset / "evidence/records/late.json").write_text(
        '{"records": [{"resource_id": "search_7999", "email": "aiko.sato@example.com", "observed_at": "2026-09-14T00:00:00Z"}]}'
    )
    with open(custom_dataset / "evidence_files.csv", "a") as fh:
        fh.write("ev_late,evidence/records/late.json,search_service,2026-09-25T00:00:00Z\n")
    run(custom_dataset, tmp_path)
    status, steps = rows(tmp_path / "out.csv")["cc_3"]
    assert status == "COMPLETE" and "search_7999" not in {s["resource_id"] for s in steps}


def test_try_request_tool_requires_timestamps_and_handles_equal_boundary(custom_dataset):
    import subprocess
    import sys

    from tests.conftest import CODE_DIR

    tool = [sys.executable, str(CODE_DIR / "try_request.py"), "--dataset", str(custom_dataset)]
    missing = subprocess.run(tool + ["--email", "a@b.com", "--text", "delete"], capture_output=True, text=True)
    assert missing.returncode != 0 and "--requested-at" in missing.stderr

    def status(requested, audit):
        out = subprocess.run(
            tool
            + [
                "--email",
                "aiko.sato@example.com",
                "--text",
                "Please delete my account.",
                "--requested-at",
                requested,
                "--audit-at",
                audit,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert out.returncode == 0, out.stderr
        return out.stdout.splitlines()[0]

    capture = "2026-09-14T09:00:00Z"  # ev_c04 is captured exactly at this instant
    # Inclusive capture boundary: evidence captured exactly at audit_at is admissible -> proven COMPLETE.
    assert status("2026-09-01T10:00:00Z", capture).startswith("STATUS: COMPLETE")
    # One second earlier the evidence does not exist yet -> nothing proves completion.
    assert status("2026-09-01T10:00:00Z", "2026-09-14T08:59:59Z").startswith("STATUS: INCOMPLETE - insufficient evidence")
    # requested_at == audit_at is valid input; the observations (08:10, 08:20) predate the request,
    # so nothing was observed during the deletion window -> INCOMPLETE, never an unsupported COMPLETE.
    assert status(capture, capture).startswith("STATUS: INCOMPLETE - insufficient evidence")


def test_deterministic_output(custom_dataset, tmp_path):
    run(custom_dataset, tmp_path)
    first = (tmp_path / "out.csv").read_bytes()
    run(custom_dataset, tmp_path)
    assert (tmp_path / "out.csv").read_bytes() == first
