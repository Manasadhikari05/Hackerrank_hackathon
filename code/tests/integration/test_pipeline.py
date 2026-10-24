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
    assert summary.cases == 4 and not summary.errors


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


def test_deterministic_output(custom_dataset, tmp_path):
    run(custom_dataset, tmp_path)
    first = (tmp_path / "out.csv").read_bytes()
    run(custom_dataset, tmp_path)
    assert (tmp_path / "out.csv").read_bytes() == first
