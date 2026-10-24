"""The independent submission validator accepts the committed output and rejects corrupted copies."""

import csv
import importlib.util
import json

import pytest

from tests.conftest import CODE_DIR, REPO_ROOT

pytestmark = pytest.mark.dataset

spec = importlib.util.spec_from_file_location("validate_submission", CODE_DIR / "evaluation" / "validate_submission.py")
vs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vs)


def run_checks(path):
    report = vs.Report()
    vs.check_output(path, report)
    return [e for _, errors, _, _ in report.sections for e in errors]


def test_submitted_output_passes():
    assert run_checks(REPO_ROOT / "output.csv") == []


def _mutate(tmp_path, fn):
    rows = list(csv.reader(open(REPO_ROOT / "output.csv", newline="", encoding="utf-8")))
    fn(rows)
    out = tmp_path / "out.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        csv.writer(fh).writerows(rows)
    return run_checks(out)


def _first_finding_row(rows):
    return next(r for r in rows[1:] if '"FINDING"' in r[2])


def test_rejects_evidence_that_does_not_concern_the_resource(tmp_path):
    def swap(rows):
        r = _first_finding_row(rows)
        steps = json.loads(r[2])
        steps[0]["resource_id"] = "search_999999"  # an id the cited evidence never mentions
        r[2] = json.dumps(steps)

    assert any("does not mention" in e or "does not concern" in e for e in _mutate(tmp_path, swap))


def test_rejects_complete_without_proof_and_missing_rows(tmp_path):
    def corrupt(rows):
        rows[1][1], rows[1][2] = "COMPLETE", "[]"
        del rows[-1]

    errs = _mutate(tmp_path, corrupt)
    assert any("COMPLETE without" in e for e in errs) and any("case_id set differs" in e for e in errs)


def test_rejects_finding_remediated_by_the_wrong_operation(tmp_path):
    def mispair(rows):
        r = next(r for r in rows[1:] if "REPORT_ACTIVE_DATA_FLOW" in r[2])
        steps = json.loads(r[2])
        for s in steps:
            if s["operation"] == "DISABLE_DATA_FLOW":
                s["operation"], s["state"] = "DELETE_RECORD", "ABSENT"
        r[2] = json.dumps(steps)

    errs = _mutate(tmp_path, mispair)
    assert any("remediated by ['DELETE_RECORD']" in e for e in errs)
