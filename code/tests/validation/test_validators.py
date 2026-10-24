"""Negative tests: every mandatory contract rule must be rejected loudly."""

import csv
import json

import pytest

from deletion_auditor.validation import (
    DecisionInvariantValidator,
    EvidenceCatalog,
    EvidenceReferenceValidator,
    OutputSchemaValidator,
    OutputValidationError,
    StepOrderValidator,
    validate_output_file,
)
from tests.conftest import make_request, ts


def step(n, phase, op, state, ev="", sys_="account_service", rid="account_1"):
    return {
        "step_no": n,
        "phase": phase,
        "system_id": sys_,
        "resource_id": rid,
        "operation": op,
        "state": state,
        "evidence_id": ev,
    }


GOOD_INCOMPLETE = [
    step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "ev_1"),
    step(2, "REMEDIATION", "DELETE_RECORD", "ABSENT"),
    step(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
]
CATALOG = EvidenceCatalog({"ev_1": ts("2026-09-10T00:00:00Z"), "ev_late": ts("2026-09-30T00:00:00Z")})
AUDIT = ts("2026-09-20T00:00:00Z")


def write(tmp_path, rows, header=("case_id", "deletion_status", "steps_json")):
    p = tmp_path / "out.csv"
    with p.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return p


def test_valid_file_passes(tmp_path):
    p = write(tmp_path, [["case_1", "INCOMPLETE", json.dumps(GOOD_INCOMPLETE)], ["case_2", "NOT_APPLICABLE", "[]"]])
    validate_output_file(p, [make_request("case_1"), make_request("case_2")], CATALOG)


@pytest.mark.parametrize(
    "rows,needle",
    [
        ([["case_1", "DONE", "[]"]], "invalid deletion_status"),
        ([["case_1", "INCOMPLETE", "{not json"]], "not valid JSON"),
        ([["case_1", "INCOMPLETE", "{}"]], "must be a JSON array"),
        ([["case_1", "NOT_APPLICABLE", json.dumps(GOOD_INCOMPLETE)]], "NOT_APPLICABLE must have"),
        ([["case_1", "INCOMPLETE", json.dumps([step(1, "REMEDIATION", "PURGE_RECORD", "GONE")])]], "unsupported operation"),
        ([["case_1", "INCOMPLETE", json.dumps([dict(GOOD_INCOMPLETE[0], extra=1)] + GOOD_INCOMPLETE[1:])]], "step keys"),
    ],
)
def test_contract_violations_raise(tmp_path, rows, needle):
    p = write(tmp_path, rows)
    with pytest.raises(OutputValidationError) as exc:
        validate_output_file(p, [make_request("case_1")], CATALOG)
    assert any(needle in e for e in exc.value.errors), exc.value.errors


def test_missing_duplicate_and_unsorted_rows(tmp_path):
    p = write(
        tmp_path, [["case_10", "NOT_APPLICABLE", "[]"], ["case_2", "NOT_APPLICABLE", "[]"], ["case_2", "NOT_APPLICABLE", "[]"]]
    )
    with pytest.raises(OutputValidationError) as exc:
        validate_output_file(p, [make_request("case_2"), make_request("case_3"), make_request("case_10")], CATALOG)
    text = " ".join(exc.value.errors)
    assert "duplicate" in text and "missing" in text and "not sorted" in text


def test_wrong_header(tmp_path):
    p = write(tmp_path, [["case_1", "NOT_APPLICABLE", "[]"]], header=("id", "deletion_status", "steps_json"))
    with pytest.raises(OutputValidationError):
        validate_output_file(p, [make_request("case_1")], CATALOG)


def test_evidence_reference_rules():
    v = EvidenceReferenceValidator(CATALOG)
    assert v.validate("INCOMPLETE", GOOD_INCOMPLETE, AUDIT) == []
    fabricated = [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "evidence_404")]
    assert "unknown evidence" in v.validate("INCOMPLETE", fabricated, AUDIT)[0]
    later = [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "ev_late")]
    assert "after audit_at" in v.validate("COMPLETE", later, AUDIT)[0]
    uncited = [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "")]
    assert "must cite" in v.validate("COMPLETE", uncited, AUDIT)[0]
    future_with_id = [step(1, "REMEDIATION", "DELETE_RECORD", "ABSENT", "ev_1")]
    assert "empty evidence_id" in v.validate("INCOMPLETE", future_with_id, AUDIT)[0]


def test_section_capture_time_makes_bundle_citable_only_for_that_resource():
    cat = EvidenceCatalog({"ev_b": ts("2026-09-30T00:00:00Z")})
    cat.add_section("ev_b", "account_1", ts("2026-09-15T00:00:00Z"))
    v = EvidenceReferenceValidator(cat)
    assert v.validate("COMPLETE", [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "ev_b")], AUDIT) == []
    other = [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "ev_b", rid="account_2")]
    assert v.validate("COMPLETE", other, AUDIT)


def test_order_and_numbering():
    v = StepOrderValidator()
    assert v.validate(GOOD_INCOMPLETE) == []
    assert v.validate(list(reversed([dict(s, step_no=i) for i, s in enumerate(GOOD_INCOMPLETE, 1)])))
    assert "consecutive" in v.validate([dict(GOOD_INCOMPLETE[0], step_no=2)])[0]
    unsorted_sys = [
        step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", sys_="search_service", rid="search_1"),
        step(2, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ]
    assert v.validate(unsorted_sys)


def test_phase_state_mismatch():
    errs = OutputSchemaValidator().validate_step(step(1, "FINDING", "DELETE_RECORD", "PRESENT"), "c")
    assert any("phase" in e for e in errs) and any("state" in e for e in errs)


def test_decision_invariants():
    v = DecisionInvariantValidator()
    assert v.validate("COMPLETE", GOOD_INCOMPLETE)  # findings in a COMPLETE case
    assert v.validate("INCOMPLETE", GOOD_INCOMPLETE[2:])  # no finding
    assert v.validate("INCOMPLETE", GOOD_INCOMPLETE[:1])  # finding without remediation
    assert v.validate("INCOMPLETE", GOOD_INCOMPLETE[:2])  # remediation without verification
