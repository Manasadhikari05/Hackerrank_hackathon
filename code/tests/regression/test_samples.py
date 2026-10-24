"""Regression gate against the 32 published sample answers (participant-facing, permitted)."""

import pytest

from deletion_auditor.application import AppConfig, AuditApplication
from deletion_auditor.evaluation import RegressionEvaluator
from tests.conftest import DATASET

pytestmark = pytest.mark.dataset


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    out = tmp_path_factory.mktemp("samples") / "pred.csv"
    cfg = AppConfig(requests_file="sample_deletion_requests.csv", output_path=out, run_log_path=None)
    AuditApplication(cfg).run(validate=True)
    return RegressionEvaluator().evaluate(out, DATASET / "sample_output.csv")


def test_never_claims_complete_when_reference_is_incomplete(report):
    false_complete = [c.case_id for c in report.cases if c.predicted_status == "COMPLETE" and c.expected_status != "COMPLETE"]
    assert false_complete == []


def test_every_status_mismatch_is_an_insufficient_evidence_incomplete(report):
    """The agent refuses to claim COMPLETE without proof. The only permitted disagreement with the
    reference is a case where no participant-visible evidence proves completion: predicted INCOMPLETE
    with no finding and no remediation (nothing it could cite)."""
    for c in report.cases:
        if c.status_ok:
            continue
        assert (c.expected_status, c.predicted_status) == ("COMPLETE", "INCOMPLETE"), c.case_id
        assert not any(s["phase"] in ("FINDING", "REMEDIATION") for s in c.predicted_steps), c.case_id


def test_status_accuracy_floor(report):
    assert report.metrics["case_status_accuracy"] >= 0.90


def test_no_false_positive_steps(report):
    # Every step we emit must be in the reference answer: precision is the safety-critical metric.
    assert report.metrics["step_key"]["precision"] >= 0.95


def test_recall_floor(report):
    assert report.metrics["step_key"]["recall"] >= 0.80


def test_evidence_and_state_fields(report):
    fa = report.metrics["field_accuracy"]
    assert fa["state"] == 1.0 and fa["phase"] == 1.0 and fa["evidence_id"] >= 0.95
