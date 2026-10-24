"""Regression tests for the defects found in the compliance audit (see evaluation_report.md §4)."""

from datetime import timedelta

import pytest

from deletion_auditor.domain.enums import AuditStatus, DataCategory, EvidenceType, Operation, ResourceState, RuleType
from deletion_auditor.domain.models import DeletionRule, EvidenceRecord, IntentDecision, ResourceAssessment
from deletion_auditor.infrastructure.extractors import LogExtractor
from deletion_auditor.services.evidence_collector import EvidenceCollector, ResourceView
from deletion_auditor.services.policy_evaluator import PolicyEvaluator
from deletion_auditor.services.status_decider import StatusDecider
from deletion_auditor.services.step_planner import StepPlanner
from tests.conftest import make_file, ts

YES = IntentDecision(True, 0.95, "delete", "rules")
AUDIT = ts("2026-09-15T12:00:00Z")


def rec(rid="account_1", observed="2026-09-10T00:00:00Z", captured=None, state=ResourceState.ABSENT, **kw):
    from deletion_auditor.domain.catalog import system_for_resource

    return EvidenceRecord(
        evidence_id=kw.pop("ev", "ev_1"),
        evidence_type=EvidenceType.JSON,
        captured_at=ts(captured or observed),
        observed_at=ts(observed),
        system_id=system_for_resource(rid),
        resource_id=rid,
        state=state,
        **kw,
    )


# ---- 1. absence of evidence must never become COMPLETE ----------------------------------------
def test_no_assessments_is_insufficient_evidence_not_complete():
    d = StatusDecider().decide(YES, [])
    assert d.status == AuditStatus.INCOMPLETE and d.insufficient_evidence
    assert StepPlanner().plan(d, []) == []


def test_unproven_compliant_assessment_blocks_complete():
    a = ResourceAssessment(
        "account_service",
        "account_1",
        DataCategory.USER_PROFILE,
        RuleType.DELETE,
        True,
        None,
        None,
        Operation.VERIFY_RECORD_ABSENT,
        evidence_id="",
    )
    d = StatusDecider().decide(YES, [a])
    assert d.status == AuditStatus.INCOMPLETE and d.insufficient_evidence
    steps = StepPlanner().plan(d, [a])
    assert [(s.operation, s.evidence_id) for s in steps] == [(Operation.VERIFY_RECORD_ABSENT, "")]


def test_undeterminable_linked_record_blocks_complete():
    proven = ResourceAssessment(
        "account_service",
        "account_1",
        DataCategory.USER_PROFILE,
        RuleType.DELETE,
        True,
        None,
        None,
        Operation.VERIFY_RECORD_ABSENT,
        evidence_id="ev_1",
    )
    assert StatusDecider().decide(YES, [proven]).status == AuditStatus.COMPLETE
    blocked = StatusDecider().decide(YES, [proven], unresolved=["support_9"])
    assert blocked.status == AuditStatus.INCOMPLETE and blocked.insufficient_evidence


def test_missing_required_retained_record_is_unresolved():
    rules = [DeletionRule("r12", DataCategory.SECURITY_AUDIT_LOG, "retention", RuleType.RETAIN)]
    view = ResourceView("security_service", "audit_record_1", [rec("audit_record_1", state=ResourceState.ABSENT)])
    (a,) = PolicyEvaluator(rules).evaluate([view], AUDIT)
    assert not a.compliant and a.finding is None and a.verification == Operation.VERIFY_RECORD_PRESENT
    assert StatusDecider().decide(YES, [a]).status == AuditStatus.INCOMPLETE


# ---- 2. strict time admissibility (AGENTS.md: later evidence must not change the answer) ------
@pytest.mark.parametrize(
    "observed,captured,ok",
    [
        ("2026-09-15T12:00:00Z", "2026-09-15T12:00:00Z", True),  # boundary: exactly audit_at is admissible
        ("2026-09-10T00:00:00Z", "2026-09-18T00:00:00Z", False),  # observed before, evidence item captured after
        ("2026-09-16T00:00:00Z", "2026-09-16T00:00:00Z", False),  # observed after audit
    ],
)
def test_admissibility(observed, captured, ok):
    assert EvidenceCollector.admissible(rec(observed=observed, captured=captured), AUDIT) is ok


class _Repo:
    def __init__(self):
        self.files = []

    def list_evidence(self):
        return []

    def read_evidence(self, file_id):
        raise KeyError(file_id)


def _collector(records):
    c = EvidenceCollector(_Repo(), [])
    c.index(records)
    return c


def test_link_from_later_evidence_is_ignored():
    """Regression: a resource linked to the subject only by a post-audit file used to be reported."""
    from deletion_auditor.domain.models import IdentityProfile

    later_link = rec("account_9", observed="2026-09-20T00:00:00Z", identifiers=frozenset({"email:a@b.com"}))
    unlinked_state = rec("account_9", observed="2026-09-10T00:00:00Z", state=ResourceState.ABSENT)
    views = _collector([later_link, unlinked_state]).collect(IdentityProfile(None, emails={"a@b.com"}), AUDIT)
    assert views == []


def test_out_of_window_resource_is_flagged_not_dropped():
    from deletion_auditor.domain.models import IdentityProfile

    old = rec("search_1", observed="2026-03-01T00:00:00Z", state=ResourceState.PRESENT, identifiers=frozenset({"email:a@b.com"}))
    (view,) = _collector([old]).collect(IdentityProfile(None, emails={"a@b.com"}), AUDIT, since=AUDIT - timedelta(days=14))
    assert view.in_window is False


# ---- 3. sixth log dialect, owner_key propagation, *_loaded outcomes ---------------------------
PIPE_LOG = (
    '2026-07-03T07:54:08Z | DEBUG | export_service | tr-41 | export_download_check_started | owner_key="a@b.com" attempt="1"\n'
    '2026-07-03T07:54:16Z | INFO | export_service | tr-41 | export_download_check_completed | resource_id="export_5" available="true"\n'
    '2026-07-03T07:56:56Z | DEBUG | legal_service | tr-42 | retained_order_query_started | subject_ref="user_2"\n'
    '2026-07-03T07:57:01Z | INFO | legal_service | tr-42 | retained_order_loaded | resource_id="legal_hold_7" access="allowed"\n'
    '2026-07-03T07:58:00Z | WARN | analytics_platform | tr-43 | analytics_identity_scan | resource_id="analytics_3" matched_value="a@b.com"\n'
)


def test_pipe_delimited_log_dialect():
    recs = {r.resource_id: r for r in LogExtractor().extract(make_file(path="x.log"), PIPE_LOG.encode())}
    assert recs["export_5"].state == ResourceState.PRESENT and "email:a@b.com" in recs["export_5"].identifiers
    assert not recs["export_5"].exposed_kinds  # owner_key is a query key, not stored content
    assert recs["legal_hold_7"].state == ResourceState.PRESENT and "user:user_2" in recs["legal_hold_7"].identifiers
    assert recs["analytics_3"].state == ResourceState.PRESENT and "email" in recs["analytics_3"].exposed_kinds


# ---- 4. final review: replica JSON payloads, screenshot detail panels, required checks -----------
def test_sql_json_payload_columns_are_parsed():
    """Regression: replica tables store the record in a record_json column; its restore_allowed /
    enabled / [REDACTED] fields were ignored, producing false findings (e.g. a redacted ticket
    reported as a remaining record)."""
    from deletion_auditor.domain.enums import DataCategory
    from deletion_auditor.infrastructure.extractors import SqlSnapshotExtractor

    sql = b"""CREATE TABLE customer_data_primary (resource_id TEXT, origin_system TEXT, record_json TEXT);
INSERT INTO customer_data_primary VALUES ('backup_1','backup_service','{"resource_id":"backup_1","subject_reference":"user_5","restore_allowed":false}');
INSERT INTO customer_data_primary VALUES ('data_flow_1','integration_service','{"resource_id":"data_flow_1","subject_selector":"user_5","enabled":false}');
INSERT INTO customer_data_primary VALUES ('support_1','support_platform','{"resource_id":"support_1","ticket_id":"CS-1","subject_reference":"user_5","message_text":"[REDACTED]"}');
"""
    recs = {r.resource_id: r for r in SqlSnapshotExtractor().extract(make_file(path="x.sql"), sql)}
    assert recs["backup_1"].restore_allowed is False
    assert recs["data_flow_1"].flow_enabled is False
    s = recs["support_1"]
    assert s.redacted_marker and s.category == DataCategory.SUPPORT_MESSAGE and s.has_user_reference


def test_screenshot_detail_panel_carries_the_selected_records_state():
    from deletion_auditor.infrastructure.extractors import ImageOcrExtractor
    from deletion_auditor.infrastructure.interpreters import RuleBasedInterpreter

    page = "Connections | data_flow_1121 customer_analytics_warehouse | data_flow_9846 lucia@x.com"
    cases = {
        "data_flow_1121\nStatus Healthy\nOwner Data Platform\nSelector jain@x.com\nSync mode Continuous sync": (
            "flow_enabled",
            True,
        ),
        "data_flow_1121\nStatus Paused\nSelector jain@x.com": ("flow_enabled", False),
        "export_1260\nOwner ingrid@x.com\nExpires 25 Jun 2026\nActivity\nReady for download": ("state", ResourceState.PRESENT),
        "backup_9287\nAccount areed@x.com\nChecksum Verified\nRetention end 26 Jul 2026": ("restore_allowed", None),
    }
    for panel, (attr, expected) in cases.items():
        x = ImageOcrExtractor(RuleBasedInterpreter(), ocr=lambda b: page, panel_ocr=lambda b, p=panel: p)
        rid = panel.split("\n")[0]
        (rec_,) = [r for r in x.extract(make_file(path="s.png"), b"img") if r.resource_id == rid]
        assert getattr(rec_, attr) == expected, panel
        assert rec_.exposed_kinds == {"email"}


def test_undetermined_record_gets_required_check_but_no_finding():
    rules = [DeletionRule("r14", DataCategory.BACKUP_ARCHIVE, "restore can be blocked", RuleType.RETAIN)]
    assert PolicyEvaluator(rules).required_check(DataCategory.BACKUP_ARCHIVE) == Operation.VERIFY_RESTORE_BLOCKED
    d = StatusDecider().decide(YES, [], unresolved=["backup_9"])
    steps = StepPlanner().plan(d, [], [(Operation.VERIFY_RESTORE_BLOCKED, "backup_service", "backup_9")])
    assert [(s.phase.value, s.operation, s.evidence_id) for s in steps] == [
        ("VERIFICATION", Operation.VERIFY_RESTORE_BLOCKED, "")
    ]
    # never added to a COMPLETE plan
    ok = ResourceAssessment(
        "account_service",
        "account_1",
        DataCategory.USER_PROFILE,
        RuleType.DELETE,
        True,
        None,
        None,
        Operation.VERIFY_RECORD_ABSENT,
        evidence_id="ev_1",
    )
    done = StatusDecider().decide(YES, [ok])
    assert [s.operation for s in StepPlanner().plan(done, [ok], [(Operation.VERIFY_RESTORE_BLOCKED, "backup_service", "b")])] == [
        Operation.VERIFY_RECORD_ABSENT
    ]


def test_alias_link_is_not_admissible_before_the_catalog_published_it():
    """Regression: catalog aliases were applied regardless of time, so a document could be attributed
    to a resource before the data catalog had linked them."""
    from deletion_auditor.infrastructure.interpreters import RuleBasedInterpreter

    alias_time = ts("2026-07-18T11:07:01Z")
    interp = RuleBasedInterpreter({"NST-0001": ("export_42", "export_service", alias_time)})
    doc = make_file(path="s.pdf", origin="account_history_service", captured="2026-07-18T11:00:00Z")
    (r,) = interp.interpret("STATEMENT\nNST-0001\nana@example.com\nbob@example.com\n", doc)
    assert r.captured_at == alias_time  # admissible only once both document and alias exist
    assert not EvidenceCollector.admissible(r, ts("2026-07-18T11:05:00Z"))
    assert EvidenceCollector.admissible(r, ts("2026-07-18T11:10:00Z"))
