"""Policy evaluation, recreation risk, state reconstruction, status decision and step ordering."""

from dataclasses import replace

from deletion_auditor.domain.enums import (
    AuditStatus,
    DataCategory,
    EvidenceType,
    Operation,
    ResourceState,
    RuleType,
    StepPhase,
)
from deletion_auditor.domain.models import DeletionRule, EvidenceRecord, IntentDecision
from deletion_auditor.services.evidence_collector import ResourceView
from deletion_auditor.services.policy_evaluator import PolicyEvaluator
from deletion_auditor.services.recreation_risk import RecreationRiskAnalyzer
from deletion_auditor.services.status_decider import StatusDecider
from deletion_auditor.services.step_planner import StepPlanner
from tests.conftest import ts

AUDIT = ts("2026-09-20T00:00:00Z")
RULES = [
    DeletionRule("r1", DataCategory.USER_PROFILE, "Always", RuleType.DELETE),
    DeletionRule("r5", DataCategory.SUPPORT_MESSAGE, "shared", RuleType.REDACT),
    DeletionRule("r7", DataCategory.ANALYTICS_PROFILE, "attributable", RuleType.ANONYMIZE),
    DeletionRule("r12", DataCategory.SECURITY_AUDIT_LOG, "retention", RuleType.RETAIN),
    DeletionRule("r15", DataCategory.ACCOUNT_TOMBSTONE, "tombstone", RuleType.REDACT),
]


def obs(rid, state=ResourceState.PRESENT, ev="ev_1", at="2026-09-10T00:00:00Z", captured=None, **kw):
    from deletion_auditor.domain.catalog import system_for_resource

    return EvidenceRecord(
        evidence_id=ev,
        evidence_type=EvidenceType.JSON,
        captured_at=ts(captured or at),
        observed_at=ts(at),
        system_id=system_for_resource(rid),
        resource_id=rid,
        state=state,
        **kw,
    )


def view(*records):
    return ResourceView(records[0].system_id, records[0].resource_id, list(records), ["ev_1"])


def evaluate(*views):
    return PolicyEvaluator(RULES).evaluate(list(views), AUDIT)


# ---- state reconstruction -------------------------------------------------------------------
def test_latest_observation_wins_over_older_conflicting_one():
    v = view(
        obs("account_1", ResourceState.PRESENT, "ev_old", "2026-09-01T00:00:00Z"),
        obs("account_1", ResourceState.ABSENT, "ev_new", "2026-09-15T00:00:00Z"),
    )
    (a,) = evaluate(v)
    assert a.compliant and a.verification == Operation.VERIFY_RECORD_ABSENT and a.evidence_id == "ev_new"


def test_replica_copy_beats_absent_primary_at_same_instant():
    v = view(
        obs("account_1", ResourceState.ABSENT, "ev_sql", source="sql:primary"),
        obs("account_1", ResourceState.PRESENT, "ev_sql", source="sql:replica", exposed_kinds=frozenset({"email"})),
    )
    (a,) = evaluate(v)
    assert not a.compliant and a.finding == Operation.REPORT_REMAINING_RECORD


def test_link_only_and_unknown_records_prove_nothing():
    v = view(obs("account_1", ResourceState.UNKNOWN, link_only=True))
    assert evaluate(v) == []


def test_uncitable_later_file_is_not_cited():
    # observed before audit but exported after it: usable for state, never cited
    v = view(obs("search_1", ResourceState.PRESENT, "ev_late", "2026-09-19T00:00:00Z", captured="2026-09-25T00:00:00Z"))
    (a,) = evaluate(v)
    assert not a.compliant and a.evidence_id == ""


# ---- policy -----------------------------------------------------------------------------
def test_support_message_with_identifier_needs_redaction():
    v = view(obs("support_1", exposed_kinds=frozenset({"email"}), category=DataCategory.SUPPORT_MESSAGE))
    (a,) = evaluate(v)
    assert (a.finding, a.remediation, a.verification) == (
        Operation.REPORT_EXPOSED_PII,
        Operation.REDACT_RECORD,
        Operation.VERIFY_RECORD_REDACTED,
    )


def test_redacted_support_message_is_compliant():
    v = view(obs("support_1", has_user_reference=True, redacted_marker=True, category=DataCategory.SUPPORT_MESSAGE))
    (a,) = evaluate(v)
    assert a.compliant and a.verification == Operation.VERIFY_RECORD_REDACTED


def test_analytics_with_user_reference_is_still_attributable():
    v = view(obs("analytics_1", has_user_reference=True))
    (a,) = evaluate(v)
    assert a.remediation == Operation.ANONYMIZE_RECORD


def test_anonymized_analytics_is_compliant():
    (a,) = evaluate(view(obs("analytics_1")))
    assert a.compliant and a.verification == Operation.VERIFY_RECORD_ANONYMIZED


def test_tombstone_keeps_user_id_but_not_direct_identifiers():
    ok = view(obs("tombstone_1", has_user_reference=True))
    bad = view(obs("tombstone_2", has_user_reference=True, exposed_kinds=frozenset({"email", "name"})))
    a_ok, a_bad = evaluate(ok, bad)
    assert a_ok.compliant and a_ok.verification == Operation.VERIFY_RECORD_REDACTED
    assert not a_bad.compliant and a_bad.remediation == Operation.REDACT_RECORD


def test_retained_security_record_is_verified_present_not_deleted():
    (a,) = evaluate(view(obs("audit_record_1", has_user_reference=True, retention_until=ts("2033-01-01T00:00:00Z"))))
    assert a.compliant and a.verification == Operation.VERIFY_RECORD_PRESENT and a.remediation is None


def test_expired_retention_requires_deletion():
    (a,) = evaluate(view(obs("audit_record_1", retention_until=ts("2026-01-01T00:00:00Z"))))
    assert a.required_action == RuleType.DELETE and a.remediation == Operation.DELETE_RECORD


# ---- recreation risk --------------------------------------------------------------------
def test_active_flow_and_restorable_backup_are_risks():
    flow = view(obs("data_flow_1", flow_enabled=True))
    backup = view(obs("backup_1", restore_allowed=True))
    risks = RecreationRiskAnalyzer().analyze([flow, backup], AUDIT)
    assert {r.finding for r in risks} == {Operation.REPORT_ACTIVE_DATA_FLOW, Operation.REPORT_RESTORE_RISK}


def test_disabled_flow_after_active_check_is_compliant():
    flow = view(
        obs("data_flow_1", flow_enabled=True, at="2026-09-01T00:00:00Z", ev="activity_1"),
        obs("data_flow_1", flow_enabled=False, at="2026-09-12T00:00:00Z", ev="ev_2"),
    )
    (r,) = RecreationRiskAnalyzer().analyze([flow], AUDIT)
    assert r.compliant and r.verification == Operation.VERIFY_DATA_FLOW_DISABLED and r.evidence_id == "ev_2"


# ---- status + planning ------------------------------------------------------------------
YES = IntentDecision(True, 0.9, "x", "rules")
NO = IntentDecision(False, 0.9, "x", "rules")


def test_non_deletion_request_is_not_applicable_with_no_steps():
    d = StatusDecider().decide(NO, [])
    assert d.status == AuditStatus.NOT_APPLICABLE
    assert StepPlanner().plan(d, []) == []


def test_complete_only_when_everything_compliant():
    (ok,) = evaluate(view(obs("account_1", ResourceState.ABSENT)))
    (bad,) = evaluate(view(obs("search_1")))
    assert StatusDecider().decide(YES, [ok]).status == AuditStatus.COMPLETE
    assert StatusDecider().decide(YES, [ok, bad]).status == AuditStatus.INCOMPLETE


def test_plan_orders_phases_operations_and_disables_flows_first():
    views = [
        view(obs("search_1")),
        view(obs("support_1", exposed_kinds=frozenset({"email"}), category=DataCategory.SUPPORT_MESSAGE)),
        view(obs("account_1", ResourceState.ABSENT)),
    ]
    assessments = RecreationRiskAnalyzer().analyze([view(obs("data_flow_1", flow_enabled=True))], AUDIT) + evaluate(*views)
    decision = StatusDecider().decide(YES, assessments)
    steps = StepPlanner().plan(decision, assessments)
    ops = [s.operation for s in steps]
    assert [s.step_no for s in steps] == list(range(1, len(steps) + 1))
    assert [s.phase for s in steps] == sorted(
        (s.phase for s in steps), key=[StepPhase.FINDING, StepPhase.REMEDIATION, StepPhase.VERIFICATION].index
    )
    assert ops.index(Operation.DISABLE_DATA_FLOW) < ops.index(Operation.DELETE_RECORD) < ops.index(Operation.REDACT_RECORD)
    remediation_and_future = [s for s in steps if s.phase != StepPhase.FINDING]
    assert all(s.evidence_id == "" for s in remediation_and_future)
    assert all(s.evidence_id for s in steps if s.phase == StepPhase.FINDING)


def test_complete_plan_cites_evidence_for_every_verification():
    (a,) = evaluate(view(obs("account_1", ResourceState.ABSENT, "ev_9")))
    steps = StepPlanner().plan(StatusDecider().decide(YES, [a]), [a])
    assert [(s.operation, s.evidence_id) for s in steps] == [(Operation.VERIFY_RECORD_ABSENT, "ev_9")]


def test_state_value_matches_operation():
    (a,) = evaluate(view(replace(obs("search_1"))))
    for s in StepPlanner().plan(StatusDecider().decide(YES, [a]), [a]):
        assert (
            s.state
            == {"REPORT_REMAINING_RECORD": "PRESENT", "DELETE_RECORD": "ABSENT", "VERIFY_RECORD_ABSENT": "ABSENT"}[
                s.operation.value
            ]
        )
