"""Applies deletion_rules.csv to the reconstructed state of every stored record."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..domain.catalog import DEFAULT_CATEGORY_ACTION
from ..domain.enums import DataCategory, Operation, ResourceState, RuleType
from ..domain.models import DeletionRule, EvidenceRecord, ResourceAssessment
from .evidence_collector import ResourceView
from .recreation_risk import RISK_CATEGORIES


@dataclass(frozen=True)
class Verdict:
    compliant: bool
    finding: Operation | None
    remediation: Operation | None
    verification: Operation | None
    rationale: str = field(compare=False)  # explanatory only; two observations agree if the operations agree


ABSENT_OK = Verdict(True, None, None, Operation.VERIFY_RECORD_ABSENT, "record absent")


def verdict_for(action: RuleType, record: EvidenceRecord) -> Verdict | None:
    """Pure policy decision for one observation. None = the observation proves nothing."""
    present = record.state == ResourceState.PRESENT
    absent = record.state == ResourceState.ABSENT
    exposes_direct = bool(record.exposed_kinds) and not record.redacted_marker
    if action == RuleType.DELETE:
        if absent:
            return ABSENT_OK
        if present:
            return Verdict(
                False,
                Operation.REPORT_REMAINING_RECORD,
                Operation.DELETE_RECORD,
                Operation.VERIFY_RECORD_ABSENT,
                "record still present",
            )
        return None
    if action == RuleType.REDACT:
        if not present:
            return None
        if exposes_direct:
            return Verdict(
                False,
                Operation.REPORT_EXPOSED_PII,
                Operation.REDACT_RECORD,
                Operation.VERIFY_RECORD_REDACTED,
                f"exposes {sorted(record.exposed_kinds)}",
            )
        return Verdict(True, None, None, Operation.VERIFY_RECORD_REDACTED, "no direct identifiers")
    if action == RuleType.ANONYMIZE:
        if absent:
            return ABSENT_OK
        if not present:
            return None
        if exposes_direct or (record.has_user_reference and not record.anonymized_marker):
            return Verdict(
                False,
                Operation.REPORT_EXPOSED_PII,
                Operation.ANONYMIZE_RECORD,
                Operation.VERIFY_RECORD_ANONYMIZED,
                "record still attributable",
            )
        return Verdict(True, None, None, Operation.VERIFY_RECORD_ANONYMIZED, "not attributable")
    if action == RuleType.RETAIN:
        if absent:
            # A record that policy requires to be retained is gone. No allowed operation restores
            # it, so it is reported as unresolved (never COMPLETE) with the check that must pass.
            return Verdict(False, None, None, Operation.VERIFY_RECORD_PRESENT, "required retained record missing")
        if present:
            return Verdict(True, None, None, Operation.VERIFY_RECORD_PRESENT, "retained by policy")
    return None


class PolicyEvaluator:
    def __init__(self, rules: list[DeletionRule]):
        self._actions: dict[DataCategory, RuleType] = dict(DEFAULT_CATEGORY_ACTION)
        for rule in rules:
            self._actions[rule.data_category] = rule.action

    REQUIRED_CHECK = {
        RuleType.DELETE: Operation.VERIFY_RECORD_ABSENT,
        RuleType.REDACT: Operation.VERIFY_RECORD_REDACTED,
        RuleType.ANONYMIZE: Operation.VERIFY_RECORD_ANONYMIZED,
        RuleType.RETAIN: Operation.VERIFY_RECORD_PRESENT,
    }

    def required_check(self, category: DataCategory | None) -> Operation | None:
        """The post-condition policy requires for a record of this category, independent of its
        current (possibly unknown) state. Used for checks that must pass on an INCOMPLETE case."""
        if category == DataCategory.DATA_FLOW:
            return Operation.VERIFY_DATA_FLOW_DISABLED
        if category == DataCategory.BACKUP_ARCHIVE:
            return Operation.VERIFY_RESTORE_BLOCKED
        if category is None:
            return None
        return self.REQUIRED_CHECK.get(self._actions.get(category, RuleType.DELETE))

    def required_action(self, category: DataCategory, record: EvidenceRecord, audit_at: datetime) -> RuleType:
        action = self._actions.get(category, RuleType.DELETE)
        if action == RuleType.RETAIN and category == DataCategory.SECURITY_AUDIT_LOG:
            # rule_12 only applies "within the supplied retention period".
            expiry = record.retention_until
            if expiry is not None and expiry < audit_at:
                return RuleType.DELETE
        return action

    def evaluate(self, views: list[ResourceView], audit_at: datetime) -> list[ResourceAssessment]:
        out = []
        for view in views:
            category = view.category
            if category is None or category in RISK_CATEGORIES:
                continue
            current = view.current()
            if current is None:
                continue  # linked, but no observation proves its state
            action = self.required_action(category, current, audit_at)
            verdict = verdict_for(action, current)
            if verdict is None:
                continue
            cite = view.citable(audit_at, lambda r, a=action, v=verdict: verdict_for(a, r) == v)
            out.append(
                ResourceAssessment(
                    system_id=view.system_id,
                    resource_id=view.resource_id,
                    category=category,
                    required_action=action,
                    compliant=verdict.compliant,
                    finding=verdict.finding,
                    remediation=verdict.remediation,
                    verification=verdict.verification,
                    evidence_id=cite.evidence_id if cite else "",
                    rationale=verdict.rationale,
                )
            )
        return out
