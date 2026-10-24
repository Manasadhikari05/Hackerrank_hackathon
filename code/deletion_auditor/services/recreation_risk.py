"""Detects processes that can copy or recreate the subject's data (sync flows, restorable backups)."""

from __future__ import annotations

from datetime import datetime

from ..domain.enums import DataCategory, Operation, RuleType
from ..domain.models import ResourceAssessment
from .evidence_collector import ResourceView

RISK_CATEGORIES = (DataCategory.DATA_FLOW, DataCategory.BACKUP_ARCHIVE)


class RecreationRiskAnalyzer:
    def handles(self, view: ResourceView) -> bool:
        return view.category in RISK_CATEGORIES

    def analyze(self, views: list[ResourceView], audit_at: datetime) -> list[ResourceAssessment]:
        out = []
        for view in views:
            if not self.handles(view):
                continue
            assessment = self._assess(view, audit_at)
            if assessment:
                out.append(assessment)
        return out

    def _assess(self, view: ResourceView, audit_at: datetime) -> ResourceAssessment | None:
        is_flow = view.category == DataCategory.DATA_FLOW
        attr = "flow_enabled" if is_flow else "restore_allowed"
        records = [r for r in view.informative() if getattr(r, attr) is not None]
        if not records:
            return None
        latest = max(records, key=lambda r: (r.observed_at, r.captured_at, r.evidence_id))
        risky = bool(getattr(latest, attr))
        cite = view.citable(audit_at, lambda r: getattr(r, attr) is not None and bool(getattr(r, attr)) == risky)
        if is_flow:
            ops = (Operation.REPORT_ACTIVE_DATA_FLOW, Operation.DISABLE_DATA_FLOW, Operation.VERIFY_DATA_FLOW_DISABLED)
            why = "data flow enabled" if risky else "data flow disabled"
        else:
            ops = (Operation.REPORT_RESTORE_RISK, Operation.BLOCK_RESTORE, Operation.VERIFY_RESTORE_BLOCKED)
            why = "backup restore allowed" if risky else "backup restore blocked"
        return ResourceAssessment(
            system_id=view.system_id,
            resource_id=view.resource_id,
            category=view.category,
            required_action=None if is_flow else RuleType.RETAIN,
            compliant=not risky,
            finding=ops[0] if risky else None,
            remediation=ops[1] if risky else None,
            verification=ops[2],
            evidence_id=cite.evidence_id if cite else "",
            rationale=why,
        )
