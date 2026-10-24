"""Derives the case status from the intent decision and the per-resource assessments."""

from __future__ import annotations

from ..domain.enums import AuditStatus
from ..domain.models import AuditDecision, IntentDecision, ResourceAssessment


class StatusDecider:
    def decide(self, intent: IntentDecision, assessments: list[ResourceAssessment]) -> AuditDecision:
        if not intent.authorizes_deletion:
            return AuditDecision(AuditStatus.NOT_APPLICABLE, f"no deletion authorised ({intent.rationale})", intent.confidence)
        open_items = [a for a in assessments if not a.compliant]
        if open_items:
            names = ", ".join(f"{a.resource_id}:{a.rationale}" for a in open_items[:5])
            return AuditDecision(AuditStatus.INCOMPLETE, f"{len(open_items)} unresolved item(s): {names}")
        return AuditDecision(AuditStatus.COMPLETE, f"{len(assessments)} item(s) verified compliant")
