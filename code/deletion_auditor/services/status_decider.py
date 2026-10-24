"""Derives the case status from the intent decision and the per-resource assessments.

COMPLETE must be *proven*: problem_statement.md requires every relevant copy to have the required
treatment, and a COMPLETE row may contain only evidence-backed verification steps. Therefore
absence of evidence is never treated as evidence of absence:

* no admissible evidence links any record to the subject       -> INCOMPLETE (insufficient evidence)
* a linked record whose state at audit_at cannot be determined, or whose only (pre-request)
  observation shows a policy violation                          -> INCOMPLETE (insufficient evidence)
* a compliant verdict that no citable evidence supports         -> INCOMPLETE (insufficient evidence)
"""

from __future__ import annotations

from ..domain.enums import AuditStatus
from ..domain.models import AuditDecision, IntentDecision, ResourceAssessment


class StatusDecider:
    def decide(
        self,
        intent: IntentDecision,
        assessments: list[ResourceAssessment],
        unresolved: list[str] | tuple[str, ...] = (),
    ) -> AuditDecision:
        if not intent.authorizes_deletion:
            return AuditDecision(AuditStatus.NOT_APPLICABLE, f"no deletion authorised ({intent.rationale})", intent.confidence)
        open_items = [a for a in assessments if not a.compliant]
        if open_items:
            names = ", ".join(f"{a.resource_id}:{a.rationale}" for a in open_items[:5])
            return AuditDecision(AuditStatus.INCOMPLETE, f"{len(open_items)} unresolved item(s): {names}")
        reasons = []
        if not assessments:
            reasons.append("no admissible evidence links any record to the subject")
        unproven = [a.resource_id for a in assessments if not a.proven]
        if unproven:
            reasons.append(f"compliance not provable from evidence available at audit_at: {unproven[:5]}")
        if unresolved:
            reasons.append(f"linked record(s) not confirmed compliant during the request window: {list(unresolved)[:5]}")
        if reasons:
            return AuditDecision(
                AuditStatus.INCOMPLETE, "insufficient evidence: " + "; ".join(reasons), 0.5, insufficient_evidence=True
            )
        return AuditDecision(AuditStatus.COMPLETE, f"{len(assessments)} item(s) verified compliant")
