"""Builds the ordered steps_json for a decided case.

Ordering follows problem_statement.md: FINDING -> REMEDIATION -> VERIFICATION; inside a phase,
the operation order of the official table, then system_id, then resource_id. This also satisfies
the safety rule that data flows are disabled and restores blocked before records are changed.
"""

from __future__ import annotations

from ..domain.catalog import OPERATION_SPECS, step_sort_key
from ..domain.enums import AuditStatus, Operation
from ..domain.models import AuditDecision, AuditStep, ResourceAssessment


class StepPlanner:
    def plan(self, decision: AuditDecision, assessments: list[ResourceAssessment]) -> list[AuditStep]:
        if decision.status == AuditStatus.NOT_APPLICABLE:
            return []
        # Steps that must cite evidence are only emitted when a citable (captured <= audit_at)
        # evidence item exists; we never cite later evidence or invent an id.
        drafts: list[tuple[Operation, str, str, str]] = []
        if decision.status == AuditStatus.COMPLETE:
            for a in assessments:
                if a.verification and a.evidence_id:
                    drafts.append((a.verification, a.system_id, a.resource_id, a.evidence_id))
        else:
            for a in assessments:
                if not a.compliant and a.finding and a.evidence_id:
                    drafts.append((a.finding, a.system_id, a.resource_id, a.evidence_id))
                if not a.compliant and a.remediation:
                    drafts.append((a.remediation, a.system_id, a.resource_id, ""))
                if a.verification:
                    drafts.append((a.verification, a.system_id, a.resource_id, ""))

        unique = {(op, sys_id, rid): ev for op, sys_id, rid, ev in drafts}
        ordered = sorted(unique.items(), key=lambda kv: step_sort_key(OPERATION_SPECS[kv[0][0]].phase, *kv[0]))
        return [
            AuditStep(
                step_no=i,
                phase=OPERATION_SPECS[op].phase,
                system_id=sys_id,
                resource_id=rid,
                operation=op,
                state=OPERATION_SPECS[op].state,
                evidence_id=ev,
            )
            for i, ((op, sys_id, rid), ev) in enumerate(ordered, start=1)
        ]
