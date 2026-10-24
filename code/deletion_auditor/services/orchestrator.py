"""AuditOrchestrator: runs the per-case pipeline over injected collaborators.

intent -> identity -> evidence -> recreation risk + policy -> status -> steps -> invariants
"""

from __future__ import annotations

import logging
from typing import Protocol

from ..domain.enums import AuditStatus
from ..domain.models import AuditDecision, AuditResult, DeletionRequest
from ..interfaces.ml import IntentClassifier
from ..validation.validators import DecisionInvariantValidator
from .evidence_collector import EvidenceCollector
from .identity_resolver import IdentityResolver
from .policy_evaluator import PolicyEvaluator
from .recreation_risk import RecreationRiskAnalyzer
from .status_decider import StatusDecider
from .step_planner import StepPlanner

log = logging.getLogger(__name__)


class EventSink(Protocol):
    def log(self, event: str, details: dict) -> None: ...


class _NullSink:
    def log(self, event: str, details: dict) -> None:
        pass


class AuditOrchestrator:
    def __init__(
        self,
        intent_classifier: IntentClassifier,
        identity_resolver: IdentityResolver,
        evidence_collector: EvidenceCollector,
        policy_evaluator: PolicyEvaluator,
        risk_analyzer: RecreationRiskAnalyzer,
        status_decider: StatusDecider,
        step_planner: StepPlanner,
        invariant_validator: DecisionInvariantValidator | None = None,
        sink: EventSink | None = None,
        scope_to_request_window: bool = True,
    ):
        self.scope_to_request_window = scope_to_request_window
        self.intent_classifier = intent_classifier
        self.identity_resolver = identity_resolver
        self.evidence_collector = evidence_collector
        self.policy_evaluator = policy_evaluator
        self.risk_analyzer = risk_analyzer
        self.status_decider = status_decider
        self.step_planner = step_planner
        self.invariant_validator = invariant_validator or DecisionInvariantValidator()
        self.sink = sink or _NullSink()
        self.errors: list[tuple[str, str]] = []

    def audit(self, requests: list[DeletionRequest]) -> list[AuditResult]:
        return [self.audit_one(r) for r in requests]

    def audit_one(self, request: DeletionRequest) -> AuditResult:
        try:
            return self._audit(request)
        except Exception as exc:  # one bad case must not abort the batch; it is reported loudly
            log.exception("case %s failed", request.case_id)
            self.errors.append((request.case_id, repr(exc)))
            self.sink.log("case_error", {"case_id": request.case_id, "error": repr(exc)})
            return AuditResult(
                case_id=request.case_id,
                decision=AuditDecision(AuditStatus.INCOMPLETE, f"audit failed: {exc!r}", 0.0),
                warnings=[f"pipeline error: {exc!r}"],
            )

    def _audit(self, request: DeletionRequest) -> AuditResult:
        intent = self.intent_classifier.classify(request)
        if not intent.authorizes_deletion:
            decision = self.status_decider.decide(intent, [])
            self.sink.log(
                "case",
                {
                    "case_id": request.case_id,
                    "status": decision.status.value,
                    "intent": intent.rationale,
                    "intent_source": intent.source,
                },
            )
            return AuditResult(request.case_id, decision)

        profile = self.identity_resolver.resolve(request)
        since = request.requested_at if self.scope_to_request_window else None
        views = self.evidence_collector.collect(profile, request.audit_at, since)
        assessments = self.risk_analyzer.analyze(views, request.audit_at) + self.policy_evaluator.evaluate(
            views, request.audit_at
        )
        decision = self.status_decider.decide(intent, assessments)
        steps = self.step_planner.plan(decision, assessments)
        result = AuditResult(request.case_id, decision, steps, assessments)

        if profile.primary_id is None:
            result.warnings.append("request email not found in current or historical identities")
        if not assessments:
            result.warnings.append("no admissible evidence linked to the subject")
        result.warnings += [f"{a.resource_id}: {a.rationale}" for a in assessments if a.verification is None]
        violations = self.invariant_validator.validate_result(result)
        if violations:
            raise AssertionError("; ".join(violations))

        self.sink.log(
            "case",
            {
                "case_id": request.case_id,
                "status": decision.status.value,
                "subject": profile.primary_id,
                "resources": len(views),
                "steps": len(steps),
                "warnings": result.warnings,
            },
        )
        return result
