"""Composition root (UML: AuditApplication). The only place that knows concrete classes."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..domain.models import AuditResult, DeletionRequest
from ..infrastructure.activity_adapter import ActivityEvidenceAdapter
from ..infrastructure.extractors import (
    ImageOcrExtractor,
    JsonExtractor,
    LogExtractor,
    PdfExtractor,
    SqlSnapshotExtractor,
    TextExtractor,
)
from ..infrastructure.intent import LLMIntentClassifier, RuleBasedIntentClassifier
from ..infrastructure.interpreters import LLMEvidenceInterpreter, RuleBasedInterpreter
from ..infrastructure.output_writer import CsvOutputWriter
from ..infrastructure.repositories import (
    CsvActivityRepository,
    CsvIdentityRepository,
    CsvPolicyRepository,
    CsvRequestRepository,
    FileEvidenceRepository,
)
from ..interfaces.ml import IntentClassifier, ModelClient, ModelUsage
from ..interfaces.output import OutputWriter
from ..interfaces.processing import EvidenceInterpreter
from ..interfaces.repositories import (
    ActivityRepository,
    EvidenceRepository,
    IdentityRepository,
    PolicyRepository,
    RequestRepository,
)
from ..services.evidence_collector import EvidenceCollector
from ..services.identity_resolver import IdentityResolver
from ..services.orchestrator import AuditOrchestrator
from ..services.policy_evaluator import PolicyEvaluator
from ..services.recreation_risk import RecreationRiskAnalyzer
from ..services.status_decider import StatusDecider
from ..services.step_planner import StepPlanner
from ..validation.validators import EvidenceCatalog, validate_output_file
from .config import AppConfig
from .run_logger import RunLogger

log = logging.getLogger(__name__)


@dataclass
class RunSummary:
    cases: int
    status_counts: dict[str, int]
    errors: list[tuple[str, str]]
    output_path: Path
    seconds: float
    model_usage: list[ModelUsage] = field(default_factory=list)


@dataclass
class Dependencies:
    """Everything the pipeline needs, injectable for tests."""

    requests: RequestRepository
    identities: IdentityRepository
    policy: PolicyRepository
    activities: ActivityRepository
    evidence: EvidenceRepository
    writer: OutputWriter
    intent: IntentClassifier
    interpreter: EvidenceInterpreter
    model_client: ModelClient | None = None
    ocr: object | None = None
    # Receives data-catalog aliases at build time (may be the same object as `interpreter`).
    rule_interpreter: RuleBasedInterpreter | None = None


def default_dependencies(config: AppConfig) -> Dependencies:
    ds = config.dataset_dir
    rule_interpreter = RuleBasedInterpreter()
    intent: IntentClassifier = RuleBasedIntentClassifier()
    interpreter: EvidenceInterpreter = rule_interpreter
    client: ModelClient | None = None
    if config.use_llm:
        try:
            from ..infrastructure.model_clients import OpenAIModelClient

            client = OpenAIModelClient(config.llm_model)
            intent = LLMIntentClassifier(client, intent)
            interpreter = LLMEvidenceInterpreter(client, rule_interpreter)
        except (RuntimeError, ImportError) as exc:
            log.warning("LLM disabled: %s", exc)
    return Dependencies(
        requests=CsvRequestRepository(config.requests_path),
        identities=CsvIdentityRepository(ds / "user_identities.csv", ds / "user_audit_log.csv"),
        policy=CsvPolicyRepository(ds / "deletion_rules.csv"),
        activities=CsvActivityRepository(ds / "system_activity.csv"),
        evidence=FileEvidenceRepository(ds),
        writer=CsvOutputWriter(),
        intent=intent,
        interpreter=interpreter,
        model_client=client,
        rule_interpreter=rule_interpreter,
    )


class AuditApplication:
    def __init__(self, config: AppConfig, deps: Dependencies | None = None):
        self.config = config
        self.deps = deps or default_dependencies(config)
        self.run_logger = RunLogger(config.run_log_path)
        self._orchestrator: AuditOrchestrator | None = None
        self.catalog = EvidenceCatalog()

    def build(self) -> AuditOrchestrator:
        if self._orchestrator is not None:
            return self._orchestrator
        d = self.deps
        activities = d.activities.load_activities()
        adapter = ActivityEvidenceAdapter()
        if d.rule_interpreter is not None:
            d.rule_interpreter.set_aliases(adapter.aliases(activities))

        extractors = [
            SqlSnapshotExtractor(),
            JsonExtractor(),
            LogExtractor(),
            TextExtractor(d.interpreter),
            PdfExtractor(d.interpreter),
        ]
        if self.config.enable_ocr:
            extractors.append(ImageOcrExtractor(d.interpreter, ocr=d.ocr))
        collector = EvidenceCollector(d.evidence, extractors)
        collector.index(adapter.to_records(activities))

        identities = d.identities.load_identities()
        changes = d.identities.load_identity_changes()
        for ev in d.evidence.list_evidence():
            self.catalog.add(ev.file_id, ev.captured_at)
        for a in activities:
            self.catalog.add(a.activity_id, a.event_time)
        for c in changes:
            self.catalog.add(c.audit_id, c.event_time)

        self.run_logger.log("index", {k: v for k, v in sorted(collector.stats.items())})
        self._orchestrator = AuditOrchestrator(
            intent_classifier=d.intent,
            identity_resolver=IdentityResolver(identities, changes),
            evidence_collector=collector,
            policy_evaluator=PolicyEvaluator(d.policy.load_rules()),
            risk_analyzer=RecreationRiskAnalyzer(),
            status_decider=StatusDecider(),
            step_planner=StepPlanner(),
            sink=self.run_logger,
        )
        return self._orchestrator

    def audit(self, requests: list[DeletionRequest]) -> list[AuditResult]:
        return self.build().audit(requests)

    def run(self, validate: bool = True) -> RunSummary:
        start = time.perf_counter()
        requests = self.deps.requests.load_requests()
        results = self.audit(requests)
        self.deps.writer.write(results, self.config.output_path)
        if validate:
            try:
                validate_output_file(self.config.output_path, requests, self.catalog)
            except Exception as exc:
                self.run_logger.log("validation_failed", {"error": str(exc)[:2000]})
                self.run_logger.save_report()
                raise
        counts: dict[str, int] = {}
        for r in results:
            counts[r.status.value] = counts.get(r.status.value, 0) + 1
        orchestrator = self.build()
        usage = [self.deps.model_client.usage] if self.deps.model_client else []
        summary = RunSummary(
            cases=len(results),
            status_counts=dict(sorted(counts.items())),
            errors=list(orchestrator.errors),
            output_path=self.config.output_path,
            seconds=round(time.perf_counter() - start, 2),
            model_usage=usage,
        )
        self.run_logger.log(
            "summary",
            {
                "cases": summary.cases,
                "status_counts": summary.status_counts,
                "errors": len(summary.errors),
                "seconds": summary.seconds,
            },
        )
        self.run_logger.save_report()
        return summary
