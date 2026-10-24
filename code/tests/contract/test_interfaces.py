"""Contract tests: every concrete implementation honours its abstract interface (Liskov)."""

import inspect

import pytest

from deletion_auditor.domain.enums import AuditStatus
from deletion_auditor.domain.models import (
    ActivityEvent,
    AuditDecision,
    AuditResult,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    EvidenceRecord,
    IdentityChange,
    IdentitySnapshot,
    IntentDecision,
)
from deletion_auditor.infrastructure.extractors import (
    ImageOcrExtractor,
    JsonExtractor,
    LogExtractor,
    PdfExtractor,
    SqlSnapshotExtractor,
    TextExtractor,
)
from deletion_auditor.infrastructure.intent import LLMIntentClassifier, RuleBasedIntentClassifier
from deletion_auditor.infrastructure.interpreters import LLMEvidenceInterpreter, RuleBasedInterpreter
from deletion_auditor.infrastructure.model_clients import ScriptedModelClient
from deletion_auditor.infrastructure.output_writer import CsvOutputWriter
from deletion_auditor.infrastructure.repositories import (
    CsvActivityRepository,
    CsvIdentityRepository,
    CsvPolicyRepository,
    CsvRequestRepository,
    FileEvidenceRepository,
)
from deletion_auditor.interfaces import (
    EvidenceExtractor,
    EvidenceInterpreter,
    IntentClassifier,
    ModelClient,
    OutputWriter,
)
from tests.conftest import CUSTOM_DATASET, OFFICIAL_RULES, make_file, make_request

INTERP = RuleBasedInterpreter()
EXTRACTORS = [
    (JsonExtractor(), "json"),
    (SqlSnapshotExtractor(), "sql"),
    (LogExtractor(), "log"),
    (TextExtractor(INTERP), "txt"),
    (PdfExtractor(INTERP), "pdf"),
    (ImageOcrExtractor(INTERP, ocr=lambda b: ""), "png"),
]


@pytest.mark.parametrize("extractor,ext", EXTRACTORS, ids=[e for _, e in EXTRACTORS])
def test_extractor_contract(extractor, ext):
    assert isinstance(extractor, EvidenceExtractor)
    f = make_file(path=f"evidence/a.{ext}")
    assert extractor.supports(f)
    assert not extractor.supports(make_file(path="evidence/a.xlsx"))
    for garbage in (b"", b"\x00\xff\xfe garbage", b"resource_id=account_1"):
        out = extractor.extract(f, garbage)  # must never raise
        assert isinstance(out, list) and all(isinstance(r, EvidenceRecord) for r in out)
        assert all(r.evidence_id == f.file_id for r in out)


def test_each_format_handled_by_exactly_one_extractor():
    for ext in ("json", "sql", "log", "txt", "pdf", "png"):
        f = make_file(path=f"a.{ext}")
        assert sum(e.supports(f) for e, _ in EXTRACTORS) == 1


@pytest.mark.parametrize("interp", [INTERP, LLMEvidenceInterpreter(ScriptedModelClient(['{"records": []}']), INTERP)])
def test_interpreter_contract_never_invents_ids(interp):
    assert isinstance(interp, EvidenceInterpreter)
    text = "Reference account_12 for a@example.com"
    out = interp.interpret(text, make_file())
    assert out and all(r.resource_id in text for r in out)


@pytest.mark.parametrize(
    "clf", [RuleBasedIntentClassifier(), LLMIntentClassifier(ScriptedModelClient(), RuleBasedIntentClassifier(), 0.0)]
)
def test_intent_contract(clf):
    assert isinstance(clf, IntentClassifier)
    assert isinstance(clf.classify(make_request()), IntentDecision)


def test_model_client_contract():
    c = ScriptedModelClient(['{"ok": true}'])
    assert isinstance(c, ModelClient)
    assert c.structured_generate("hi") == {"ok": True}
    assert c.usage.calls == 1 and c.usage.input_tokens > 0


def test_repositories_contract():
    ds = CUSTOM_DATASET
    reqs = CsvRequestRepository(ds / "deletion_requests.csv").load_requests()
    assert reqs and all(isinstance(r, DeletionRequest) for r in reqs)
    idr = CsvIdentityRepository(ds / "user_identities.csv", ds / "user_audit_log.csv")
    assert all(isinstance(i, IdentitySnapshot) for i in idr.load_identities())
    assert all(isinstance(c, IdentityChange) for c in idr.load_identity_changes())
    assert all(isinstance(r, DeletionRule) for r in CsvPolicyRepository(OFFICIAL_RULES).load_rules())
    assert all(isinstance(a, ActivityEvent) for a in CsvActivityRepository(ds / "system_activity.csv").load_activities())
    ev = FileEvidenceRepository(ds)
    files = ev.list_evidence()
    assert files and all(isinstance(f, EvidenceFile) for f in files)
    assert isinstance(ev.read_evidence(files[0].file_id), bytes)
    with pytest.raises(KeyError):
        ev.read_evidence("does_not_exist")


def test_writer_contract(tmp_path):
    w = CsvOutputWriter()
    assert isinstance(w, OutputWriter)
    assert w.get_schema()["columns"] == ["case_id", "deletion_status", "steps_json"]
    w.write(
        [
            AuditResult("case_2", AuditDecision(AuditStatus.NOT_APPLICABLE, "")),
            AuditResult("case_10", AuditDecision(AuditStatus.NOT_APPLICABLE, "")),
        ],
        tmp_path / "o.csv",
    )
    lines = (tmp_path / "o.csv").read_text().splitlines()
    assert lines == ["case_id,deletion_status,steps_json", "case_2,NOT_APPLICABLE,[]", "case_10,NOT_APPLICABLE,[]"]


def test_services_depend_only_on_abstractions():
    """Dependency inversion: the services layer never imports the infrastructure layer."""
    import importlib
    import pkgutil

    import deletion_auditor.services as services_pkg

    for mod in pkgutil.iter_modules(services_pkg.__path__):
        src = inspect.getsource(importlib.import_module(f"deletion_auditor.services.{mod.name}"))
        assert "infrastructure" not in src, mod.name
