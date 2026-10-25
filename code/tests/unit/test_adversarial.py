"""Adversarial regression tests from the independent audit (synthetic data only)."""

import csv
import importlib.util
import json
import os

import pytest

from deletion_auditor.domain.enums import EvidenceType, ResourceState
from deletion_auditor.domain.identifiers import email_hash
from deletion_auditor.domain.models import ActivityEvent, EvidenceRecord, IdentityChange, IdentitySnapshot
from deletion_auditor.infrastructure.activity_adapter import ActivityEvidenceAdapter
from deletion_auditor.infrastructure.extractors import SqlSnapshotExtractor
from deletion_auditor.infrastructure.intent import RuleBasedIntentClassifier
from deletion_auditor.infrastructure.repositories import CsvRequestRepository, MalformedInputError
from deletion_auditor.services.evidence_collector import EvidenceCollector, ResourceView, merge_pessimistic
from deletion_auditor.services.identity_resolver import IdentityResolver
from tests.conftest import CODE_DIR, make_file, make_request, ts

AUDIT = "2026-09-20T00:00:00Z"


# ---- identity as of audit_at -----------------------------------------------------------------------
def _moved_email_resolver():
    """x@ex.com belonged to user_b until 2026-10-01, then moved to user_s (after the audit)."""
    snaps = [
        IdentitySnapshot("user_s", "Sam", "x@ex.com", "+1 202 555 0100", email_hash("x@ex.com"), ts("2026-10-01T00:00:00Z")),
        IdentitySnapshot(
            "user_b", "Bea", "b-new@ex.com", "+1 202 555 0199", email_hash("b-new@ex.com"), ts("2026-10-01T00:00:00Z")
        ),
    ]
    changes = [
        IdentityChange("a1", "user_b", ts("2026-10-01T00:00:00Z"), "email", "x@ex.com", "b-new@ex.com"),
        IdentityChange("a2", "user_s", ts("2026-10-01T00:00:01Z"), "email", "s-old@ex.com", "x@ex.com"),
    ]
    return IdentityResolver(snaps, changes)


def test_email_acquired_after_audit_is_not_the_subjects_at_audit_time():
    """Regression: the current snapshot was used unconditionally, so an email the subject only obtained
    after audit_at (held by someone else at audit time) linked that other person's evidence."""
    r = _moved_email_resolver()
    p = r.resolve(make_request(email="s-old@ex.com", audit=AUDIT))
    assert p.primary_id == "user_s"
    assert "x@ex.com" not in p.emails and "s-old@ex.com" in p.emails
    # the request email x@ex.com at audit time belonged to user_b
    assert r.resolve(make_request(email="x@ex.com", audit=AUDIT)).primary_id == "user_b"
    # after both changes, the same email resolves to the new holder
    assert r.resolve(make_request(email="x@ex.com", audit="2026-10-05T00:00:00Z")).primary_id == "user_s"


# ---- intent: negated deletion wording --------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "I do not want my account deleted. I just need my invoices.",
        "I never asked you to remove my profile; please restore my login.",
        "No need to erase my data, just unsubscribe me from newsletters.",
    ],
)
def test_negated_deletion_is_not_an_authorisation(text):
    """Regression: these were classified as deletion requests with 0.95 confidence."""
    assert not RuleBasedIntentClassifier().classify(make_request(text=text)).authorizes_deletion


@pytest.mark.parametrize(
    "text",
    [
        "Your system did not delete my data last time. Please delete my account now.",
        "I have not used this account in years; please erase it.",
        "Je demande la suppression de mon compte, je ne veux pas le garder.",
    ],
)
def test_an_affirmative_deletion_mention_still_authorises(text):
    assert RuleBasedIntentClassifier().classify(make_request(text=text)).authorizes_deletion


# ---- untrusted SQL evidence ------------------------------------------------------------------------
def test_sql_evidence_cannot_write_files(tmp_path):
    """Regression: ATTACH in an evidence script created a database file on disk."""
    target = tmp_path / "written.db"
    sql = (
        f"ATTACH DATABASE '{target}' AS evil; CREATE TABLE evil.t(a);"
        "CREATE TABLE x(resource_id TEXT); INSERT INTO x VALUES ('account_1');"
    ).encode()
    SqlSnapshotExtractor().extract(make_file(path="x.sql"), sql)
    assert not os.path.exists(target)
    ok = b"CREATE TABLE x(resource_id TEXT); INSERT INTO x VALUES ('account_1');"
    assert [r.resource_id for r in SqlSnapshotExtractor().extract(make_file(path="x.sql"), ok)] == ["account_1"]


# ---- validator: transcript must be append-only -----------------------------------------------------
def _validator():
    spec = importlib.util.spec_from_file_location("vs", CODE_DIR / "evaluation" / "validate_submission.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ENTRY = "## [2026-01-01T00:00:00Z] {t}\n\nUser Prompt (verbatim, secrets redacted):\nx\n\nAgent Response Summary:\ny\n\nActions:\n* z\n\nContext:\ntool=Claude Code\nmodel=m-1\n"


def test_validator_flags_deleted_log_entries(tmp_path, monkeypatch):
    """Regression: removed transcript entries passed every per-entry check."""
    vs = _validator()
    start = "## [2026-01-01T00:00:00Z] SESSION START\n\ntool=Claude Code\nmodel=m-1\n\n"
    committed = start + ENTRY.format(t="one") + "\n" + ENTRY.format(t="two")
    log = tmp_path / "log.txt"
    for working, ok in ((committed + "\n" + ENTRY.format(t="three"), True), (start + ENTRY.format(t="two"), False)):
        log.write_text(working)
        monkeypatch.setattr(vs, "committed_log", lambda p, c=committed: c)
        report = vs.Report()
        vs.check_log(log, report)
        errors = report.sections[0][1]
        assert (errors == []) is ok, errors


# ---- evidence conflicts, batches and boundaries ----------------------------------------------------
def _rec(ev, state, at="2026-09-10T00:00:00Z", captured=None):
    return EvidenceRecord(ev, EvidenceType.JSON, ts(captured or at), ts(at), "search_service", "search_1", state)


def test_conflicting_sources_at_the_same_instant_resolve_pessimistically_and_deterministically():
    a, b = _rec("ev_b", ResourceState.ABSENT), _rec("ev_a", ResourceState.PRESENT)
    for order in ([a, b], [b, a]):
        merged = merge_pessimistic(order)
        assert merged.state == ResourceState.PRESENT and merged.evidence_id == "ev_a"
    assert ResourceView("search_service", "search_1", [a, b]).current().state == ResourceState.PRESENT


@pytest.mark.parametrize(
    "observed,ok",
    [("2026-09-20T05:30:00+05:30", True), ("2026-09-20T05:30:01+05:30", False), ("2026-09-19T20:00:00-04:00", True)],
)
def test_cutoff_compares_instants_across_utc_offsets(observed, ok):
    rec = _rec("ev", ResourceState.PRESENT, at=observed, captured=observed)
    assert EvidenceCollector.admissible(rec, ts(AUDIT)) is ok


def test_batched_workflow_claims_never_link_or_prove_anything():
    """One deletion batch touching several customers' accounts: the claims are not evidence."""
    events = [
        ActivityEvent(
            f"act_{i}",
            ts("2026-09-02T10:00:00Z"),
            "DELETE_RECORD",
            "deletion_worker",
            "account_service",
            f"account_{i}",
            "SUCCESS",
            f"Deletion worker submitted primary profile account_{i}.",
        )
        for i in range(3)
    ]
    assert ActivityEvidenceAdapter().to_records(events) == []


# ---- malformed inputs --------------------------------------------------------------------------------
def test_unterminated_csv_quote_fails_fast(tmp_path):
    p = tmp_path / "req.csv"
    p.write_text(
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        'c1,a@b.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T00:00:00Z,2026-09-10T00:00:00Z,"never closed\n'
        "c2,b@b.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T00:00:00Z,2026-09-10T00:00:00Z,delete\n"
    )
    rows = list(csv.reader(open(p, newline="")))
    assert len(rows) == 2  # the stray quote makes csv merge request c2 into c1's text
    with pytest.raises(MalformedInputError, match="unterminated quote"):
        CsvRequestRepository(p).load_requests()


def test_multiline_request_text_without_embedded_rows_is_accepted(tmp_path):
    p = tmp_path / "req.csv"
    p.write_text(
        "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
        'c1,a@b.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T00:00:00Z,2026-09-10T00:00:00Z,"Please delete\nmy account."\n'
    )
    assert [r.case_id for r in CsvRequestRepository(p).load_requests()] == ["c1"]


def test_unexpected_types_in_json_evidence_do_not_crash():
    from deletion_auditor.infrastructure.extractors import JsonExtractor

    doc = {"records": [{"resource_id": "backup_1", "restore_allowed": "maybe", "subject_reference": 7, "email": ["a@b.com"]}]}
    (r,) = JsonExtractor().extract(make_file(), json.dumps(doc).encode())
    assert r.restore_allowed is None and "email:a@b.com" in r.identifiers


# ---- release-candidate audit -----------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "Please do not keep my data — delete it.",
        "Please do not keep my data, delete it.",
        "Please do not keep my data - delete it.",
    ],
)
def test_negated_other_action_does_not_negate_a_deletion(text):
    """Regression (introduced by the negation fix): 'do not keep ... delete it' was read as a refusal."""
    assert RuleBasedIntentClassifier().classify(make_request(text=text)).authorizes_deletion


@pytest.mark.parametrize(
    "body,needle",
    [
        (
            "c1,a@b.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T00:00:00Z,2026-09-10T00:00:00Z,Please delete, thanks\n",
            "more fields",
        ),
        ("c1,a@b.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T00:00:00Z,2026-09-10T00:00:00Z\n", "fewer fields"),
    ],
)
def test_shifted_csv_columns_fail_fast(tmp_path, body, needle):
    """Regression: an unquoted comma silently truncated request_text (surplus field dropped)."""
    p = tmp_path / "req.csv"
    p.write_text("case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n" + body)
    with pytest.raises(MalformedInputError, match=needle):
        CsvRequestRepository(p).load_requests()


def test_validator_matches_whole_identifiers_only():
    """Regression: substring matching let 'account_1' be 'found' inside 'account_10'."""
    vs = _validator()
    assert not vs.mentions("account_1", b"see account_10 and xaccount_1")
    assert vs.mentions("account_1", b"see account_1.")


def test_validator_detects_a_committed_truncation(tmp_path, monkeypatch):
    """Regression: comparing only with HEAD accepted a truncation that had itself been committed."""
    vs = _validator()
    start = "## [2026-01-01T00:00:00Z] SESSION START\n\ntool=Claude Code\nmodel=m-1\n\n"
    log = tmp_path / "log.txt"
    log.write_text(start + ENTRY.format(t="two"))  # entry "one" was removed and that removal committed
    monkeypatch.setattr(vs, "committed_log", lambda p: log.read_text())
    monkeypatch.setattr(vs, "historical_headers", lambda p: {"## [2026-01-01T00:00:00Z] one", "## [2026-01-01T00:00:00Z] two"})
    report = vs.Report()
    vs.check_log(log, report)
    assert any("missing" in e for e in report.sections[0][1])
