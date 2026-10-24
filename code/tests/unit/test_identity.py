"""Identity matching: current + historical identifiers, decoys, time cut-off."""

from deletion_auditor.domain.identifiers import email_hash, tokens_from_text
from deletion_auditor.domain.models import IdentityChange, IdentitySnapshot
from deletion_auditor.services.identity_resolver import IdentityResolver
from tests.conftest import make_request, ts

SNAP = [
    IdentitySnapshot("user_1", "Ana Lima", "ana.lima@example.com", "+55 11 91234-5678", email_hash("ana.lima@example.com"), None),
    IdentitySnapshot(
        "user_2", "Ana Lima Jr", "ana.lima.jr@example.com", "+55 11 99999-0000", email_hash("ana.lima.jr@example.com"), None
    ),
]
CHANGES = [
    IdentityChange("audit_1", "user_1", ts("2025-01-01T00:00:00Z"), "email", "ana.old@example.com", "ana.lima@example.com"),
    IdentityChange("audit_2", "user_1", ts("2025-01-01T00:00:00Z"), "phone", "+55 11 90000-1111", "+55 11 91234-5678"),
    IdentityChange("audit_3", "user_1", ts("2027-01-01T00:00:00Z"), "email", "ana.lima@example.com", "ana.future@example.com"),
]


def resolver():
    return IdentityResolver(SNAP, CHANGES)


def test_current_email_resolves_with_history():
    p = resolver().resolve(make_request(email="ana.lima@example.com"))
    assert p.primary_id == "user_1"
    assert {"ana.lima@example.com", "ana.old@example.com"} <= p.emails
    assert "phone:5511900001111" in p.tokens  # historical phone
    assert "hash:" + email_hash("ana.old@example.com") in p.tokens  # hash of historical email


def test_historical_email_resolves_to_same_subject():
    p = resolver().resolve(make_request(email="ANA.OLD@example.com"))
    assert p.primary_id == "user_1"
    assert "audit_1" in p.audit_ids


def test_changes_after_audit_are_ignored():
    p = resolver().resolve(make_request(email="ana.lima@example.com", audit="2026-09-20T00:00:00Z"))
    assert "ana.future@example.com" not in p.emails


def test_decoy_similar_email_never_matches():
    p = resolver().resolve(make_request(email="ana.lima@example.com"))
    assert "email:ana.lima.jr@example.com" not in p.tokens
    assert "user:user_2" not in p.tokens


def test_unknown_email_still_searchable():
    p = resolver().resolve(make_request(email="nobody@example.com"))
    assert p.primary_id is None
    assert p.tokens == {"email:nobody@example.com", "hash:" + email_hash("nobody@example.com")}


def test_names_are_not_linking_tokens():
    p = resolver().resolve(make_request(email="ana.lima@example.com"))
    assert not any(t.startswith("name:") for t in p.tokens)


def test_tokens_from_text_extracts_all_kinds():
    text = "user_42 wrote from X.Y@Mail.com, phone +1 (202) 555-0103, hash " + "a" * 64
    toks = tokens_from_text(text)
    assert {"user:user_42", "email:x.y@mail.com", "phone:12025550103", "hash:" + "a" * 64} <= toks
