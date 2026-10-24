"""Evidence interpretation rules shared by every extractor."""

from deletion_auditor.domain.enums import DataCategory, EvidenceType, ResourceState
from deletion_auditor.infrastructure.record_builder import build_record
from tests.conftest import make_file

F = make_file()


def rec(fields, **kw):
    return build_record(fields, F, EvidenceType.JSON, **kw)


def test_requires_resource_id():
    assert rec({"email": "a@b.com"}) is None
    assert rec({"resource_id": "not an id"}) is None


def test_system_inferred_from_prefix():
    assert rec({"resource_id": "data_flow_12"}).system_id == "integration_service"
    assert rec({"resource_id": "audit_record_9"}).system_id == "security_service"


def test_404_lookup_is_absent_and_lookup_key_links_without_exposing():
    r = rec({"resource_id": "account_1", "status_code": 404, "lookup_key": "a@b.com"})
    assert r.state == ResourceState.ABSENT
    assert "email:a@b.com" in r.identifiers
    assert not r.exposed_kinds


def test_record_content_exposes_direct_identifiers():
    r = rec({"resource_id": "search_1", "email": "a@b.com", "display_name": "Ana Lima"})
    assert r.state == ResourceState.PRESENT
    assert r.exposed_kinds == {"email", "name"}


def test_user_reference_is_not_direct_identifier():
    r = rec({"resource_id": "support_1", "customer_reference": "user_7", "message_text": "[REDACTED]"})
    assert r.has_user_reference and not r.exposed_kinds and r.redacted_marker


def test_flow_and_restore_flags():
    assert rec({"resource_id": "data_flow_1", "enabled": "1"}).flow_enabled is True
    assert rec({"resource_id": "data_flow_1", "enabled": False}).flow_enabled is False
    assert rec({"resource_id": "backup_1", "restore_allowed": "0"}).restore_allowed is False
    assert rec({"resource_id": "backup_1", "eligible": "true", "deletion_block": "false"}).restore_allowed is True
    assert rec({"resource_id": "backup_1", "decision": "deny"}).restore_allowed is False


def test_tombstone_account_status_deleted_means_row_present():
    r = rec({"resource_id": "tombstone_1", "account_status": "DELETED", "email": "a@b.com"})
    assert r.state == ResourceState.PRESENT and "email" in r.exposed_kinds


def test_integrity_seal_hash_is_not_an_identifier():
    r = rec({"resource_id": "audit_record_1", "integrity_seal": "sha256:" + "0" * 64})
    assert not r.identifiers


def test_explicit_category_and_hints():
    assert rec({"resource_id": "support_1", "record_type": "SUPPORT_ATTACHMENT"}).category == DataCategory.SUPPORT_ATTACHMENT
    assert rec({"resource_id": "support_1", "message_text": "hi"}).category == DataCategory.SUPPORT_MESSAGE
    assert rec({"resource_id": "analytics_1", "email_opt_in": "true"}).category == DataCategory.MARKETING_PROFILE


def test_nested_documents_are_flattened():
    r = rec({"resource_id": "search_1", "hits": {"total": 0, "documents": []}})
    assert r.state == ResourceState.ABSENT
