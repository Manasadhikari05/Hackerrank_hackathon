"""Enumerations that mirror the official output contract (problem_statement.md)."""

from __future__ import annotations

from enum import Enum


class AuditStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class StepPhase(str, Enum):
    # The UML proposed IDENTIFY/ANALYZE/REMEDIATE/VERIFY; the contract only allows these three.
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class RuleType(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class EvidenceType(str, Enum):
    CSV = "CSV"
    JSON = "JSON"
    PDF = "PDF"
    IMAGE = "IMAGE"
    SQL = "SQL"
    LOG = "LOG"
    TEXT = "TEXT"
    ACTIVITY = "ACTIVITY"
    OTHER = "OTHER"


class ResourceState(str, Enum):
    """Normalized state of one resource as seen by one observation."""

    PRESENT = "PRESENT"  # record exists (may or may not expose identifiers)
    ABSENT = "ABSENT"  # record confirmed gone
    UNKNOWN = "UNKNOWN"  # observation names the resource but proves nothing about existence


class Operation(str, Enum):
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class DataCategory(str, Enum):
    """Categories from deletion_rules.csv plus the two non-record process categories."""

    USER_PROFILE = "USER_PROFILE"
    SECONDARY_IDENTIFIER = "SECONDARY_IDENTIFIER"
    SEARCH_INDEX_ENTRY = "SEARCH_INDEX_ENTRY"
    CACHE_ENTRY = "CACHE_ENTRY"
    SUPPORT_MESSAGE = "SUPPORT_MESSAGE"
    SUPPORT_ATTACHMENT = "SUPPORT_ATTACHMENT"
    ANALYTICS_PROFILE = "ANALYTICS_PROFILE"
    PRODUCT_TELEMETRY = "PRODUCT_TELEMETRY"
    USER_EXPORT = "USER_EXPORT"
    MARKETING_PROFILE = "MARKETING_PROFILE"
    EMAIL_DELIVERY_LOG = "EMAIL_DELIVERY_LOG"
    SECURITY_AUDIT_LOG = "SECURITY_AUDIT_LOG"
    LEGAL_HOLD_RECORD = "LEGAL_HOLD_RECORD"
    BACKUP_ARCHIVE = "BACKUP_ARCHIVE"
    ACCOUNT_TOMBSTONE = "ACCOUNT_TOMBSTONE"
    DATA_FLOW = "DATA_FLOW"  # sync/integration process, not a stored record
