"""Static contract knowledge: allowed operations, their phase/state, and ordering.

Everything here is copied from problem_statement.md ("Allowed Operations" table and
"Rules" section). Keeping it in one place lets validators and the planner share a
single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import DataCategory, Operation, RuleType, StepPhase


@dataclass(frozen=True)
class OperationSpec:
    phase: StepPhase
    state: str
    order: int  # position in the official table; used for intra-phase ordering


OPERATION_SPECS: dict[Operation, OperationSpec] = {
    Operation.REPORT_REMAINING_RECORD: OperationSpec(StepPhase.FINDING, "PRESENT", 0),
    Operation.REPORT_EXPOSED_PII: OperationSpec(StepPhase.FINDING, "PRESENT", 1),
    Operation.REPORT_ACTIVE_DATA_FLOW: OperationSpec(StepPhase.FINDING, "ACTIVE", 2),
    Operation.REPORT_RESTORE_RISK: OperationSpec(StepPhase.FINDING, "ACTIVE", 3),
    Operation.DISABLE_DATA_FLOW: OperationSpec(StepPhase.REMEDIATION, "DISABLED", 4),
    Operation.BLOCK_RESTORE: OperationSpec(StepPhase.REMEDIATION, "BLOCKED", 5),
    Operation.DELETE_RECORD: OperationSpec(StepPhase.REMEDIATION, "ABSENT", 6),
    Operation.REDACT_RECORD: OperationSpec(StepPhase.REMEDIATION, "REDACTED", 7),
    Operation.ANONYMIZE_RECORD: OperationSpec(StepPhase.REMEDIATION, "ANONYMIZED", 8),
    Operation.VERIFY_RECORD_ABSENT: OperationSpec(StepPhase.VERIFICATION, "ABSENT", 9),
    Operation.VERIFY_RECORD_PRESENT: OperationSpec(StepPhase.VERIFICATION, "PRESENT", 10),
    Operation.VERIFY_RECORD_REDACTED: OperationSpec(StepPhase.VERIFICATION, "REDACTED", 11),
    Operation.VERIFY_RECORD_ANONYMIZED: OperationSpec(StepPhase.VERIFICATION, "ANONYMIZED", 12),
    Operation.VERIFY_DATA_FLOW_DISABLED: OperationSpec(StepPhase.VERIFICATION, "DISABLED", 13),
    Operation.VERIFY_RESTORE_BLOCKED: OperationSpec(StepPhase.VERIFICATION, "BLOCKED", 14),
}

PHASE_ORDER: dict[StepPhase, int] = {
    StepPhase.FINDING: 0,
    StepPhase.REMEDIATION: 1,
    StepPhase.VERIFICATION: 2,
}

# Resource-id prefix -> owning system. Longest prefix wins (data_flow_ before data_).
RESOURCE_PREFIX_SYSTEM: dict[str, str] = {
    "account_": "account_service",
    "search_": "search_service",
    "analytics_": "analytics_platform",
    "support_": "support_platform",
    "export_": "export_service",
    "data_flow_": "integration_service",
    "backup_": "backup_service",
    "audit_record_": "security_service",
    "tombstone_": "identity_service",
    "marketing_": "marketing_platform",
    "cache_": "cache_service",
    "email_delivery_": "email_delivery_service",
    "object_": "object_storage",
    "telemetry_": "telemetry_service",
    "legal_hold_": "legal_service",
}

# Default category per system when the evidence gives no explicit record_type.
SYSTEM_DEFAULT_CATEGORY: dict[str, DataCategory] = {
    "account_service": DataCategory.USER_PROFILE,
    "search_service": DataCategory.SEARCH_INDEX_ENTRY,
    "analytics_platform": DataCategory.ANALYTICS_PROFILE,
    "support_platform": DataCategory.SUPPORT_MESSAGE,
    "export_service": DataCategory.USER_EXPORT,
    "integration_service": DataCategory.DATA_FLOW,
    "backup_service": DataCategory.BACKUP_ARCHIVE,
    "security_service": DataCategory.SECURITY_AUDIT_LOG,
    "identity_service": DataCategory.ACCOUNT_TOMBSTONE,
    "marketing_platform": DataCategory.MARKETING_PROFILE,
    "cache_service": DataCategory.CACHE_ENTRY,
    "email_delivery_service": DataCategory.EMAIL_DELIVERY_LOG,
    "object_storage": DataCategory.SUPPORT_ATTACHMENT,
    "telemetry_service": DataCategory.PRODUCT_TELEMETRY,
    "legal_service": DataCategory.LEGAL_HOLD_RECORD,
}

# Fallback policy if deletion_rules.csv lacks a category (should not happen with
# the supplied file; the CSV always takes precedence).
DEFAULT_CATEGORY_ACTION: dict[DataCategory, RuleType] = {
    DataCategory.USER_PROFILE: RuleType.DELETE,
    DataCategory.SECONDARY_IDENTIFIER: RuleType.DELETE,
    DataCategory.SEARCH_INDEX_ENTRY: RuleType.DELETE,
    DataCategory.CACHE_ENTRY: RuleType.DELETE,
    DataCategory.SUPPORT_MESSAGE: RuleType.REDACT,
    DataCategory.SUPPORT_ATTACHMENT: RuleType.DELETE,
    DataCategory.ANALYTICS_PROFILE: RuleType.ANONYMIZE,
    DataCategory.PRODUCT_TELEMETRY: RuleType.ANONYMIZE,
    DataCategory.USER_EXPORT: RuleType.DELETE,
    DataCategory.MARKETING_PROFILE: RuleType.DELETE,
    DataCategory.EMAIL_DELIVERY_LOG: RuleType.REDACT,
    DataCategory.SECURITY_AUDIT_LOG: RuleType.RETAIN,
    DataCategory.LEGAL_HOLD_RECORD: RuleType.RETAIN,
    DataCategory.BACKUP_ARCHIVE: RuleType.RETAIN,
    DataCategory.ACCOUNT_TOMBSTONE: RuleType.REDACT,
}


def system_for_resource(resource_id: str) -> str | None:
    best = None
    for prefix, system in RESOURCE_PREFIX_SYSTEM.items():
        if resource_id.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, system)
    return best[1] if best else None


def case_sort_key(case_id: str):
    """Natural order: case_2 < case_10 (lexicographic order would put case_10 first)."""
    head, _, tail = case_id.rpartition("_")
    return (head, int(tail)) if tail.isdigit() else (case_id, 0)


def step_sort_key(phase: StepPhase, operation: Operation, system_id: str, resource_id: str):
    """Official ordering: phase, then operation table order, then system_id, then resource_id."""
    return (PHASE_ORDER[phase], OPERATION_SPECS[operation].order, system_id, resource_id)
