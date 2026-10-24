"""Turn a flat ``field -> value`` map into a normalised EvidenceRecord.

All extractors funnel through :func:`build_record`, which keeps the interpretation rules
(what counts as absent, exposed, enabled, ...) in one tested place.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from ..domain.catalog import RESOURCE_PREFIX_SYSTEM, system_for_resource
from ..domain.enums import DataCategory, EvidenceType, ResourceState
from ..domain.identifiers import (
    EMAIL_RE,
    HASH_RE,
    PHONE_RE,
    USER_REF_RE,
    email_token,
    hash_token,
    name_token,
    tokens_from_text,
    user_token,
)
from ..domain.models import EvidenceFile, EvidenceRecord, parse_ts

RESOURCE_ID_RE = re.compile(r"\b(?:" + "|".join(re.escape(p) for p in RESOURCE_PREFIX_SYSTEM) + r")[0-9]+\b")
KNOWN_SYSTEMS = frozenset(RESOURCE_PREFIX_SYSTEM.values()) | {"identity_service"}

# Keys whose value is the *query* used to find a record. They link the observation to a
# subject but do not prove the record itself stores that identifier.
LOOKUP_KEYS = frozenset(
    {
        "lookup_key",
        "match_key",
        "correlation_key",
        "subject_key",
        "scan_key",
        "subject_ref",
        "owner_key",
        "query",
        "subject_reference_lookup",
    }
)
# Keys that never carry personal identifiers even if they look like hashes or ids.
IGNORED_KEYS = frozenset(
    {
        "integrity_seal",
        "archive_key",
        "archive_path",
        "object_key",
        "checksum",
        "trace_id",
        "requestid",
        "file_name",
        "connector_name",
        "index",
        "index_name",
        "pod",
        "instance",
        "region",
    }
)
USER_REFERENCE_KEYS = frozenset({"customer_reference", "subject_reference", "user_id", "subject_selector"})
NAME_KEYS = frozenset({"full_name", "display_name", "requester_name", "name", "customer_name"})
TIME_KEYS = ("observed_at", "recorded_at", "event_time", "captured_at", "updated_at", "timestamp")

ABSENT_WORDS = frozenset({"miss", "not_found", "notfound", "absent", "deleted", "none", "no_hit"})
PRESENT_WORDS = frozenset({"hit", "found", "identifiable", "redacted", "anonymized", "active", "blocked", "disabled", "present"})
NULLS = (None, "", "null", "NULL", "None")


def _is_null(value: Any) -> bool:
    return value in NULLS


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "enabled", "on"}:
        return True
    if text in {"0", "false", "no", "disabled", "off"}:
        return False
    return None


def _category_from(value: Any) -> DataCategory | None:
    if isinstance(value, str):
        try:
            return DataCategory(value.strip().upper())
        except ValueError:
            return None
    return None


def _flatten(fields: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        k = str(key).lower()
        if isinstance(value, Mapping):
            out.update(_flatten(value, prefix + k + "."))
        elif isinstance(value, list):
            texts = [v for v in value if not isinstance(v, (Mapping, list))]
            nested = [v for v in value if isinstance(v, Mapping)]
            if texts:
                out[prefix + k] = " ".join(str(t) for t in texts)
            for i, item in enumerate(nested):
                out.update(_flatten(item, f"{prefix}{k}[{i}]."))
        else:
            out[prefix + k] = value
    return out


def build_record(
    fields: Mapping[str, Any],
    evidence: EvidenceFile,
    evidence_type: EvidenceType,
    *,
    default_system: str | None = None,
    default_time: datetime | None = None,
    default_state: ResourceState = ResourceState.PRESENT,
    source: str = "",
    link_only: bool = False,
) -> EvidenceRecord | None:
    flat = _flatten(fields)
    resource_id = flat.get("resource_id")
    if _is_null(resource_id):
        return None
    match = RESOURCE_ID_RE.search(str(resource_id))
    if not match:
        return None
    resource_id = match.group(0)

    system = None
    declared = flat.get("system") or flat.get("system_id")
    if isinstance(declared, str) and declared in KNOWN_SYSTEMS:
        system = declared
    system = system or system_for_resource(resource_id) or default_system
    if not system:
        return None

    observed_at = default_time or evidence.captured_at
    for key in TIME_KEYS:
        ts = parse_ts(str(flat[key])) if not _is_null(flat.get(key)) else None
        if ts:
            observed_at = ts
            break

    link_tokens: set[str] = set()
    exposed: set[str] = set()
    has_user_ref = False
    category: DataCategory | None = None
    state = default_state
    flow_enabled: bool | None = None
    restore_allowed: bool | None = None
    redacted = False
    anonymized = False
    retention_until = None

    for key, value in flat.items():
        leaf = key.rsplit(".", 1)[-1]
        if _is_null(value) or leaf in IGNORED_KEYS or leaf == "resource_id":
            continue
        text = str(value)
        low = text.strip().lower()

        if leaf in ("record_type", "data_category", "category"):
            category = _category_from(text) or category
            continue
        if leaf == "retention_until":
            retention_until = parse_ts(text)
            continue
        if leaf == "enabled":
            flow_enabled = _as_bool(value)
            continue
        if leaf == "restore_allowed":
            restore_allowed = _as_bool(value)
            continue
        if leaf in ("status_code", "http_status"):
            if low == "404":
                state = ResourceState.ABSENT
            elif low.startswith("2"):
                state = ResourceState.PRESENT
            continue
        if leaf in ("rows", "total_hits", "hits.total", "total"):
            if low.isdigit():
                state = ResourceState.ABSENT if int(low) == 0 else ResourceState.PRESENT
            continue
        if leaf == "account_status":
            # The row exists; DELETED/DELETION_PENDING describe the account, not this record
            # (an account tombstone row carries account_status=DELETED).
            state = ResourceState.PRESENT
            continue
        if leaf in ("result", "status", "state"):
            word = low.replace(" ", "_")
            if word in ABSENT_WORDS:
                state = ResourceState.ABSENT
            elif word in PRESENT_WORDS:
                state = ResourceState.PRESENT
            if word == "redacted":
                redacted = True
            if word == "anonymized":
                anonymized = True
            if word == "identifiable":
                exposed.add("identifier")
            if word in ("active", "blocked", "disabled") and system == "integration_service":
                flow_enabled = word == "active"
            if word in ("active", "blocked") and system == "backup_service":
                restore_allowed = word == "active"
            continue
        if leaf in ("download_available", "available"):
            flag = _as_bool(value)
            if flag is False:
                state = ResourceState.ABSENT
            elif flag is True:
                state = ResourceState.PRESENT
            continue
        if leaf == "eligible" and system == "backup_service":
            # restore_candidate_evaluated: eligible=true and no deletion block -> restorable
            if _as_bool(value) is not None and restore_allowed is not False:
                restore_allowed = bool(_as_bool(value))
            continue
        if leaf == "deletion_block" and system == "backup_service":
            if _as_bool(value):
                restore_allowed = False
            continue
        if leaf == "decision" and system == "backup_service":
            if low in ("deny", "denied", "blocked"):
                restore_allowed = False
            elif low in ("allow", "allowed", "permit"):
                restore_allowed = True
            continue
        if leaf == "direct_identifiers":
            if low.isdigit() and int(low) > 0:
                exposed.add("identifier")
            continue
        if leaf in ("marker_found", "scheduler_registered", "last_run", "detector", "last_write"):
            continue
        if leaf == "last_delivery_status" and flow_enabled is None:
            flow_enabled = low not in ("stopped", "disabled", "paused")
            continue
        if leaf in ("email_opt_in",):
            category = category or DataCategory.MARKETING_PROFILE
            continue
        if leaf == "event":
            if "attachment" in low:
                category = category or DataCategory.SUPPORT_ATTACHMENT
            elif ("message" in low or "ticket" in low) and system == "support_platform":
                category = category or DataCategory.SUPPORT_MESSAGE
            continue
        if leaf in ("message_text", "message_excerpt", "ticket_id") and system == "support_platform":
            category = category or DataCategory.SUPPORT_MESSAGE
            # fall through: message text may itself contain identifiers
        if leaf == "file" and system == "support_platform":
            category = category or DataCategory.SUPPORT_ATTACHMENT
            continue
        if low == "[redacted]":
            redacted = True
            continue
        if "no direct identifier" in low:
            anonymized = True
            continue

        tokens = tokens_from_text(text)
        if leaf in LOOKUP_KEYS:
            link_tokens |= tokens
            continue
        if leaf in USER_REFERENCE_KEYS:
            user_refs = {t for t in tokens if t.startswith("user:")}
            if user_refs:
                has_user_ref = True
            link_tokens |= tokens
            # subject_selector / reference columns sometimes hold an email instead of user_id
            exposed |= {t.split(":", 1)[0] for t in tokens if not t.startswith("user:")}
            continue
        if leaf in NAME_KEYS and not EMAIL_RE.search(text) and not USER_REF_RE.search(text):
            exposed.add("name")
            link_tokens.add(name_token(text))
            continue
        if tokens:
            link_tokens |= tokens
            exposed |= {t.split(":", 1)[0] for t in tokens if not t.startswith("user:")}
            if any(t.startswith("user:") for t in tokens):
                has_user_ref = True

    exposed.discard("user")
    return EvidenceRecord(
        evidence_id=evidence.file_id,
        evidence_type=evidence_type,
        captured_at=evidence.captured_at,
        observed_at=observed_at,
        system_id=system,
        resource_id=resource_id,
        state=state,
        identifiers=frozenset(link_tokens),
        exposed_kinds=frozenset(exposed),
        has_user_reference=has_user_ref,
        category=category,
        flow_enabled=flow_enabled,
        restore_allowed=restore_allowed,
        redacted_marker=redacted,
        anonymized_marker=anonymized,
        retention_until=retention_until,
        link_only=link_only,
        source=source,
    )


__all__ = [
    "RESOURCE_ID_RE",
    "build_record",
    "EMAIL_RE",
    "HASH_RE",
    "PHONE_RE",
    "email_token",
    "hash_token",
    "user_token",
]
