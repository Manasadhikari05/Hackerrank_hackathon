"""Domain models. No I/O, no third-party imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .enums import (
    AuditStatus,
    DataCategory,
    EvidenceType,
    Operation,
    ResourceState,
    RuleType,
    StepPhase,
)
from .identifiers import (
    email_hash,
    email_token,
    hash_token,
    name_token,
    phone_token,
    user_token,
)


def parse_ts(value: str | None) -> datetime | None:
    """Parse ISO-8601 timestamps such as ``2026-09-15T11:00:00Z`` into aware datetimes."""
    if not value:
        return None
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime | None
    audit_at: datetime
    request_text: str

    def get_customer_identifiers(self) -> set[str]:
        return {email_token(self.email)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "email": self.email,
            "requested_at": self.requested_at.isoformat(),
            "reported_status": self.reported_status,
            "audit_at": self.audit_at.isoformat(),
        }


@dataclass
class IdentityProfile:
    """Current plus historical identifiers for one subject, as known at a cut-off time."""

    primary_id: str | None
    historical_ids: list[str] = field(default_factory=list)
    emails: set[str] = field(default_factory=set)
    phone_numbers: set[str] = field(default_factory=set)
    email_hashes: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    audit_ids: list[str] = field(default_factory=list)

    @property
    def tokens(self) -> set[str]:
        """Tokens that are strong enough to *link* a record to this subject.

        Names are deliberately excluded: they are not unique and the dataset contains
        near-duplicate decoy names.
        """
        out: set[str] = set()
        if self.primary_id:
            out.add(user_token(self.primary_id))
        out |= {email_token(e) for e in self.emails}
        out |= {phone_token(p) for p in self.phone_numbers}
        out |= {hash_token(h) for h in self.email_hashes}
        out |= {hash_token(email_hash(e)) for e in self.emails}
        return out

    @property
    def name_tokens(self) -> set[str]:
        return {name_token(n) for n in self.names}

    def merge(self, other: IdentityProfile) -> IdentityProfile:
        return IdentityProfile(
            primary_id=self.primary_id or other.primary_id,
            historical_ids=sorted(set(self.historical_ids) | set(other.historical_ids)),
            emails=self.emails | other.emails,
            phone_numbers=self.phone_numbers | other.phone_numbers,
            email_hashes=self.email_hashes | other.email_hashes,
            names=self.names | other.names,
            audit_ids=sorted(set(self.audit_ids) | set(other.audit_ids)),
        )


@dataclass(frozen=True)
class EvidenceFile:
    """One row of evidence_files.csv."""

    file_id: str
    file_path: str
    origin: str
    captured_at: datetime

    @property
    def extension(self) -> str:
        return self.file_path.rsplit(".", 1)[-1].lower() if "." in self.file_path else ""


@dataclass(frozen=True)
class IdentityChange:
    """One row of user_audit_log.csv."""

    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class IdentitySnapshot:
    """One row of user_identities.csv."""

    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime | None


@dataclass(frozen=True)
class EvidenceRecord:
    """One normalised observation of one resource taken from one evidence item.

    Every extractor (SQL, JSON, logs, PDF, OCR, activity stream) emits this shape, so the
    services layer never depends on file formats.
    """

    evidence_id: str
    evidence_type: EvidenceType
    captured_at: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    state: ResourceState
    # Tokens that link the observation to a subject (record content *and* lookup keys).
    identifiers: frozenset[str] = frozenset()
    # Direct identifier kinds (email/phone/hash/name) stored *in the record itself*.
    exposed_kinds: frozenset[str] = frozenset()
    # True when the record still carries a stable user_id reference.
    has_user_reference: bool = False
    category: DataCategory | None = None
    flow_enabled: bool | None = None
    restore_allowed: bool | None = None
    redacted_marker: bool = False
    anonymized_marker: bool = False
    retention_until: datetime | None = None
    # Capture time of an explicitly time-stamped section inside a later-exported bundle.
    section_captured_at: datetime | None = None
    explicit: bool = True
    link_only: bool = False  # True when the row only links identity (e.g. data catalog)
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "state": self.state.value,
            "observed_at": self.observed_at.isoformat(),
            "identifiers": sorted(self.identifiers),
            "category": self.category.value if self.category else None,
            "source": self.source,
        }


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: DataCategory
    condition: str
    action: RuleType

    def is_applicable(self, category: DataCategory) -> bool:
        return self.data_category == category


@dataclass(frozen=True)
class ActivityEvent:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class IntentDecision:
    authorizes_deletion: bool
    confidence: float
    rationale: str
    source: str  # "rules" or "llm:<model>"


@dataclass
class ResourceAssessment:
    """Policy decision for one resource linked to the subject (UML: AuditFinding)."""

    system_id: str
    resource_id: str
    category: DataCategory
    required_action: RuleType | None
    compliant: bool
    finding: Operation | None
    remediation: Operation | None
    verification: Operation | None
    evidence_id: str
    rationale: str = ""


@dataclass(frozen=True)
class AuditStep:
    """One element of steps_json (UML: RemediationStep, generalised to all three phases)."""

    step_no: int
    phase: StepPhase
    system_id: str
    resource_id: str
    operation: Operation
    state: str
    evidence_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_no": self.step_no,
            "phase": self.phase.value,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation.value,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass
class AuditDecision:
    status: AuditStatus
    rationale: str
    confidence: float = 1.0


@dataclass
class AuditResult:
    case_id: str
    decision: AuditDecision
    steps: list[AuditStep] = field(default_factory=list)
    findings: list[ResourceAssessment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def status(self) -> AuditStatus:
        return self.decision.status

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "deletion_status": self.status.value,
            "steps": [s.to_dict() for s in self.steps],
        }
