"""CSV- and filesystem-backed repositories (UML: CsvRequestRepository, CsvPolicyRepository,
FileEvidenceRepository) plus identity and activity repositories."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from ..domain.enums import DataCategory, RuleType
from ..domain.models import (
    ActivityEvent,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    IdentityChange,
    IdentitySnapshot,
    parse_ts,
)
from ..interfaces.repositories import (
    ActivityRepository,
    EvidenceRepository,
    IdentityRepository,
    PolicyRepository,
    RequestRepository,
)

log = logging.getLogger(__name__)

REQUEST_COLUMNS = ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text")


class MalformedInputError(ValueError):
    """Raised when a mandatory input file is structurally invalid."""


def _read_csv(path: Path, required: tuple[str, ...]) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"required input missing: {path}")
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in required if c not in (reader.fieldnames or [])]
        if missing:
            raise MalformedInputError(f"{path.name} is missing columns {missing}")
        return list(reader)


class CsvRequestRepository(RequestRepository):
    def __init__(self, path: Path):
        self._path = Path(path)

    def load_requests(self) -> list[DeletionRequest]:
        out: list[DeletionRequest] = []
        seen: set[str] = set()
        for i, row in enumerate(_read_csv(self._path, REQUEST_COLUMNS), start=2):
            case_id = (row.get("case_id") or "").strip()
            requested = parse_ts(row.get("requested_at"))
            audit = parse_ts(row.get("audit_at"))
            if not case_id or requested is None or audit is None:
                raise MalformedInputError(f"{self._path.name}:{i} has an empty case_id or invalid timestamp")
            if requested > audit:
                # A request cannot be audited before it was made; equal timestamps are valid.
                raise MalformedInputError(f"{self._path.name}:{i} ({case_id}) has requested_at after audit_at")
            if case_id in seen:
                raise MalformedInputError(f"{self._path.name}:{i} duplicates case_id {case_id}")
            seen.add(case_id)
            out.append(
                DeletionRequest(
                    case_id=case_id,
                    email=(row.get("email") or "").strip(),
                    requested_at=requested,
                    reported_status=(row.get("reported_status") or "").strip(),
                    reported_at=parse_ts(row.get("reported_at")),
                    audit_at=audit,
                    request_text=row.get("request_text") or "",
                )
            )
        return out


class CsvIdentityRepository(IdentityRepository):
    def __init__(self, identities_path: Path, audit_log_path: Path):
        self._identities = Path(identities_path)
        self._audit_log = Path(audit_log_path)

    def load_identities(self) -> list[IdentitySnapshot]:
        rows = _read_csv(self._identities, ("user_id", "name", "email", "phone", "email_hash"))
        return [
            IdentitySnapshot(
                user_id=r["user_id"].strip(),
                name=r["name"].strip(),
                email=r["email"].strip(),
                phone=r["phone"].strip(),
                email_hash=r["email_hash"].strip(),
                updated_at=parse_ts(r.get("updated_at")),
            )
            for r in rows
        ]

    def load_identity_changes(self) -> list[IdentityChange]:
        rows = _read_csv(self._audit_log, ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"))
        out = []
        for r in rows:
            ts = parse_ts(r["event_time"])
            if ts is None:
                log.warning("skipping audit row %s with bad timestamp", r.get("audit_id"))
                continue
            out.append(
                IdentityChange(
                    audit_id=r["audit_id"],
                    user_id=r["user_id"],
                    event_time=ts,
                    field_name=r["field_name"].strip().lower(),
                    old_value=r["old_value"].strip(),
                    new_value=r["new_value"].strip(),
                )
            )
        return out


class CsvPolicyRepository(PolicyRepository):
    def __init__(self, path: Path):
        self._path = Path(path)

    def load_rules(self) -> list[DeletionRule]:
        rules = []
        for r in _read_csv(self._path, ("rule_id", "data_category", "condition", "required_action")):
            try:
                rules.append(
                    DeletionRule(
                        rule_id=r["rule_id"],
                        data_category=DataCategory(r["data_category"].strip()),
                        condition=r["condition"],
                        action=RuleType(r["required_action"].strip()),
                    )
                )
            except ValueError as exc:
                raise MalformedInputError(f"unsupported rule {r.get('rule_id')}: {exc}") from exc
        return rules


class CsvActivityRepository(ActivityRepository):
    def __init__(self, path: Path):
        self._path = Path(path)

    def load_activities(self) -> list[ActivityEvent]:
        out = []
        for r in _read_csv(self._path, ("activity_id", "event_time", "event_type", "resource_id", "details")):
            ts = parse_ts(r["event_time"])
            if ts is None:
                continue
            out.append(
                ActivityEvent(
                    activity_id=r["activity_id"],
                    event_time=ts,
                    event_type=r["event_type"],
                    source_system=r.get("source_system", ""),
                    target_system=r.get("target_system", ""),
                    resource_id=r["resource_id"],
                    reported_result=r.get("reported_result", ""),
                    details=r["details"],
                )
            )
        return out


class FileEvidenceRepository(EvidenceRepository):
    def __init__(self, dataset_dir: Path, manifest_name: str = "evidence_files.csv"):
        self._root = Path(dataset_dir)
        self._manifest = self._root / manifest_name
        self._files: dict[str, EvidenceFile] | None = None

    def list_evidence(self) -> list[EvidenceFile]:
        if self._files is None:
            files = {}
            for r in _read_csv(self._manifest, ("file_id", "file_path", "captured_at")):
                ts = parse_ts(r["captured_at"])
                if ts is None:
                    log.warning("evidence %s has no valid captured_at; ignored", r["file_id"])
                    continue
                files[r["file_id"]] = EvidenceFile(r["file_id"], r["file_path"], r.get("origin", ""), ts)
            self._files = files
        return list(self._files.values())

    def read_evidence(self, file_id: str) -> bytes:
        self.list_evidence()
        assert self._files is not None
        evidence = self._files[file_id]
        path = (self._root / evidence.file_path).resolve()
        if self._root.resolve() not in path.parents:
            raise PermissionError(f"evidence path escapes dataset dir: {evidence.file_path}")
        return path.read_bytes()
