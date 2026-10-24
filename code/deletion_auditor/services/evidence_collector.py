"""Collects every observation of every resource linked to a subject, as of ``audit_at``.

The collector is built once over the whole corpus (all evidence files + trusted activity rows)
and then answers per-case queries from in-memory indexes, so a 518-case run parses each file
only once.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime

from ..domain.catalog import SYSTEM_DEFAULT_CATEGORY
from ..domain.enums import DataCategory, ResourceState
from ..domain.models import EvidenceFile, EvidenceRecord, IdentityProfile
from ..interfaces.processing import EvidenceExtractor
from ..interfaces.repositories import EvidenceRepository

log = logging.getLogger(__name__)


@dataclass
class ResourceView:
    """All admissible observations of one resource for one case."""

    system_id: str
    resource_id: str
    records: list[EvidenceRecord] = field(default_factory=list)
    link_evidence: list[str] = field(default_factory=list)

    @property
    def category(self) -> DataCategory | None:
        explicit = [r for r in self.records if r.category is not None]
        if explicit:
            return max(explicit, key=lambda r: (r.observed_at, r.captured_at)).category
        if self.system_id == "support_platform":
            # rule_05 (REDACT) applies only to conversations with shared context that must be kept.
            # Without any message/order context in the evidence that condition is not met, so the
            # record is treated like a subject-only artefact and must be deleted (rule_06).
            return DataCategory.SUPPORT_ATTACHMENT
        return SYSTEM_DEFAULT_CATEGORY.get(self.system_id)

    def citable(self, audit_at: datetime, predicate) -> EvidenceRecord | None:
        """Latest record that proves ``predicate`` and was captured at or before audit_at.

        Preference: evidence files captured by audit_at; only if none exists, a section of a later
        bundle whose own explicit capture stamp is at or before audit_at.
        """
        proving = [r for r in self.informative() if predicate(r)]
        for tier in (
            [r for r in proving if r.captured_at <= audit_at],
            [r for r in proving if r.section_captured_at is not None and r.section_captured_at <= audit_at],
        ):
            if tier:
                return max(tier, key=lambda r: (r.observed_at, r.captured_at, r.evidence_id))
        return None

    def informative(self) -> list[EvidenceRecord]:
        return [
            r
            for r in self.records
            if not r.link_only
            and (r.state != ResourceState.UNKNOWN or r.flow_enabled is not None or r.restore_allowed is not None)
        ]

    def current(self) -> EvidenceRecord | None:
        """Latest informative observation. Records from the same evidence at the same instant
        (e.g. primary + replica tables) are merged pessimistically: any copy present wins."""
        candidates = self.informative()
        if not candidates:
            return None
        # Omission-based absence only wins when it is strictly newer than any explicit observation.
        latest_key = max((r.observed_at, r.captured_at, r.explicit) for r in candidates)
        tied = [r for r in candidates if (r.observed_at, r.captured_at, r.explicit) == latest_key]
        return merge_pessimistic(tied)


def merge_pessimistic(records: list[EvidenceRecord]) -> EvidenceRecord:
    base = sorted(records, key=lambda r: (r.evidence_id, r.source))[0]
    if len(records) == 1:
        return base
    present = [r for r in records if r.state == ResourceState.PRESENT]
    pick = sorted(present, key=lambda r: (r.evidence_id, r.source))[0] if present else base
    return replace(
        pick,
        state=ResourceState.PRESENT if present else pick.state,
        exposed_kinds=frozenset().union(*(r.exposed_kinds for r in present)) if present else pick.exposed_kinds,
        has_user_reference=any(r.has_user_reference for r in present) if present else pick.has_user_reference,
        flow_enabled=True if any(r.flow_enabled for r in records) else pick.flow_enabled,
        restore_allowed=True if any(r.restore_allowed for r in records) else pick.restore_allowed,
    )


class EvidenceCollector:
    def __init__(
        self,
        repository: EvidenceRepository,
        extractors: list[EvidenceExtractor],
        link_with_later_evidence: bool = True,
    ):
        self.link_with_later_evidence = link_with_later_evidence
        self._repository = repository
        self._extractors = extractors
        self._by_resource: dict[str, list[EvidenceRecord]] = defaultdict(list)
        self._by_token: dict[str, set[str]] = defaultdict(set)
        self._files: dict[str, EvidenceFile] = {}
        self.stats: dict[str, int] = defaultdict(int)
        self._indexed = False

    def index(self, extra_records: list[EvidenceRecord] | None = None) -> None:
        for evidence in self._repository.list_evidence():
            self._files[evidence.file_id] = evidence
            extractor = next((e for e in self._extractors if e.supports(evidence)), None)
            if extractor is None:
                log.warning("no extractor supports %s (%s); skipped", evidence.file_id, evidence.file_path)
                self.stats["unsupported_files"] += 1
                continue
            try:
                content = self._repository.read_evidence(evidence.file_id)
            except (OSError, KeyError, PermissionError) as exc:
                log.warning("cannot read %s: %s", evidence.file_id, exc)
                self.stats["unreadable_files"] += 1
                continue
            records = extractor.extract(evidence, content)
            self.stats[f"records_{type(extractor).__name__}"] += len(records)
            self._add(records)
        self._add(extra_records or [])
        self.stats["records_activity"] += len(extra_records or [])
        self._indexed = True

    def section_capture_times(self) -> dict[tuple[str, str], datetime]:
        """Capture time per (evidence, resource) where a record carries a section-level stamp
        earlier than its file's manifest time."""
        out: dict[tuple[str, str], datetime] = {}
        for rid, records in self._by_resource.items():
            for r in records:
                if r.section_captured_at is not None:
                    key = (r.evidence_id, rid)
                    out[key] = min(out.get(key, r.section_captured_at), r.section_captured_at)
        return out

    def _add(self, records: list[EvidenceRecord]) -> None:
        for r in records:
            self._by_resource[r.resource_id].append(r)
            for t in r.identifiers:
                self._by_token[t].add(r.resource_id)

    def collect(self, profile: IdentityProfile, audit_at: datetime, since: datetime | None = None) -> list[ResourceView]:
        """Resources linked to ``profile`` with their admissible observations.

        ``since`` (the request time) scopes the audit to records observed during the deletion
        window: a resource seen only months before the request says nothing about what the
        deletion workflow left behind.
        """
        if not self._indexed:
            raise RuntimeError("EvidenceCollector.index() must run before collect()")
        tokens = profile.tokens
        candidate_ids: set[str] = set()
        for t in tokens:
            candidate_ids |= self._by_token.get(t, set())

        views: list[ResourceView] = []
        for rid in sorted(candidate_ids):
            admissible = [r for r in self._by_resource[rid] if self._admissible(r, audit_at)]
            # Ownership of a resource id is time-invariant (ids are never reused), so a later
            # catalogue entry may tell us *which* record is the subject's. Its *state* below is
            # still reconstructed exclusively from observations made at or before audit_at.
            pool = self._by_resource[rid] if self.link_with_later_evidence else admissible
            links = sorted({r.evidence_id for r in pool if r.identifiers & tokens})
            if not links or not admissible:
                continue
            if since is not None and not any(r.observed_at >= since and not r.link_only for r in admissible):
                continue
            views.append(ResourceView(admissible[0].system_id, rid, list(admissible), links))
        return views

    @staticmethod
    def _admissible(record: EvidenceRecord, audit_at: datetime) -> bool:
        # A log line or snapshot section observed before audit_at describes the state at that
        # time even if the export file was produced later. Whether it may be *cited* is a
        # separate question (see ResourceView.citable).
        return record.observed_at <= audit_at
