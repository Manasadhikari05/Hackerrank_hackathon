"""Converts the global activity stream into evidence.

Only activity rows that *observe* state are trusted as evidence:

* ``CHECK_DATA_FLOW`` / ``CHECK_RESTORE_ACCESS`` - explicit checks of a live process;
* ``RESTORE_BACKUP`` and connector repopulation - prove data was recreated;
* ``LINK_RESOURCE_IDENTITY`` - data-catalog identity links (link-only, no state).

Workflow outcomes (``DELETE_RECORD ... SUCCESS``, ``Policy action completed``) are claims and are
deliberately ignored, as the problem statement requires.
"""

from __future__ import annotations

import re

from ..domain.enums import EvidenceType, ResourceState
from ..domain.models import ActivityEvent, EvidenceFile, EvidenceRecord
from .record_builder import RESOURCE_ID_RE, build_record

ALIAS_RE = re.compile(r"\b([a-z_]+_\d+) \(([^)]+)\)")


def _pseudo_file(event: ActivityEvent) -> EvidenceFile:
    return EvidenceFile(
        file_id=event.activity_id,
        file_path="system_activity.csv",
        origin=event.source_system,
        captured_at=event.event_time,
    )


class ActivityEvidenceAdapter:
    def to_records(self, events: list[ActivityEvent]) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        for ev in events:
            rec = self._convert(ev)
            if rec:
                records.append(rec)
        return records

    def _convert(self, ev: ActivityEvent) -> EvidenceRecord | None:
        pseudo = _pseudo_file(ev)
        details = ev.details
        low = details.lower()
        if ev.event_type == "LINK_RESOURCE_IDENTITY":
            return build_record(
                {"resource_id": ev.resource_id, "system": ev.target_system, "subject_reference_lookup": details},
                pseudo,
                EvidenceType.ACTIVITY,
                default_state=ResourceState.UNKNOWN,
                source="activity:link",
                link_only=True,
            )
        if ev.event_type == "CHECK_DATA_FLOW" and "remains enabled" in low:
            return build_record(
                {"resource_id": ev.resource_id, "enabled": True},
                pseudo,
                EvidenceType.ACTIVITY,
                source="activity:check_data_flow",
            )
        if ev.event_type == "CHECK_RESTORE_ACCESS" and "can still be restored" in low:
            return build_record(
                {"resource_id": ev.resource_id, "restore_allowed": True},
                pseudo,
                EvidenceType.ACTIVITY,
                source="activity:check_restore",
            )
        if "repopulated downstream resource" in low:
            target = RESOURCE_ID_RE.findall(details)
            if target:
                return build_record(
                    {"resource_id": target[-1], "result": "FOUND"},
                    pseudo,
                    EvidenceType.ACTIVITY,
                    source="activity:repopulated",
                )
        return None

    @staticmethod
    def aliases(events: list[ActivityEvent]) -> dict[str, tuple]:
        """Business-reference aliases published by the data catalog, e.g. NST-... -> export_1842."""
        out: dict[str, tuple[str, str]] = {}
        for ev in events:
            if ev.event_type != "LINK_RESOURCE_IDENTITY":
                continue
            for rid, alias in ALIAS_RE.findall(ev.details):
                if alias != rid:
                    out[alias] = (rid, ev.target_system, ev.event_time)
        return out
