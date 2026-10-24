"""Resolves the request email to the subject's current *and historical* identifiers, as of audit_at.

The identity snapshot is "now"; ``user_audit_log.csv`` records how it got there. Identifiers are
reconstructed for the audit cut-off: changes made after ``audit_at`` are undone (their old value was
the subject's at the cut-off, their new value was not yet), so a value acquired later - possibly one
another person held at audit time - can never link that other person's evidence to the subject.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from ..domain.models import DeletionRequest, IdentityChange, IdentityProfile, IdentitySnapshot

FIELD_MAP = {"email": "emails", "phone": "phone_numbers", "email_hash": "email_hashes", "name": "names"}
SNAPSHOT_FIELD = {"email": "email", "phone": "phone", "email_hash": "email_hash", "name": "name"}


def _norm(field: str, value: str) -> str:
    return value.strip().lower() if field in ("email", "email_hash") else value.strip()


class IdentityResolver:
    def __init__(self, identities: list[IdentitySnapshot], changes: list[IdentityChange]):
        self._by_user = {i.user_id: i for i in identities}
        self._changes: dict[str, list[IdentityChange]] = defaultdict(list)
        for c in sorted(changes, key=lambda c: (c.event_time, c.audit_id)):
            self._changes[c.user_id].append(c)
        # email -> users that held it at some point (current snapshot or audit-log value)
        self._email_users: dict[str, set[str]] = defaultdict(set)
        for i in identities:
            if i.email:
                self._email_users[_norm("email", i.email)].add(i.user_id)
        for c in changes:
            if c.field_name == "email":
                for value in (c.old_value, c.new_value):
                    if value:
                        self._email_users[_norm("email", value)].add(c.user_id)

    # ---- identity as of a cut-off ----------------------------------------------------------------
    def value_at(self, user_id: str, field: str, at: datetime) -> str | None:
        """The value of ``field`` for ``user_id`` at time ``at`` (snapshot with later changes undone)."""
        snap = self._by_user.get(user_id)
        value = getattr(snap, SNAPSHOT_FIELD[field], None) if snap else None
        for c in reversed(self._changes.get(user_id, [])):
            if c.field_name == field and c.event_time > at:
                value = c.old_value
        return _norm(field, value) if value else None

    def values_until(self, user_id: str, field: str, at: datetime) -> set[str]:
        """Every value ``field`` had for ``user_id`` at or before ``at`` (current at ``at`` plus history)."""
        out = set()
        current = self.value_at(user_id, field, at)
        if current:
            out.add(current)
        for c in self._changes.get(user_id, []):
            if c.field_name == field and c.event_time <= at:
                out |= {_norm(field, v) for v in (c.old_value, c.new_value) if v}
        return out

    def owner_at(self, email: str, at: datetime) -> tuple[str | None, list[str]]:
        """User who held ``email`` at ``at``; otherwise the most recent earlier holder."""
        holders = sorted(self._email_users.get(email, ()))
        current = [u for u in holders if self.value_at(u, "email", at) == email]
        if len(current) == 1:
            return current[0], []
        best: tuple | None = None
        for u in holders:
            for c in self._changes.get(u, []):
                if (
                    c.field_name == "email"
                    and c.event_time <= at
                    and email in (_norm("email", c.old_value), _norm("email", c.new_value))
                ):
                    if best is None or (c.event_time, c.audit_id) > best[:2]:
                        best = (c.event_time, c.audit_id, u)
        if best is None:
            return None, []
        return best[2], [best[1]]

    # ---- request resolution ------------------------------------------------------------------------
    def resolve(self, request: DeletionRequest) -> IdentityProfile:
        email = request.email.strip().lower()
        at = request.audit_at
        user_id, audit_ids = self.owner_at(email, at)
        if user_id is None:
            # Unknown subject: we can still search evidence by the supplied email.
            return IdentityProfile(primary_id=None, emails={email})

        profile = IdentityProfile(primary_id=user_id, emails={email})
        for field, attr in FIELD_MAP.items():
            getattr(profile, attr).update(self.values_until(user_id, field, at))
        for c in self._changes.get(user_id, []):
            if c.event_time <= at and c.field_name in FIELD_MAP:
                profile.historical_ids.append(c.old_value)
                audit_ids.append(c.audit_id)
        profile.audit_ids = sorted(set(audit_ids))
        return profile
