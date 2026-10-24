"""Resolves the request email to the subject's current *and historical* identifiers."""

from __future__ import annotations

from collections import defaultdict

from ..domain.models import DeletionRequest, IdentityChange, IdentityProfile, IdentitySnapshot

FIELD_MAP = {"email": "emails", "phone": "phone_numbers", "email_hash": "email_hashes", "name": "names"}


class IdentityResolver:
    def __init__(self, identities: list[IdentitySnapshot], changes: list[IdentityChange]):
        self._by_user = {i.user_id: i for i in identities}
        self._changes = defaultdict(list)
        for c in sorted(changes, key=lambda c: (c.event_time, c.audit_id)):
            self._changes[c.user_id].append(c)
        self._current_email = {i.email.lower(): i.user_id for i in identities if i.email}
        # Historical email -> [(event_time, user_id)] for emails that were changed away from.
        self._historical_email: dict[str, list[tuple]] = defaultdict(list)
        for c in changes:
            if c.field_name == "email":
                for value in (c.old_value, c.new_value):
                    if value:
                        self._historical_email[value.lower()].append((c.event_time, c.user_id, c.audit_id))

    def resolve(self, request: DeletionRequest) -> IdentityProfile:
        email = request.email.strip().lower()
        user_id = self._current_email.get(email)
        audit_ids: list[str] = []
        if user_id is None:
            # Only history recorded at or before the audit cut-off may be used.
            candidates = sorted((t, u, a) for t, u, a in self._historical_email.get(email, []) if t <= request.audit_at)
            if candidates:
                _, user_id, audit_id = candidates[-1]
                audit_ids.append(audit_id)
        if user_id is None:
            # Unknown subject: we can still search evidence by the supplied email.
            return IdentityProfile(primary_id=None, emails={email})

        profile = IdentityProfile(primary_id=user_id, emails={email})
        snap = self._by_user.get(user_id)
        if snap:
            profile.emails.add(snap.email.lower())
            if snap.phone:
                profile.phone_numbers.add(snap.phone)
            if snap.email_hash:
                profile.email_hashes.add(snap.email_hash.lower())
            if snap.name:
                profile.names.add(snap.name)
        for change in self._changes.get(user_id, []):
            if change.event_time > request.audit_at:
                continue
            attr = FIELD_MAP.get(change.field_name)
            if not attr:
                continue
            bucket = getattr(profile, attr)
            for value in (change.old_value, change.new_value):
                if value:
                    bucket.add(value.lower() if attr in ("emails", "email_hashes") else value)
            profile.historical_ids.append(change.old_value)
            audit_ids.append(change.audit_id)
        profile.audit_ids = sorted(set(audit_ids))
        return profile
