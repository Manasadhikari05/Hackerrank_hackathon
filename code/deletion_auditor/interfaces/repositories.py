"""Repository contracts. Services never open files directly."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..domain.models import (
    ActivityEvent,
    DeletionRequest,
    DeletionRule,
    EvidenceFile,
    IdentityChange,
    IdentitySnapshot,
)


class RequestRepository(ABC):
    @abstractmethod
    def load_requests(self) -> list[DeletionRequest]:
        """Return every request, in input order."""


class IdentityRepository(ABC):
    @abstractmethod
    def load_identities(self) -> list[IdentitySnapshot]:
        """Current identity snapshot rows."""

    @abstractmethod
    def load_identity_changes(self) -> list[IdentityChange]:
        """Historical identity-change rows."""


class PolicyRepository(ABC):
    @abstractmethod
    def load_rules(self) -> list[DeletionRule]:
        """Deletion rules, one per data category."""


class ActivityRepository(ABC):
    @abstractmethod
    def load_activities(self) -> list[ActivityEvent]:
        """Global system-activity stream."""


class EvidenceRepository(ABC):
    @abstractmethod
    def list_evidence(self) -> list[EvidenceFile]:
        """Manifest entries for every evidence item."""

    @abstractmethod
    def read_evidence(self, file_id: str) -> bytes:
        """Raw bytes of one evidence item. Raises KeyError for unknown ids."""
