"""Evidence-processing contracts.

Extractors turn one evidence file into normalised EvidenceRecords. Formats whose content is
free text (PDF, OCR, plain text) delegate the text -> record step to an EvidenceInterpreter,
so a rule-based or an LLM-backed interpreter can be swapped in without touching extractors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..domain.models import EvidenceFile, EvidenceRecord


class EvidenceExtractor(ABC):
    @abstractmethod
    def supports(self, evidence: EvidenceFile) -> bool:
        """True if this extractor can parse the given evidence item."""

    @abstractmethod
    def extract(self, evidence: EvidenceFile, content: bytes) -> list[EvidenceRecord]:
        """Parse the content. Must not raise on malformed content; return [] instead."""


class EvidenceInterpreter(ABC):
    @abstractmethod
    def interpret(self, raw_content: str, evidence: EvidenceFile) -> list[EvidenceRecord]:
        """Convert unstructured text into records. Must only emit resource ids present in raw_content."""
