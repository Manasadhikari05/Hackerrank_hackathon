"""Abstraction layer: contracts the services depend on (dependency inversion)."""

from .ml import IntentClassifier, ModelClient
from .output import OutputWriter
from .processing import EvidenceExtractor, EvidenceInterpreter
from .repositories import (
    ActivityRepository,
    EvidenceRepository,
    IdentityRepository,
    PolicyRepository,
    RequestRepository,
)

__all__ = [
    "ActivityRepository",
    "EvidenceExtractor",
    "EvidenceInterpreter",
    "EvidenceRepository",
    "IdentityRepository",
    "IntentClassifier",
    "ModelClient",
    "OutputWriter",
    "PolicyRepository",
    "RequestRepository",
]
