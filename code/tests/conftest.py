from __future__ import annotations

import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from deletion_auditor.domain.models import DeletionRequest, EvidenceFile  # noqa: E402

DATASET = REPO_ROOT / "dataset"
CUSTOM_DATASET = CODE_DIR / "evaluation" / "custom_cases" / "dataset"
CUSTOM_EXPECTED = CODE_DIR / "evaluation" / "custom_cases" / "expected_output.csv"


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def make_file(file_id="ev_1", path="evidence/x.json", origin="test", captured="2026-09-10T00:00:00Z") -> EvidenceFile:
    return EvidenceFile(file_id, path, origin, ts(captured))


def make_request(
    case_id="case_1",
    email="a@example.com",
    text="Please delete my account.",
    requested="2026-09-01T00:00:00Z",
    audit="2026-09-20T00:00:00Z",
) -> DeletionRequest:
    return DeletionRequest(case_id, email, ts(requested), "COMPLETE", ts(requested), ts(audit), text)


@pytest.fixture
def custom_dataset(tmp_path) -> Path:
    """A writable copy of the fictional custom-case dataset (tests may corrupt it)."""
    dst = tmp_path / "dataset"
    shutil.copytree(CUSTOM_DATASET, dst)
    return dst


def pytest_collection_modifyitems(config, items):
    skip_ds = pytest.mark.skip(reason="dataset/ not present")
    skip_ocr = pytest.mark.skip(reason="tesseract not installed")
    for item in items:
        if "dataset" in item.keywords and not (DATASET / "deletion_requests.csv").exists():
            item.add_marker(skip_ds)
        if "ocr" in item.keywords and shutil.which("tesseract") is None:
            item.add_marker(skip_ocr)
