"""End-to-end: the real entry point on all 518 requests, output validated against the contract."""

import csv
import json
import subprocess
import sys

import pytest

from tests.conftest import CODE_DIR, DATASET

pytestmark = [pytest.mark.dataset, pytest.mark.slow]


def test_main_entry_point_full_dataset(tmp_path):
    out = tmp_path / "output.csv"
    proc = subprocess.run(
        [sys.executable, str(CODE_DIR / "main.py"), "--output", str(out)], capture_output=True, text=True, timeout=600
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    with open(DATASET / "deletion_requests.csv", newline="") as fh:
        expected_ids = [r["case_id"] for r in csv.DictReader(fh)]
    with open(out, newline="") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == ["case_id", "deletion_status", "steps_json"]
        got = list(reader)
    assert len(got) == len(expected_ids) == 518
    assert sorted(r["case_id"] for r in got) == sorted(expected_ids)
    for r in got:
        assert r["deletion_status"] in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
        assert isinstance(json.loads(r["steps_json"]), list)
