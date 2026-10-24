"""Audit one hand-entered request through the real pipeline (does not touch output.csv).

    python3 code/try_request.py --email keiko.nakamura@gmail.com \
        --text "Please finish deleting my account." \
        --requested-at 2026-09-01T12:00:00Z --audit-at 2026-09-15T12:00:00Z

Every timestamp is required: the tool never invents a request or audit time, because the time
window decides which evidence is admissible.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deletion_auditor.application import AppConfig, AuditApplication
from deletion_auditor.domain.models import DeletionRequest, parse_ts


def timestamp(value: str):
    ts = parse_ts(value)
    if ts is None:
        raise argparse.ArgumentTypeError(f"not an ISO-8601 timestamp: {value!r} (e.g. 2026-09-15T12:00:00Z)")
    return ts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--email", required=True)
    p.add_argument("--text", required=True, help="request_text")
    p.add_argument("--requested-at", required=True, type=timestamp)
    p.add_argument("--audit-at", required=True, type=timestamp)
    p.add_argument("--dataset", type=Path, default=None)
    p.add_argument("--json", action="store_true", help="print the steps_json array only")
    args = p.parse_args(argv)
    if args.requested_at > args.audit_at:
        p.error("--requested-at must not be after --audit-at")

    cfg = AppConfig(run_log_path=None)
    if args.dataset:
        cfg.dataset_dir = args.dataset
    request = DeletionRequest("manual_case", args.email, args.requested_at, "", None, args.audit_at, args.text)
    result = AuditApplication(cfg).audit([request])[0]
    if args.json:
        print(json.dumps([s.to_dict() for s in result.steps], sort_keys=True))
        return 0
    print(f"STATUS: {result.status.value} - {result.decision.rationale}")
    for s in result.steps:
        cols = (f"{s.step_no:>2}", f"{s.phase.value:<12}", f"{s.operation.value:<26}", f"{s.system_id:<22}")
        print(" ".join(cols), f"{s.resource_id:<18}", s.evidence_id or "-")
    for w in result.warnings:
        print("warning:", w)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
