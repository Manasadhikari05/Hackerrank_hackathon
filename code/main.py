"""Entry point: python3 code/main.py [--requests FILE] [--output PATH] [--no-ocr]

Audits every request in dataset/deletion_requests.csv and writes output.csv at the repository root.
The written file is validated against the output contract; any violation exits non-zero.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from deletion_auditor.application import AppConfig, AuditApplication  # noqa: E402
from deletion_auditor.validation import OutputValidationError  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Ghost Data Still Exists - deletion-audit agent")
    p.add_argument("--dataset", type=Path, default=None, help="dataset directory (default: <repo>/dataset)")
    p.add_argument("--requests", default="deletion_requests.csv", help="request CSV inside the dataset dir")
    p.add_argument("--output", type=Path, default=None, help="output CSV path (default: <repo>/output.csv)")
    p.add_argument("--no-ocr", action="store_true", help="skip screenshot OCR (Tesseract not installed)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    config = AppConfig(requests_file=args.requests, enable_ocr=not args.no_ocr)
    if args.dataset:
        config.dataset_dir = args.dataset
    if args.output:
        config.output_path = args.output
    try:
        summary = AuditApplication(config).run()
    except OutputValidationError as exc:
        print(f"OUTPUT INVALID: {exc}", file=sys.stderr)
        return 3
    except (FileNotFoundError, ValueError) as exc:
        print(f"INPUT ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {summary.output_path} ({summary.cases} cases in {summary.seconds}s): {summary.status_counts}")
    if summary.errors:
        print(f"{len(summary.errors)} case(s) failed: {summary.errors[:5]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
