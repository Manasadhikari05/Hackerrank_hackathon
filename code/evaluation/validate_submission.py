"""Independent submission validator.

Deliberately imports nothing from ``deletion_auditor``: it re-derives every rule from
problem_statement.md and AGENTS.md so that a bug in the agent cannot also hide in its own checks.

    python3 code/evaluation/validate_submission.py            # output.csv + log.txt (+ code.zip if present)
    python3 code/evaluation/validate_submission.py --rerun    # also regenerate output twice: determinism
    python3 code/evaluation/validate_submission.py --write-report

Exit status is non-zero when any structural (schema) check fails.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
STEP_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
# problem_statement.md "Allowed Operations", in table order
OPERATIONS = [
    ("REPORT_REMAINING_RECORD", "FINDING", "PRESENT"),
    ("REPORT_EXPOSED_PII", "FINDING", "PRESENT"),
    ("REPORT_ACTIVE_DATA_FLOW", "FINDING", "ACTIVE"),
    ("REPORT_RESTORE_RISK", "FINDING", "ACTIVE"),
    ("DISABLE_DATA_FLOW", "REMEDIATION", "DISABLED"),
    ("BLOCK_RESTORE", "REMEDIATION", "BLOCKED"),
    ("DELETE_RECORD", "REMEDIATION", "ABSENT"),
    ("REDACT_RECORD", "REMEDIATION", "REDACTED"),
    ("ANONYMIZE_RECORD", "REMEDIATION", "ANONYMIZED"),
    ("VERIFY_RECORD_ABSENT", "VERIFICATION", "ABSENT"),
    ("VERIFY_RECORD_PRESENT", "VERIFICATION", "PRESENT"),
    ("VERIFY_RECORD_REDACTED", "VERIFICATION", "REDACTED"),
    ("VERIFY_RECORD_ANONYMIZED", "VERIFICATION", "ANONYMIZED"),
    ("VERIFY_DATA_FLOW_DISABLED", "VERIFICATION", "DISABLED"),
    ("VERIFY_RESTORE_BLOCKED", "VERIFICATION", "BLOCKED"),
]
OP = {name: (phase, state, i) for i, (name, phase, state) in enumerate(OPERATIONS)}
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
# Which remediation answers a finding, and which verification proves a remediation's end state
# (the Meaning column of the official operation table).
FIX_FOR = {
    "REPORT_REMAINING_RECORD": {"DELETE_RECORD"},
    "REPORT_EXPOSED_PII": {"REDACT_RECORD", "ANONYMIZE_RECORD"},
    "REPORT_ACTIVE_DATA_FLOW": {"DISABLE_DATA_FLOW"},
    "REPORT_RESTORE_RISK": {"BLOCK_RESTORE"},
}
CHECK_FOR = {
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
    "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
    "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
}
ZIP_FORBIDDEN = re.compile(
    r"(^|/)(dataset|\.venv|venv|node_modules|__pycache__|\.pytest_cache|\.ruff_cache|\.git)/|"
    r"\.(zip|tar|gz|tgz|7z|rar)$|(^|/)\.env$|(^|/)\.DS_Store$"
)
SECRET = re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH) PRIVATE KEY)")


def ts(value: str) -> datetime:
    return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).astimezone(timezone.utc)


def readable_bytes(path: Path) -> bytes:
    """Raw bytes, or extracted text for PDFs (their text lives in compressed streams)."""
    data = path.read_bytes()
    if path.suffix.lower() == ".pdf":
        try:
            import io

            from PyPDF2 import PdfReader

            data += "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages).encode()
        except Exception:  # PyPDF2 missing or unreadable PDF: fall back to raw bytes
            pass
    return data


def ocr_text(path: Path) -> bytes | None:
    """Full-page OCR text of a screenshot, or None when Tesseract is not available."""
    try:
        import pytesseract
        from PIL import Image

        return pytesseract.image_to_string(Image.open(path)).encode()
    except Exception:
        return None


def case_num(case_id: str) -> int:
    return int(re.sub(r"\D", "", case_id) or 0)


class Report:
    def __init__(self):
        self.sections: list[tuple[str, list[str], list[str], dict]] = []

    def add(self, title: str, errors: list[str], warnings: list[str], facts: dict):
        self.sections.append((title, errors, warnings, facts))

    @property
    def errors(self) -> int:
        return sum(len(e) for _, e, _, _ in self.sections)


def load_evidence_times() -> tuple[dict[str, datetime], dict[str, dict], dict[str, str]]:
    times: dict[str, datetime] = {}
    activities: dict[str, dict] = {}
    paths: dict[str, str] = {}
    with open(DATASET / "evidence_files.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            times[r["file_id"]] = ts(r["captured_at"])
            paths[r["file_id"]] = r["file_path"]
    with open(DATASET / "system_activity.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            times[r["activity_id"]] = ts(r["event_time"])
            activities[r["activity_id"]] = r
    with open(DATASET / "user_audit_log.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            times[r["audit_id"]] = ts(r["event_time"])
    return times, activities, paths


def check_output(path: Path, report: Report) -> dict:
    errors, warnings = [], []
    with open(DATASET / "deletion_requests.csv", newline="", encoding="utf-8") as fh:
        requests = {r["case_id"]: r for r in csv.DictReader(fh)}
    times, activities, paths = load_evidence_times()
    aliases = {}  # resource_id -> alias published by the data catalog
    for a in activities.values():
        if a["event_type"] == "LINK_RESOURCE_IDENTITY":
            for rid, alias in re.findall(r"\b([a-z_]+_\d+) \(([^)]+)\)", a["details"]):
                aliases.setdefault(rid, set()).add(alias)

    raw_rows = list(csv.reader(open(path, newline="", encoding="utf-8")))
    header, rows = raw_rows[0], raw_rows[1:]
    if header != HEADER:
        errors.append(f"header {header} != {HEADER}")
    for i, r in enumerate(rows, 2):
        if len(r) != 3:
            errors.append(f"line {i}: {len(r)} columns")
    ids = [r[0] for r in rows]
    dupes = [k for k, v in Counter(ids).items() if v > 1]
    if dupes:
        errors.append(f"duplicate case_ids: {dupes[:10]}")
    if set(ids) != set(requests):
        errors.append(
            f"case_id set differs: missing {sorted(set(requests) - set(ids))[:5]} extra {sorted(set(ids) - set(requests))[:5]}"
        )
    if ids != sorted(ids, key=case_num):
        errors.append("rows not sorted by case_id")

    status = Counter()
    provenance = Counter()
    file_cache: dict[str, bytes] = {}
    step_total = 0
    for r in rows:
        if len(r) != 3:
            continue
        cid, st, raw = r
        status[st] += 1
        if st not in STATUSES:
            errors.append(f"{cid}: status {st!r}")
        try:
            steps = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"{cid}: steps_json invalid JSON ({exc})")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json not an array")
            continue
        step_total += len(steps)
        if st == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: NOT_APPLICABLE with steps")
        if st == "COMPLETE" and not steps:
            errors.append(f"{cid}: COMPLETE without any evidence-backed verification")
        if st == "INCOMPLETE" and not steps:
            warnings.append(f"{cid}: INCOMPLETE with [] (no linkable evidence)")
        audit = ts(requests[cid]["audit_at"]) if cid in requests else None
        prev, seen = None, set()
        found, fixed, verified = set(), set(), set()
        ops_by_res: dict[tuple, dict[str, set]] = {}
        for n, s in enumerate(steps, 1):
            if not isinstance(s, dict) or set(s) != STEP_KEYS:
                errors.append(f"{cid}: step {n} keys {sorted(s) if isinstance(s, dict) else type(s)}")
                continue
            if s["step_no"] != n or isinstance(s["step_no"], bool):
                errors.append(f"{cid}: step_no {s['step_no']} at position {n}")
            if s["operation"] not in OP:
                errors.append(f"{cid}: operation {s['operation']}")
                continue
            phase, state, order = OP[s["operation"]]
            if (s["phase"], s["state"]) != (phase, state):
                errors.append(f"{cid}: {s['operation']} has phase/state {s['phase']}/{s['state']}")
            key = (PHASES.index(phase), order, s["system_id"], s["resource_id"])
            if prev is not None and key < prev:
                errors.append(f"{cid}: step {n} out of order")
            prev = key
            ident = (s["operation"], s["system_id"], s["resource_id"])
            if ident in seen:
                errors.append(f"{cid}: duplicate step {ident}")
            seen.add(ident)
            res = (s["system_id"], s["resource_id"])
            {"FINDING": found, "REMEDIATION": fixed, "VERIFICATION": verified}[phase].add(res)
            ops_by_res.setdefault(res, {p: set() for p in PHASES})[phase].add(s["operation"])
            if st == "COMPLETE" and phase != "VERIFICATION":
                errors.append(f"{cid}: COMPLETE contains {phase}")
            must_cite = phase == "FINDING" or (st == "COMPLETE" and phase == "VERIFICATION")
            ev = s["evidence_id"]
            if not must_cite:
                if ev != "":
                    errors.append(f"{cid}: future step {n} cites {ev!r}")
                continue
            if ev not in times:
                errors.append(f"{cid}: step {n} cites unknown evidence {ev!r}")
                continue
            if audit and times[ev] > audit:
                errors.append(f"{cid}: step {n} cites {ev} captured after audit_at")
            # semantic provenance: does the cited item actually concern this resource?
            rid = s["resource_id"]
            if ev in activities:
                ok = activities[ev]["resource_id"] == rid or rid in activities[ev]["details"]
                provenance["activity: names resource" if ok else "activity: does NOT name resource"] += 1
                if not ok:
                    errors.append(f"{cid}: {ev} does not concern {rid}")
            elif ev in paths:
                if paths[ev].lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
                    if ev not in file_cache:
                        file_cache[ev] = ocr_text(DATASET / paths[ev])
                    text = file_cache[ev]
                    if text is None:
                        provenance["screenshot (OCR unavailable; not verified)"] += 1
                    elif rid.encode() in text or rid.replace("_", " ").encode() in text:
                        provenance["screenshot OCR shows resource id"] += 1
                    elif any(a.encode() in text for a in aliases.get(rid, ())):
                        provenance["screenshot OCR shows catalog alias"] += 1
                    else:
                        provenance["screenshot OCR does NOT show resource"] += 1
                        errors.append(f"{cid}: screenshot {ev} does not show {rid}")
                    continue
                if ev not in file_cache:
                    file_cache[ev] = readable_bytes(DATASET / paths[ev])
                data = file_cache[ev]
                if rid.encode() in data:
                    provenance["file contains resource id"] += 1
                elif any(a.encode() in data for a in aliases.get(rid, ())):
                    provenance["file contains catalog alias of resource"] += 1
                else:
                    provenance["file does NOT mention resource"] += 1
                    errors.append(f"{cid}: {ev} does not mention {rid}")
            else:
                provenance["identity audit row"] += 1
        if st == "INCOMPLETE":
            for res in sorted(found - fixed):
                errors.append(f"{cid}: finding without remediation {res}")
            for res in sorted(fixed - found):
                errors.append(f"{cid}: remediation without finding {res}")
            for res in sorted(fixed - verified):
                errors.append(f"{cid}: remediation without verification {res}")
            for res, ops in sorted(ops_by_res.items()):
                for f in ops["FINDING"]:
                    if ops["REMEDIATION"] and not (ops["REMEDIATION"] & FIX_FOR[f]):
                        errors.append(f"{cid}: {f} on {res} remediated by {sorted(ops['REMEDIATION'])}")
                for r in ops["REMEDIATION"]:
                    if CHECK_FOR[r] not in ops["VERIFICATION"]:
                        errors.append(f"{cid}: {r} on {res} is not verified by {CHECK_FOR[r]}")

    facts = {
        "rows": len(rows),
        "expected requests": len(requests),
        "status counts": dict(sorted(status.items())),
        "steps": step_total,
        "citation provenance": dict(sorted(provenance.items())),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    report.add("output.csv", errors, warnings, facts)
    return facts


def committed_log(path: Path) -> str | None:
    try:
        rel = path.resolve().relative_to(ROOT)
        out = subprocess.run(["git", "show", f"HEAD:{rel.as_posix()}"], cwd=ROOT, capture_output=True, timeout=30)
    except (ValueError, OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8") if out.returncode == 0 else None


def check_log(path: Path, report: Report) -> None:
    errors, warnings = [], []
    text = path.read_text(encoding="utf-8")
    entries = re.split(r"(?m)^## \[", text)[1:]
    starts = [e for e in entries if "SESSION START" in e.splitlines()[0]]
    if not starts:
        errors.append("no SESSION START entry")
    for e in entries:
        title = e.splitlines()[0][:70]
        tools = re.findall(r"(?m)^tool=(.*)$", e)
        models = re.findall(r"(?m)^model=(.*)$", e)
        if len(tools) != 1 or not tools[0].strip() or tools[0].strip().lower() in ("unknown", "ai"):
            errors.append(f"entry '{title}': tool= must appear exactly once and be populated")
        if len(models) != 1 or not models[0].strip() or models[0].strip().lower() == "unknown":
            errors.append(f"entry '{title}': model= must appear exactly once and be populated")
        if "SESSION START" not in title:
            for section in ("User Prompt", "Agent Response Summary:", "Actions:", "Context:"):
                if section not in e:
                    errors.append(f"entry '{title}': missing section {section}")
    if SECRET.search(text):
        errors.append("possible secret in log.txt")
    # AGENTS.md section 2: append-only. The committed log must be an exact prefix of the working copy;
    # this catches deleted or rewritten entries (which per-entry format checks cannot see).
    committed = committed_log(path)
    if committed is None:
        warnings.append("append-only check skipped: log.txt is not tracked in a git checkout")
    elif not text.startswith(committed):
        errors.append("log.txt is not append-only: the committed version is not a prefix of the working copy")
    report.add(
        "log.txt",
        errors,
        warnings,
        {
            "entries": len(entries),
            "session starts": len(starts),
            "models seen": sorted(set(re.findall(r"(?m)^model=(.*)$", text))),
        },
    )


def check_zip(path: Path, report: Report) -> None:
    errors, warnings = [], []
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        bad = [n for n in names if ZIP_FORBIDDEN.search(n)]
        if bad:
            errors.append(f"forbidden entries: {bad[:10]}")
        required = [
            "README.md",
            "code/README.md",
            "code/main.py",
            "code/requirements.txt",
            "code/evaluation/evaluation_report.md",
            "code/evaluation/usage_report.md",
        ]
        for r in required:
            if r not in names:
                errors.append(f"missing {r}")
        nested = [n for n in names if n.startswith(("hackerrank", "code/code/"))]
        if nested:
            errors.append(f"unexpected nesting: {nested[:5]}")
        for n in names:
            if n.endswith((".py", ".md", ".txt", ".toml", ".ini", ".yml", ".csv", ".json", ".log", ".sql")):
                if SECRET.search(zf.read(n).decode("utf-8", "ignore")):
                    errors.append(f"possible secret in {n}")
    report.add("code.zip", errors, warnings, {"files": len(names), "bytes": path.stat().st_size})


def check_determinism(report: Report, reference: Path) -> None:
    hashes = []
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(2):
            out = Path(tmp) / f"run{i}.csv"
            subprocess.run(
                [sys.executable, str(ROOT / "code" / "main.py"), "--output", str(out)], check=True, capture_output=True
            )
            hashes.append(hashlib.sha256(out.read_bytes()).hexdigest())
    ref = hashlib.sha256(reference.read_bytes()).hexdigest()
    errors = [] if hashes[0] == hashes[1] == ref else [f"runs differ: {hashes} vs submitted {ref}"]
    report.add(
        "determinism",
        errors,
        [],
        {"regenerated twice from current code": "identical to output.csv" if not errors else "DIFFERENT"},
    )


def render(report: Report) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "# Submission Validation Report",
        "",
        f"_Generated by `python3 code/evaluation/validate_submission.py --rerun --write-report` on {stamp}._",
        "",
        "This report comes from a validator that shares no code with the agent; it checks rules taken directly",
        "from problem_statement.md and AGENTS.md. **Structural (schema) checks** are hard errors. Semantic",
        "checks are limited to what the participant data can verify:",
        "",
        "- every cited evidence item exists, is available by `audit_at`, and mentions the resource it is cited for;",
        "- every finding is remediated, every remediation is backed by a finding, and every remediation is verified.",
        "",
        "Whether a decision is *correct* against the hidden answers cannot be verified here.",
        "",
        f"**Result: {'PASS' if report.errors == 0 else 'FAIL'}** ({report.errors} error(s))",
        "",
    ]
    for title, errors, warnings, facts in report.sections:
        out += [f"## {title}", "", "| Item | Value |", "|---|---|"]
        for k, v in facts.items():
            out.append(f"| {k} | {v} |")
        out.append(f"| errors | {len(errors)} |")
        out.append(f"| warnings | {len(warnings)} |")
        out.append("")
        for e in errors[:50]:
            out.append(f"- ERROR: {e}")
        for w in warnings[:50]:
            out.append(f"- warning: {w}")
        if errors or warnings:
            out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--output", type=Path, default=ROOT / "output.csv")
    p.add_argument("--log", type=Path, default=ROOT / "log.txt")
    p.add_argument("--zip", type=Path, default=ROOT / "code.zip")
    p.add_argument("--rerun", action="store_true", help="regenerate output twice and compare (determinism)")
    p.add_argument("--write-report", action="store_true")
    args = p.parse_args(argv)
    report = Report()
    check_output(args.output, report)
    check_log(args.log, report)
    if args.zip.exists():
        check_zip(args.zip, report)
    else:
        report.add("code.zip", [], [f"{args.zip} not found (build it with the README zip command)"], {})
    if args.rerun:
        check_determinism(report, args.output)
    text = render(report)
    print(text)
    if args.write_report:
        (ROOT / "code" / "evaluation" / "validation_report.md").write_text(text + "\n", encoding="utf-8")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
