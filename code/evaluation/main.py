"""Repeatable evaluation workflow.

    python3 code/evaluation/main.py                 # samples + custom cases, print metrics
    python3 code/evaluation/main.py --tests         # also run the pytest suite first
    python3 code/evaluation/main.py --full          # also audit all 518 requests -> output.csv (validated)
    python3 code/evaluation/main.py --write-report  # refresh the generated blocks in the .md reports

Exits non-zero when a test fails, an output violates the contract, or a quality gate is missed.
Only participant-facing reference answers are used (dataset/sample_output.csv and the custom cases
written for this project); no organiser data is read.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
EVAL_DIR = CODE_DIR / "evaluation"
RUNS_DIR = REPO_ROOT / "runs"
sys.path.insert(0, str(CODE_DIR))

from deletion_auditor.application import AppConfig, AuditApplication  # noqa: E402
from deletion_auditor.evaluation import RegressionEvaluator, RegressionReport  # noqa: E402

CUSTOM_DATASET = EVAL_DIR / "custom_cases" / "fixture_data"
OFFICIAL_RULES = REPO_ROOT / "dataset" / "deletion_rules.csv"
CUSTOM_EXPECTED = EVAL_DIR / "custom_cases" / "expected_output.csv"


def run_suite(
    name: str, dataset: Path, requests: str, answers: Path, ocr: bool, rules: Path | None = None
) -> tuple[RegressionReport, object]:
    RUNS_DIR.mkdir(exist_ok=True)
    out = RUNS_DIR / f"{name}_predictions.csv"
    cfg = AppConfig(
        dataset_dir=dataset,
        requests_file=requests,
        output_path=out,
        run_log_path=RUNS_DIR / f"{name}_run_log.jsonl",
        enable_ocr=ocr,
        rules_path=rules,
    )
    summary = AuditApplication(cfg).run(validate=True)  # raises OutputValidationError on contract breach
    return RegressionEvaluator().evaluate(out, answers), summary


def fmt_pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def metrics_table(title: str, report: RegressionReport) -> str:
    m = report.metrics
    k, e = m["step_key"], m["step_exact"]
    fa = m["field_accuracy"]
    lines = [
        f"#### {title} ({m['cases']} cases)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Case-level deletion_status accuracy | {fmt_pct(m['case_status_accuracy'])} |",
        f"| Sequence accuracy (entire steps_json identical) | {fmt_pct(m['sequence_accuracy'])} |",
        f"| Step precision / recall / F1 (operation+system+resource) | {fmt_pct(k['precision'])} / {fmt_pct(k['recall'])} / {fmt_pct(k['f1'])} |",
        f"| Step precision / recall / F1 (all fields except step_no) | {fmt_pct(e['precision'])} / {fmt_pct(e['recall'])} / {fmt_pct(e['f1'])} |",
        f"| Steps TP / FP / FN (key match) | {k['tp']} / {k['fp']} / {k['fn']} |",
        f"| Field accuracy on matched steps: phase / state / evidence_id / step_no | {fmt_pct(fa['phase'])} / {fmt_pct(fa['state'])} / {fmt_pct(fa['evidence_id'])} / {fmt_pct(fa['step_no'])} |",
        f"| Status confusion (expected->predicted) | {', '.join(f'{a}: {b}' for a, b in m['confusion'].items())} |",
        "",
    ]
    fails = report.failures()
    if fails:
        lines += ["Cases whose steps differ (missing = expected but not produced, extra = produced but not expected):", ""]
        for c in fails:
            miss = "; ".join(f"{op} {rid}" for op, _, rid in c.missing()) or "-"
            extra = "; ".join(f"{op} {rid}" for op, _, rid in c.extra()) or "-"
            lines.append(f"- `{c.case_id}` {c.expected_status}->{c.predicted_status}: missing {miss}; extra {extra}")
        lines.append("")
    return "\n".join(lines)


def replace_block(path: Path, marker: str, content: str) -> None:
    text = path.read_text(encoding="utf-8")
    start, end = f"<!-- BEGIN {marker} -->", f"<!-- END {marker} -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
    block = f"{start}\n{content.strip()}\n{end}"
    if not pattern.search(text):
        raise SystemExit(f"marker {marker} not found in {path}")
    path.write_text(pattern.sub(lambda _: block, text), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tests", action="store_true", help="run pytest first")
    p.add_argument("--full", action="store_true", help="audit all requests and validate output.csv")
    p.add_argument("--write-report", action="store_true", help="refresh generated blocks in the reports")
    p.add_argument("--no-ocr", action="store_true")
    p.add_argument("--require-dataset", action="store_true", help="fail instead of skipping when dataset/ is absent")
    # 0.90 floor: the agent refuses unsupported COMPLETE decisions, which costs the sample cases whose
    # completion no participant-visible evidence proves; the structural gates below are strict.
    p.add_argument("--min-status-accuracy", type=float, default=0.90)
    p.add_argument("--min-step-precision", type=float, default=0.95)
    p.add_argument("--min-custom-sequence", type=float, default=1.0)
    args = p.parse_args(argv)
    failures: list[str] = []
    ocr = not args.no_ocr

    if args.tests:
        print("== pytest")
        rc = subprocess.call([sys.executable, "-m", "pytest", "-q", str(CODE_DIR / "tests")], cwd=REPO_ROOT)
        if rc != 0:
            failures.append(f"pytest exited with {rc}")

    dataset = REPO_ROOT / "dataset"
    has_dataset = (dataset / "sample_output.csv").exists()
    if not has_dataset and (args.require_dataset or args.full):
        failures.append("dataset/ is missing but was required")
    sample = None
    if has_dataset:
        print("== sample regression (dataset/sample_output.csv)")
        sample, _ = run_suite("sample", dataset, "sample_deletion_requests.csv", dataset / "sample_output.csv", ocr)
    else:
        print("== dataset/ not present: sample regression skipped (custom cases still run)")
    print("== custom evaluation cases")
    if not OFFICIAL_RULES.exists():
        print("EVALUATION FAILED: custom cases need the official dataset/deletion_rules.csv", file=sys.stderr)
        return 1
    custom, _ = run_suite("custom", CUSTOM_DATASET, "deletion_requests.csv", CUSTOM_EXPECTED, ocr=False, rules=OFFICIAL_RULES)
    for label, rep in (("sample", sample), ("custom", custom)):
        if rep is None:
            continue
        m = rep.metrics
        print(
            f"   {label}: status={fmt_pct(m['case_status_accuracy'])} seq={fmt_pct(m['sequence_accuracy'])} "
            f"stepP={fmt_pct(m['step_key']['precision'])} stepR={fmt_pct(m['step_key']['recall'])} "
            f"evidence={fmt_pct(m['field_accuracy']['evidence_id'])}"
        )

    if sample is not None:
        sm = sample.metrics
        if sm["case_status_accuracy"] < args.min_status_accuracy:
            failures.append(f"sample status accuracy {sm['case_status_accuracy']:.3f} < {args.min_status_accuracy}")
        if sm["step_key"]["precision"] < args.min_step_precision:
            failures.append(f"sample step precision {sm['step_key']['precision']:.3f} < {args.min_step_precision}")
        false_complete = [c.case_id for c in sample.cases if c.predicted_status == "COMPLETE" != c.expected_status]
        if false_complete:
            failures.append(f"false COMPLETE decisions on samples: {false_complete}")
        unexplained = [
            c.case_id
            for c in sample.cases
            if not c.status_ok
            and not (
                c.predicted_status == "INCOMPLETE"
                and not any(s["phase"] in ("FINDING", "REMEDIATION") for s in c.predicted_steps)
            )
        ]
        if unexplained:
            failures.append(f"status mismatches that are not insufficient-evidence INCOMPLETEs: {unexplained}")
    cm = custom.metrics
    if cm["sequence_accuracy"] < args.min_custom_sequence:
        failures.append(f"custom-case sequence accuracy {cm['sequence_accuracy']:.3f} < {args.min_custom_sequence}")

    full_summary = None
    if args.full and has_dataset:
        print("== full dataset run -> output.csv")
        cfg = AppConfig(enable_ocr=ocr)
        full_summary = AuditApplication(cfg).run(validate=True)
        print(
            f"   {full_summary.cases} cases {full_summary.status_counts} in {full_summary.seconds}s; "
            f"errors={len(full_summary.errors)}"
        )
        if full_summary.errors:
            failures.append(f"{len(full_summary.errors)} case(s) raised errors in the full run")

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = "\n".join(
        [
            f"_Generated by `python3 code/evaluation/main.py --write-report` on {stamp}._",
            "",
            metrics_table("Provided samples (dataset/sample_output.csv)", sample)
            if sample
            else "_Sample regression skipped: dataset/ not present._\n",
            metrics_table("Custom evaluation cases (code/evaluation/custom_cases)", custom),
        ]
    )
    summary_md = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_md:
        with open(summary_md, "a", encoding="utf-8") as fh:
            fh.write("## Deletion-audit evaluation\n\n" + body + "\n")
            if failures:
                fh.write("\n**Gate failures:**\n" + "\n".join(f"- {f}" for f in failures) + "\n")

    if args.write_report:
        replace_block(EVAL_DIR / "evaluation_report.md", "GENERATED-METRICS", body)
        if full_summary is not None:
            usage = [
                f"_Generated on {stamp} from the full run that wrote `output.csv`._",
                "",
                "| Item | Value |",
                "|---|---|",
                f"| Requests processed | {full_summary.cases} |",
                f"| Status counts | {', '.join(f'{k}: {v}' for k, v in full_summary.status_counts.items())} |",
                f"| Wall-clock time | {full_summary.seconds} s |",
            ]
            if full_summary.model_usage:
                for u in full_summary.model_usage:
                    usage.append(
                        f"| {u.provider}/{u.model} calls / input / output tokens | {u.calls} / {u.input_tokens} / {u.output_tokens} |"
                    )
            else:
                usage.append("| Model calls | 0 (LLM disabled; deterministic pipeline) |")
            replace_block(EVAL_DIR / "usage_report.md", "GENERATED-USAGE", "\n".join(usage))
        print("reports updated")

    if failures:
        print("EVALUATION FAILED:\n  - " + "\n  - ".join(failures), file=sys.stderr)
        return 1
    print("evaluation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
