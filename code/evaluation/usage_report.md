# Usage Report — final full-dataset run

## Summary

The run that produced the submitted `output.csv` is **fully deterministic and made no model calls**.
Every decision comes from parsing evidence, matching identifiers and applying `deletion_rules.csv`.

| Provider | Model | Model calls | Input tokens | Output tokens | Total tokens | Avg tokens / request | Est. cost | Est. cost / request |
|---|---|---|---|---|---|---|---|---|
| — (none) | — | 0 | 0 | 0 | 0 | 0 | $0.00 | $0.00 |
| **Overall** | | **0** | **0** | **0** | **0** | **0** | **$0.00** | **$0.00** |

Non-LLM components used in the run:

| Component | What it does | Cost |
|---|---|---|
| Python `sqlite3` (stdlib) | Executes the SQL snapshot exports | local |
| PyPDF2 | Extracts text from PDF evidence | local |
| Tesseract OCR 5 via `pytesseract` | Reads text from screenshot evidence | local |

<!-- BEGIN GENERATED-USAGE -->
_Generated on 2026-10-24 19:54 UTC from the full run that wrote `output.csv`._

| Item | Value |
|---|---|
| Requests processed | 518 |
| Status counts | COMPLETE: 153, INCOMPLETE: 355, NOT_APPLICABLE: 10 |
| Wall-clock time | 10.21 s |
| Model calls | 0 (LLM disabled; deterministic pipeline) |
<!-- END GENERATED-USAGE -->

## Why no LLM in the final run

- On the 32 public samples the deterministic pipeline reaches 100% step precision, 100% `evidence_id`
  accuracy and zero false COMPLETE decisions. Its status accuracy is 90.6%; the 3 misses are
  insufficient-evidence cases. Every missed step is a resource that has no identifier link in participant
  evidence available at `audit_at`. A model cannot recover such a link without inventing data.
- Determinism makes the output reproducible bit-for-bit, which an integration test asserts, and easy to
  audit. That matters for a compliance artifact.

## Optional LLM path (implemented, off by default)

- **What is wired in.** `LLMIntentClassifier` is consulted only when the rule-based intent confidence is
  below 0.8. `LLMEvidenceInterpreter` is used only when rule-based parsing of a PDF or OCR text finds nothing.
- **Guardrail.** Any resource id or identifier returned by the model that is not present verbatim in the
  source text is dropped.
- **How to enable.** Set `AUDIT_USE_LLM=1` and `OPENAI_API_KEY` (and optionally `AUDIT_LLM_MODEL`, default
  `gpt-4o-mini`). Keys are read from the environment only.
- **Usage tracking.** `ModelUsage` counts calls and input/output tokens. With `--write-report`, the counts
  are written into the generated block above per provider and model.
- **Expected volume if enabled on this dataset.** I measured this rather than estimating it. All 518
  requests are classified by the rules with confidence 0.95, so the intent LLM would make 0 calls. 14 of the
  15 PDFs and screenshots yield rule-based records. The exception is `legal_retention_register_20260529.pdf`,
  which lists order numbers rather than resource ids, so the interpreter fallback would make exactly 1 call
  of about 1.5k input tokens. A worst case of one intent call per request at about 300 input and 30 output
  tokens would be roughly 170k tokens in total.
