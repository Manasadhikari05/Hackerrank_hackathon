# Deletion-Audit Agent — architecture, setup and evaluation

An evidence-driven agent that decides, for every request in `dataset/deletion_requests.csv`, whether
the person asked for deletion, reconstructs what is really left in every system at `audit_at`, and
emits the ordered findings → remediation → verification plan required by `problem_statement.md`.

## Setup and run

```bash
python3 -m pip install -r code/requirements.txt          # PyPDF2, pytesseract, Pillow
brew install tesseract   # or: sudo apt-get install tesseract-ocr   (screenshot OCR)
python3 code/main.py                                      # writes ./output.csv (518 rows, validated)
```

| Command | Purpose |
|---|---|
| `python3 code/main.py` | Audit all requests → `output.csv`. Exits non-zero if the output breaks the contract |
| `python3 code/main.py --requests sample_deletion_requests.csv --output runs/s.csv` | Run on the public samples |
| `python3 code/main.py --no-ocr` | Run without Tesseract (screenshots skipped) |
| `python3 code/try_request.py --email E --text T --requested-at TS --audit-at TS` | Audit one hand-entered request (timestamps required) |
| `python3 -m pip install -r code/requirements-dev.txt && python3 -m pytest code/tests` | Test suite |
| `python3 code/evaluation/main.py --tests --full --write-report` | Full evaluation workflow; refreshes the reports |

Python 3.10+ is required. No API key is needed. The LLM path is opt-in through `AUDIT_USE_LLM=1` and
`OPENAI_API_KEY`, both read from the environment only.

## Architecture

The design follows the layered UML (Domain, Interfaces, Infrastructure, Services, Validation, Application).
Dependencies point inward: services depend on domain models and interfaces only, and a contract test
enforces that `services/` never imports `infrastructure/`.

```
code/
├── main.py                         CLI entry point
├── deletion_auditor/
│   ├── domain/        enums.py, models.py, identifiers.py, catalog.py   (no I/O)
│   ├── interfaces/    repositories.py, processing.py, ml.py, output.py   (ABCs)
│   ├── infrastructure/
│   │   ├── repositories.py     CsvRequest/Identity/Policy/Activity repos, FileEvidenceRepository
│   │   ├── extractors.py       Json, SqlSnapshot, Log (5 dialects), Text, Pdf, ImageOcr
│   │   ├── record_builder.py   one place that turns a field map into an EvidenceRecord
│   │   ├── interpreters.py     RuleBasedInterpreter, LLMEvidenceInterpreter (guarded)
│   │   ├── activity_adapter.py trusted activity rows → evidence; catalog aliases
│   │   ├── intent.py           RuleBasedIntentClassifier, LLMIntentClassifier
│   │   ├── model_clients.py    OpenAIModelClient (optional), ScriptedModelClient (tests)
│   │   └── output_writer.py    CsvOutputWriter (atomic, deterministic JSON)
│   ├── services/      identity_resolver, evidence_collector, recreation_risk,
│   │                  policy_evaluator, status_decider, step_planner, orchestrator
│   ├── validation/    OutputSchema, StepOrder, EvidenceReference, DecisionInvariant validators
│   ├── evaluation/    RegressionEvaluator (case/step/field/sequence metrics)
│   └── application/   AppConfig, AuditApplication (composition root), RunLogger
├── evaluation/        main.py (workflow), custom_cases/, evaluation_report.md, usage_report.md
└── tests/             unit/ contract/ validation/ integration/ regression/ e2e/
```

### Per-case pipeline (`AuditOrchestrator`)

1. **Intent.** `IntentClassifier` decides whether `request_text` authorizes deletion. It is multilingual,
   and explicit refusals ("keep the account", "not asking for deletion") always win. If not → `NOT_APPLICABLE`, `[]`.
2. **Identity.** `IdentityResolver` resolves the request email, current or historical, to `user_id`. It
   collects every email, phone and sha256 email hash from the snapshot plus `user_audit_log` changes made
   up to `audit_at`. Names are not used for linking because decoys share names; near-duplicate emails never
   match because tokens are exact.
3. **Evidence.** `EvidenceCollector` indexes the corpus once. Every format becomes `EvidenceRecord`s with
   `resource_id`, linking identifiers, exposed identifier kinds, flags (`flow_enabled`, `restore_allowed`,
   redacted, anonymized), observation time and capture time. For each case it returns the resources linked
   to the subject.
4. **State at `audit_at`.** The latest informative observation from evidence observed *and* captured by
   `audit_at` decides the state. Records from the same capture are merged pessimistically, so a replica copy beats an absent primary.
5. **Recreation risk.** `RecreationRiskAnalyzer` checks connectors (enabled → `REPORT_ACTIVE_DATA_FLOW`) and
   backups (restorable → `REPORT_RESTORE_RISK`).
6. **Policy.** `PolicyEvaluator` maps the category to the rule in `deletion_rules.csv`:
   - DELETE: compliant when the record is absent.
   - REDACT: compliant when it holds no direct identifiers; a `user_id` reference may stay, as for tombstones.
   - ANONYMIZE: compliant when neither direct identifiers nor a user reference remain.
   - RETAIN: the record must be present; expired retention falls back to DELETE.
7. **Status.** `StatusDecider` returns COMPLETE only if there is at least one assessment, every assessment
   is compliant and backed by citable evidence, and no linked record is undeterminable or a stale violation.
   Otherwise it returns INCOMPLETE, flagged as insufficient evidence when no violation was found.
8. **Steps.** `StepPlanner` builds FINDING → REMEDIATION → VERIFICATION. Within each phase it orders by
   the official operation table, then `system_id`, then `resource_id`. Flows are therefore disabled and
   restores blocked before records change.

   Findings and COMPLETE verifications cite the latest evidence that proves the same verdict and was
   captured by `audit_at`. Future steps cite `""`.
9. **Invariants.** `DecisionInvariantValidator` runs on every result. After writing, the whole file is
   validated, and any violation fails the run.

### Key decisions and trade-offs

| Decision | Why | Trade-off |
|---|---|---|
| Deterministic core, LLM optional | Reproducible, auditable output with 0 tokens. On the samples, every remaining miss is information absent from the evidence, which a model cannot supply honestly | Free-text edge cases rely on rules. The LLM fallback exists for them, guarded against invented ids |
| One `EvidenceRecord` shape for all formats | Services stay format-agnostic (OCP/DIP). A new format means one new extractor | The shape must carry enough flags for every system |
| Lookup keys link but do not expose | A `404` lookup *for* `a@b.com` proves the account is linked and gone, not that it stores the email | Needs per-key semantics in `record_builder.py` |
| Strict time admissibility | A record counts (for linkage, state and citation) only if it was observed at or before `audit_at` **and** its evidence item's manifest `captured_at` is at or before `audit_at`, so later evidence never changes the answer | Lower recall: some links exist only in files exported after `audit_at` |
| COMPLETE must be proven | Absence of evidence is not evidence of absence. With no linked record, an unproven verdict, an undeterminable record, or a stale violation, the result is INCOMPLETE flagged insufficient evidence, never COMPLETE `[]` | 3 sample cases the reference marks COMPLETE are INCOMPLETE `[]` |
| Scope = observations on/after `requested_at` | Records seen only months before the request are not what the workflow left behind (validated on the samples) | A record never re-checked after the request is ignored |
| No guessing of unlinkable resources | Activity batches mix several customers, so a guess adds a false positive and still misses the true step | Lower recall (0.86 on samples) |
| Per-case error isolation plus loud validation | One bad case cannot abort 517 others, and an invalid file can never be written silently | Errors surface as non-zero exit codes |

### Adaptations from the UML diagram

- `StepPhase` (IDENTIFY/ANALYZE/REMEDIATE/VERIFY) became the contract's FINDING/REMEDIATION/VERIFICATION.
  `RemediationStep` became `AuditStep`, with exactly the seven contract fields, covering all phases.
- `EvidenceRecord` is the normalized observation rather than a raw file. `EvidenceType` adds LOG, TEXT and ACTIVITY.
- `AuditFinding` became `ResourceAssessment`, which carries the policy verdict and the evidence to cite.
- I added a `LogExtractor`, because logs are the largest evidence class, and an `ActivityEvidenceAdapter`.
  Activity rows are claims; only explicit checks, repopulation events and catalog links are trusted.
- `OpenAIModelClient` sits behind a provider-neutral `ModelClient`. `ScriptedModelClient` is the test double.
- `RegressionEvaluator` lives in `deletion_auditor/evaluation/`. The evaluation CLI is `code/evaluation/main.py`.
- `RunLogger` writes `runs/run_log.jsonl` with case ids, counts and warnings only, never personal data.
  The agent transcript stays in `log.txt` per AGENTS.md.

## Tests and CI

`code/tests` holds 142 tests plus one opt-in live-LLM test.

| Layer | Examples |
|---|---|
| unit | identity and decoys, record interpretation, every log dialect, PDF/OCR (injected engine), policy, risk, ordering, intent in six languages, mocked LLM fallback, hallucination filter |
| contract | every extractor/interpreter/classifier/repository/writer honours its ABC and never raises on garbage; the services layer does not import infrastructure |
| validation | negative tests: invalid status, malformed JSON, unknown operation, extra keys, fabricated or post-audit evidence, wrong order/numbering, phase/state mismatch, NA with steps, COMPLETE with findings |
| integration | custom cases end-to-end; missing, corrupt and unsupported evidence; malformed or duplicate requests; validator blocks bad output; determinism; no PII in the run log |
| regression | sample gates: zero false COMPLETE, every status mismatch is an insufficient-evidence INCOMPLETE, status ≥ 90%, step precision ≥ 95%, recall ≥ 80%, evidence/state/phase fields |
| e2e | `main.py` on all 518 requests |

`.github/workflows/ci.yml` runs on push, pull request and manual dispatch:
1. Ruff lint and format check.
2. pytest on Python 3.10 and 3.12, with Tesseract installed and JUnit XML uploaded.
3. The evaluation workflow, which writes metrics to the job summary and uploads predictions and run logs.

Steps that need `dataset/` are skipped automatically when the dataset is not committed. No secrets are
used in CI.
