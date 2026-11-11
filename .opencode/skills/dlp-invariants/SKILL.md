---
name: DLP and egress invariants
description: Change the DLP, routing or egress stages without breaking their contracts. Use when editing agent/dlp, agent/routing, agent/egress, the golden corpus, or ADR-002 and ADR-011, and before calling an eval or threshold change safe.
---

# DLP, routing and egress invariants

These are contracts, not preferences. A change that moves one is an ADR change,
not a tweak.

## Thresholds and what they decide

| setting | default | decides |
| --- | ---: | --- |
| `dlp_score_threshold` | 0.35 | Presidio confidence floor for an entity |
| `dlp_language_min_confidence` | 0.80 | below it the text is analysed as English (ADR-002) |
| `classifier_injection_profile` | `production` | 0.662 injection cut-off; `recall-first` lowers it to 0.5 |
| `classifier_safety_unsafe_threshold` | 0.5 | aggregate safety score that routes `unsafe_content` |
| `classifier_safety_category_threshold` | 0.3 | per-category routing (`privacy`, `fraud_manipulation`, …) |

Read them from `settings.py` rather than a document; the table above is the
default, and `.env` can override each one.

## Fail-closed contracts

- Presidio failing to initialise raises `DLPUnavailableError`; text is never passed through unredacted.
- The classifier fails closed: an inference error or malformed output yields `CONFIDENTIAL`.
- A prompt with `pii_detected` routes to `local-llama` even when the label stays `PUBLIC`; a local-model failure there returns 503 with a `SECURITY_INCIDENT`, never a cloud fallback.
- Tokens are `{{ENTITY:TYPE_INDEX}}` with a reversible AES-GCM mapping in Redis; vault, canary and quarantine keys share a **1800 s** TTL.
- Every session carries `BASTION-CANARY-<uuid4>`; a leak trips the breaker, and untrusted content is fenced before it reaches the model.

## The corpus is a measurement input

`tests/data/goldens.jsonl` is ADR-006's calibration corpus. ADR-011's recall and
false-positive numbers are measured *against it*, so adding, removing or
retitling a row changes a published measurement even when no code moved.

- Pin a regression in the specific unit test (`tests/test_dlp_presidio.py`,
  `tests/test_classifier_evals.py`), not by adding a golden row. That was the
  IDEA-014 decision and it keeps the corpus counts stable.
- Take current eval numbers from `artifacts/evals/latest.json`, never from a
  sentence in a document.

## Verifying a change

```bash
uv run pytest -q tests/test_dlp_presidio.py tests/test_classifier_evals.py tests/test_dlp_evals.py
uv run python scripts/run_evals.py        # or: scripts/gate.sh --evals
scripts/gate.sh                           # full gate before closing
```

Both eval metrics must stay at 1.000. A score below 1.0 is a regression in the
guardrail, not a threshold to relax.

## Sequence for a threshold or entity change

1. Decide it in the ADR that owns it — ADR-002 for DLP behaviour, ADR-011 for the classifier ensemble.
2. Update `settings.py`, `.env.example` and the README section that documents the knob.
3. Re-run evals and, if corpus rows moved, re-measure the ADR-011 numbers.
4. Run `scripts/gate.sh`.

## Done

Evals report 1.000 on every metric, the gate is green, and any contract that
changed is recorded in the owning ADR in the same change.
