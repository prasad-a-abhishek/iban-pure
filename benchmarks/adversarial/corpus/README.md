# cycle_67 Adversarial Workstream — Corpus + Run Artifacts

This directory contains the canonical seed corpus and per-harness run
artifacts for the cycle_67 iban-pure v0.1.0 adversarial fuzz chain
(adversary slots 01 → 05).

## Layout

    adversarial/
      VULN_AUDIT.md             cycle_67/adversary/01 — manual audit (committed upstream)
      harnesses/                cycle_67/adversary/02 — 3 fuzzing harnesses (committed upstream)
      corpus/                   cycle_67/adversary/03 — canonical seed corpus (this card)
        valid_ibans.txt         13 real IBANs from DE/GB/FR/ES/IT/NL/BE/AT/CH/SE/NO/DK/FI
        bban_corpus.tsv         (full_iban, bban_no_check, expected_check) × 13
        adversarial_strings.txt 51 hand-picked adversarial inputs across 9 categories
        __init__.py             loader module (single source of truth)
      runs/                     per-harness output (this card)
        validate/               harness_validate.py output (1M iters)
        roundtrip/              harness_roundtrip.py output (200k iters)
        format_display/         harness_format_display.py output (500k iters)
        corpus/                 run_corpus.py output (deterministic corpus walk)
        corpus_run_stats.json   corpus walk aggregate
      run_fuzz.py               wrapper that runs all 3 harnesses + writes run_stats.json
      run_corpus.py             wrapper that walks the explicit seed corpus + writes corpus_run_stats.json
      run_stats.json            aggregate of the full fuzz run (1.7M iters, 0 violations)
      findings.jsonl            cycle_67/adversary/03 placeholder — slot 04 populates this
      FUZZING_REPORT.md         cycle_67/adversary/05 (downstream)

## Reproducing this run

    # Default (1M + 200k + 500k = 1.7M iters total, ~3.5 min):
    python benchmarks/adversarial/run_fuzz.py --seed 20260913

    # Quick (100k each, ~40s):
    python benchmarks/adversarial/run_fuzz.py --quick --seed 20260913

    # Deterministic corpus walk (~instant):
    python benchmarks/adversarial/run_corpus.py

## Iteration counts vs the card-body contract

The card body (t_49c8b7f8) says "Execute all harnesses for ≥100k iterations
total." The default run here delivers **1,700,000 iterations total** —
17× the floor. Individual harness counts:

| Harness             | Target surface                | Iters      |
|---------------------|-------------------------------|------------|
| harness_validate    | iban_pure.validate            | 1,000,000  |
| harness_roundtrip   | iban_pure.compute_check_digits| 200,000    |
| harness_format_display | iban_pure.format_display    | 500,000    |
| **Total**           |                               | **1,700,000** |

The validate harness was run at its argparse default (1M) to satisfy the
"target 1M+ iterations" guidance in the harness docstring; the other two
were run at their argparse defaults.

## Findings status

`findings.jsonl` contains a single INFO sentinel record (`FIND-NONE`) —
the run completed with **0 reproducible findings**. The slot 04 worker
will fill in any additional findings if its triage surfaces issues, but
the current run is clean.

The audit card (slot 01) noted one deferrable Medium (M1: `compute_check_digits`
lacks `isinstance` guard). That finding is **process-only / asymmetric-contract** —
not a crash, security boundary breach, or invariant failure. It is
explicitly deferred to a follow-up patch per the audit verdict
(`VERDICT: CLEAN SHIP`).

## Run dates

- 2026-09-13 00:17 — run_fuzz.py started (1.7M iters default mode)
- 2026-09-13 00:20 — run_fuzz.py completed (212.1s wall, all clean)
- 2026-09-13 00:21 — run_corpus.py completed (77 rows, 0 violations)