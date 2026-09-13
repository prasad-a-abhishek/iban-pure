# TRIAGE_REPORT — iban-pure v0.1.0 (cycle_67 adversarial, slot 04)

**Target commit**: `4bf40d0` (docs(qa): add QA_REPORT.md — VERDICT SHIP)
on `wt/cycle_67-fix`
**Workdir**: `/root/projects/iban-pure/.worktrees/t_0476cddf`
**Branch**: `wt/cycle_67-adversary-04` (parent: `wt/cycle_67-adversary-03` @ `8b98434`)
**Auditor**: @default (cycle_67/adversary/04)
**Date**: 2026-09-13
**Parent slot**: `t_49c8b7f8` (cycle_67/adversary/03) — 1.7M iters, 0 crashes, 0 invariant violations
**Audit doc reference**: `benchmarks/adversarial/VULN_AUDIT.md` (cycle_67/adversary/01)
**Findings manifest**: `benchmarks/adversarial/findings.jsonl` (7 entries — 1 INFO + 3 MEDIUM + 3 LOW)
**Independent evidence**: `benchmarks/adversarial/triage/triage_evidence.json`
**Per-finding repros**: `benchmarks/adversarial/findings/M1_min/`

---

## 0. Executive summary

Slot-04 (triage) ran on the back of slot-03's clean fuzz run
(1.7M iterations, 0 crashes, 0 invariant violations across 3 harnesses)
and an **independent 50k random sweep** plus a **comment-aware re-walk
of the canonical 13-IBAN corpus**. Both came back clean for every
invariant except the **single audit-deferred MEDIUM** (M1) that
slot-02 and slot-03 already documented as R5 expected-divergent
behavior.

**Zero NEW findings were discovered in slot-04.** All 6 actionable
findings in `findings.jsonl` are carry-forwards from the slot-01
audit, ranked Medium/Low per the audit's own severity table, and
already explicitly deferred by the auditor as "defensive-coding only,
not blocking pre-ship".

**Verdict recommendation for slot-05**:
**`VERDICT: SHIP`** with M1 (and the 2 process drifts M2/M3)
documented as carry-forward items to a cycle_68 follow-up patch.
A `REMEDIATE_REQUIRED` verdict is defensible only if the cycle
owner wants M1 fixed pre-ship; nothing in the fuzz evidence supports
such a flip.

---

## 1. Triage methodology

The triage pass followed the canonical "minimize + rank + decide"
flow:

1. **Read slot-03's run_stats.json** to confirm: 1.7M iterations,
   0 invariant violations, all 3 harnesses clean, all 3 crash_log.txt
   files 0 bytes.
2. **Read slot-03's findings.jsonl** to confirm: single INFO sentinel
   (FIND-NONE), zero actionable findings.
3. **Re-read slot-01's VULN_AUDIT.md** to identify audit-deferred
   findings (M1, M2, M3, L1, L2, L3) and the audit's own verdict
   (CLEAN — SHIP).
4. **Independent verification sweep** (deterministic, seed 424242):
   - 50k random string inputs across `validate()` and
     `format_display()` — zero raises.
   - All 13 canonical IBANs from `valid_ibans.txt` walked through
     validate → format_display → validate round-trip — zero
     violations.
   - All 13 canonical IBANs walked through R6 (compute_check_digits
     reproduces original check digits when fed `cc + bban`) — zero
     violations.
   - 11 distinct non-str inputs walked through `compute_check_digits`
     — every single one raises (10× AttributeError + 1× TypeError
     for bytes), confirming audit's M1.
5. **Minimization**: For each non-NONE finding, minimized the repro
   to a single Python invocation. Only M1 needs a per-finding
   artifacts directory (M2/M3/L1/L2/L3 are already 1-line audits
   that need no minimization).
6. **Ranking**: Followed audit's severity table verbatim
   (Critical=0, High=0, Medium=3, Low=3, Info=1).
7. **Decision**: Did NOT promote any audit-deferred finding to
   blocking. Did NOT suppress any audit finding. Wrote every audit
   finding into the slot-04 findings manifest so the chain has a
   complete audit trail.

---

## 2. Inputs considered

| Source | File / location | Used for |
|---|---|---|
| Slot-03 fuzz results | `benchmarks/adversarial/run_stats.json` | Confirm zero crashes / invariant violations |
| Slot-03 crash logs | `benchmarks/adversarial/runs/*/crash_log.txt` | Confirm 0-byte (no crash artifacts) |
| Slot-03 findings | `benchmarks/adversarial/findings.jsonl` | Confirm single INFO sentinel |
| Slot-01 audit | `benchmarks/adversarial/VULN_AUDIT.md` | Source of M1, M2, M3, L1, L2, L3 findings |
| Source under test | `iban_pure/__init__.py` @ commit 4bf40d0 | Verify each finding's file:line location |
| Canonical corpus | `benchmarks/adversarial/corpus/valid_ibans.txt` | Round-trip walk (13 IBANs × R1-R7) |
| Canonical corpus | `benchmarks/adversarial/corpus/adversarial_strings.txt` | Adversarial walk (51 inputs × validate + format_display) |
| Independent sweep | `benchmarks/adversarial/triage/triage_evidence.json` | 50k random seed=424242 sweep |

---

## 3. Findings ranked by severity

Severity counts (per `findings.jsonl`):

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High     | 0 | — |
| Medium   | 3 | FIND-M1, FIND-M2, FIND-M3 |
| Low      | 3 | FIND-L1, FIND-L2, FIND-L3 |
| Info     | 1 | FIND-NONE |

Per-finding narrative:

### 3.1 FIND-NONE (INFO) — fuzz run clean

Slot-03 reported 1.7M iterations with zero crashes and zero invariant
violations across 3 harnesses (validate, roundtrip, format_display).
Slot-04's independent 50k random sweep (seed 424242) corroborated
this. The canonical 13-IBAN corpus walked cleanly through every
invariant. **No actionable findings produced by the fuzz run.**

### 3.2 FIND-M1 (Medium, deferred) — compute_check_digits lacks isinstance guard

The single code-relevant medium. Reproduces 100% with the
1-liner `compute_check_digits(None)`. Audit-deferred ("defensive
coding only, not blocking"). Slot-04 promotes from "audit-deferred,
not in fuzz findings" to "tracked Medium, deferred, not blocking".

**Decision**: Carry forward to cycle_68 as a 1-line defensive fix.
Do NOT block ship.

### 3.3 FIND-M2 (Medium, process drift) — `normalize` listed in card body but not shipped

Kanban card body for the cycle_67 chain describes iban-pure as
having 4 public functions including `normalize(iban: str) -> str`.
The shipped module exports only 3 (validate, compute_check_digits,
format_display). Audit recorded as M2 process finding.

**Decision**: Card body template fix; not a code defect. Carry forward
to cycle_68 for repo-factory card-template maintenance.

### 3.4 FIND-M3 (Medium, process drift) — compute_check_digits described as 2-arg in card body

Kanban card body describes compute_check_digits as `(country_code, bban)`
but shipped signature is `(bban)` with country code as the first 2 chars
of `bban`. Same root cause as M2.

**Decision**: Same as M2 — card body template fix; carry forward.

### 3.5 FIND-L1 (Low) — DK fixture in tests is malformed

`DK5000400440116243` is a stale fixture carried from upstream
copy-paste. Passes the mod-97 check because mod-97 is permissive
about BBAN structure, but the national-check-digit scheme inside
the BBAN is suspect.

**Decision**: Non-functional; QA already triaged. Carry forward.

### 3.6 FIND-L2 (Low) — README documents `python -m iban_pure` but no `__main__.py`

First-time users following the README hit `ModuleNotFoundError`.
Not a security issue; a docs drift.

**Decision**: README cleanup. Carry forward to cycle_68.

### 3.7 FIND-L3 (Low) — format_display has no validation gate

`format_display("DE89 3704 extra garbage here")` returns
`"DE89 3704 extra garbage here"` — silently groups garbage into
4-char blocks without raising. Confusing but not crash-y.

**Decision**: Defensive coding only. Carry forward.

---

## 4. Reproduction instructions

Each non-INFO finding has a 1-line Python repro. The minimized M1
artifact is in `benchmarks/adversarial/findings/M1_min/`.

```bash
# FIND-M1 (the only one needing a per-finding artifact dir):
python benchmarks/adversarial/findings/M1_min/repro_oneline.py
# → AttributeError: 'NoneType' object has no attribute 'replace'
#   (exit code 1)

# FIND-M2 / FIND-M3 / FIND-L1 / FIND-L2 / FIND-L3 (1-liners):
python -c 'import iban_pure; print(hasattr(iban_pure, "normalize"))'        # M2
python -c 'import inspect, iban_pure as ip; print(inspect.signature(ip.compute_check_digits))'  # M3
python -c 'import iban_pure as ip; assert ip.validate("DK5000400440116243")'  # L1
python -m iban_pure --help                                                  # L2
python -c 'import iban_pure as ip; print(repr(ip.format_display("DE89 3704 0044 0532 0130 00 garbage")))'  # L3

# Re-run the independent sweep that backs FIND-NONE:
python -c 'import random, string, iban_pure as ip; random.seed(424242); \
           [ip.validate("".join(random.choices(string.printable[:95], k=random.randint(0, 200)))) \
            for _ in range(50000)]; print("clean")'
```

---

## 5. Verdict recommendation for slot-05

**`VERDICT: SHIP`** — recommended.

Rationale:
- Zero actionable findings from the fuzz run (FIND-NONE is INFO only).
- The single code-relevant Medium (M1) is **audit-deferred** and
  slot-02/03 already classified it as R5 expected-divergent behavior.
  It is not a security issue (no host crash, no DoS, no data leak).
- The 2 process Mediums (M2, M3) are card-template drift, not code
  defects.
- The 3 Lows are non-functional (test fixture, docs drift, defensive).
- The 1.7M-iter fuzz run + 50k independent sweep confirm runtime
  stability on every public API surface.

A `VERDICT: REMEDIATE_REQUIRED` flip is defensible ONLY if the cycle
owner wants M1 fixed pre-ship. Nothing in the fuzz or audit evidence
supports that escalation — but it is a valid call, hence the
optionality surfaced in `triage_evidence.json#verdict_options`.

---

## 6. Cross-cycle carry-forward

Findings marked `carry_forward_to_cycle_68: true` in `findings.jsonl`:

- **FIND-M1** — defensive isinstance guard in compute_check_digits
- **FIND-M2** — card body template: remove `normalize` from
  iban-pure card bodies (cycle_52+ cycle_57+ cycle_67 all show this
  drift; suggests a permanent template fix)
- **FIND-M3** — card body template: fix compute_check_digits 1-arg
  signature in iban-pure card bodies (same pattern as M2)
- **FIND-L1** — replace DK test fixture with a canonical Danish IBAN
- **FIND-L2** — either remove README CLI examples or add __main__.py
- **FIND-L3** — defensive validate() gate inside format_display

The repo-factory orchestrator (next cycle) should pick these up in
the cycle_68 fix pass. None block the cycle_67 ship.

---

## 7. Audit trail

| Slot | Card | Commit | Artifact | Verdict |
|---|---|---|---|---|
| 01 | t_c076c878 | 22515d8 | `VULN_AUDIT.md` | CLEAN — SHIP (M1 deferred) |
| 02 | t_33b8de0b | db42335 | `harnesses/harness_*.py` (3 harnesses) | built |
| 03 | t_49c8b7f8 | 8b98434 | `corpus/`, `runs/`, `run_stats.json`, `findings.jsonl` (INFO only) | CLEAN — 0 crashes, 0 violations |
| 04 | **t_0476cddf** | (this commit) | `findings.jsonl` (7 entries), `findings/M1_min/`, `triage/triage_evidence.json`, this report | **SHIP — 0 new findings, 6 audit carry-forwards** |
| 05 | t_99c785a7 | (next) | `FUZZING_REPORT.md` (rolls up 01-04) | (slot-04 recommends SHIP) |

End of report.
