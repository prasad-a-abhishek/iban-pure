#!/usr/bin/env python3
"""run_corpus.py — execute the canonical seed corpus through validate() and record results.

This is the deterministic counterpart to the random-fuzz run: it walks the
EXPLICIT adversarial_strings.txt file, calls validate() / format_display() /
compute_check_digits() on each entry, and writes a per-input result table.

Purpose: prove the seed corpus is itself covered, not just used as a
generator pool. If any entry violates its expected_behavior tag, this
script exits non-zero — that's a real finding for slot 04 to triage.

Outputs:
    adversarial/runs/corpus_run_stats.json    — aggregate counts
    adversarial/runs/corpus/result.tsv        — one row per input
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from corpus import (  # noqa: E402
    corpus_metadata,
    load_adversarial_strings,
    load_bban_corpus,
    load_valid_ibans,
)
import iban_pure  # noqa: E402


_CORPUS_OUT = _HERE / "runs" / "corpus"
_CORPUS_OUT.mkdir(parents=True, exist_ok=True)


def _check_input(s: str, category: str, expected: str) -> Dict[str, object]:
    """Run all 3 public APIs against s; classify outcome."""
    out: Dict[str, object] = {
        "category": category,
        "expected_behavior": expected,
        "input_repr": repr(s),
        "input_len": len(s),
        "validate": None,
        "validate_raised": None,
        "format_display": None,
        "format_display_raised": None,
        "compute_check_digits": None,
        "compute_check_digits_raised": None,
        "violates_expected": False,
    }
    try:
        out["validate"] = iban_pure.validate(s)
    except BaseException as exc:  # noqa: BLE001
        out["validate_raised"] = f"{type(exc).__name__}: {exc}"
    try:
        out["format_display"] = iban_pure.format_display(s)
    except BaseException as exc:  # noqa: BLE001
        out["format_display_raised"] = f"{type(exc).__name__}: {exc}"
    try:
        out["compute_check_digits"] = iban_pure.compute_check_digits(s)
    except BaseException as exc:  # noqa: BLE001
        out["compute_check_digits_raised"] = f"{type(exc).__name__}: {exc}"

    # Check expected_behavior contract.
    if expected == "VALIDATE_FALSE":
        if out["validate_raised"] is not None:
            out["violates_expected"] = True
            out["violation_reason"] = f"validate raised {out['validate_raised']}; must return False"
        elif out["validate"] is not False:
            out["violates_expected"] = True
            out["violation_reason"] = f"validate returned {out['validate']!r}; must return False"
    elif expected == "FORMAT_OK":
        if out["format_display_raised"] is not None:
            out["violates_expected"] = True
            out["violation_reason"] = f"format_display raised {out['format_display_raised']}; must succeed"
    elif expected == "COMPUTE_RAISE":
        if out["compute_check_digits_raised"] is None:
            out["violates_expected"] = True
            out["violation_reason"] = "compute_check_digits did not raise; must raise ValueError"
    return out


def _check_valid_ibans() -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for ib in load_valid_ibans():
        rows.append({
            "category": "VALID_IBAN",
            "expected_behavior": "VALIDATE_TRUE",
            "input_repr": repr(ib),
            "input_len": len(ib),
            "validate": None,
            "validate_raised": None,
            "format_display": None,
            "format_display_raised": None,
            "compute_check_digits": None,
            "compute_check_digits_raised": None,
            "violates_expected": False,
        })
        try:
            rows[-1]["validate"] = iban_pure.validate(ib)
        except BaseException as exc:  # noqa: BLE001
            rows[-1]["validate_raised"] = f"{type(exc).__name__}: {exc}"
        try:
            rows[-1]["format_display"] = iban_pure.format_display(ib)
        except BaseException as exc:  # noqa: BLE001
            rows[-1]["format_display_raised"] = f"{type(exc).__name__}: {exc}"
        if rows[-1]["validate"] is not True:
            rows[-1]["violates_expected"] = True
            rows[-1]["violation_reason"] = f"validate returned {rows[-1]['validate']!r}; must return True"
    return rows


def _check_bban_corpus() -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for full, bban, expected_check in load_bban_corpus():
        out: Dict[str, object] = {
            "category": "BBAN_ROUNDTRIP",
            "expected_behavior": "ROUNDTRIP_OK",
            "input_repr": repr(bban),
            "input_len": len(bban),
            "compute_check_digits": None,
            "compute_check_digits_raised": None,
            "assembled_iban": None,
            "validate_assembled": None,
            "validate_assembled_raised": None,
            "validate_full_iban": None,
            "violates_expected": False,
        }
        try:
            out["compute_check_digits"] = iban_pure.compute_check_digits(bban)
        except BaseException as exc:  # noqa: BLE001
            out["compute_check_digits_raised"] = f"{type(exc).__name__}: {exc}"
        try:
            out["validate_full_iban"] = iban_pure.validate(full)
        except BaseException as exc:  # noqa: BLE001
            out["validate_full_iban"] = f"raised {type(exc).__name__}: {exc}"

        if out["compute_check_digits"] != expected_check:
            out["violates_expected"] = True
            out["violation_reason"] = (
                f"compute_check_digits={out['compute_check_digits']!r} "
                f"expected={expected_check!r}"
            )
        elif not out["validate_full_iban"]:
            out["violates_expected"] = True
            out["violation_reason"] = (
                f"validate(full_iban) returned {out['validate_full_iban']!r}; must return True"
            )
        else:
            # Assemble and validate.
            computed_check = out.get("compute_check_digits") or ""
            assembled = bban[:2] + str(computed_check) + bban[2:]
            out["assembled_iban"] = assembled
            try:
                out["validate_assembled"] = iban_pure.validate(assembled)
            except BaseException as exc:  # noqa: BLE001
                out["validate_assembled_raised"] = f"{type(exc).__name__}: {exc}"
            if out["validate_assembled"] is not True:
                out["violates_expected"] = True
                out["violation_reason"] = (
                    f"validate(assembled)={out['validate_assembled']!r}; must be True"
                )
        rows.append(out)
    return rows


def main() -> int:
    t0 = time.monotonic()
    started_at = _dt.datetime.now(_dt.timezone.utc)

    rows: List[Dict[str, object]] = []
    rows.extend(_check_valid_ibans())
    rows.extend(_check_bban_corpus())
    for s, cat, beh in load_adversarial_strings():
        rows.append(_check_input(s, cat, beh))

    elapsed = time.monotonic() - t0

    # Write per-input result table.
    tsv = _CORPUS_OUT / "result.tsv"
    with tsv.open("w", encoding="utf-8") as fh:
        fh.write(
            "category\texpected\tinput_repr\tinput_len\t"
            "validate\tvalidate_raised\tformat_display_raised\t"
            "compute_check_digits\tcompute_check_digits_raised\t"
            "assembled_iban\tvalidate_assembled\tviolates_expected\tviolation_reason\n"
        )
        for r in rows:
            fh.write("\t".join([
                str(r.get("category", "")),
                str(r.get("expected_behavior", "")),
                str(r.get("input_repr", "")),
                str(r.get("input_len", "")),
                str(r.get("validate", "")),
                str(r.get("validate_raised", "")),
                str(r.get("format_display_raised", "")),
                str(r.get("compute_check_digits", "")),
                str(r.get("compute_check_digits_raised", "")),
                str(r.get("assembled_iban", "")),
                str(r.get("validate_assembled", "")),
                str(r.get("violates_expected", "")),
                str(r.get("violation_reason", "")),
            ]) + "\n")

    # Aggregate.
    by_category: Dict[str, int] = {}
    violations: List[Dict[str, object]] = []
    for r in rows:
        cat = str(r.get("category", ""))
        by_category[cat] = by_category.get(cat, 0) + 1
        if r.get("violates_expected"):
            violations.append(r)

    summary = {
        "started_at": started_at.isoformat(),
        "ended_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 3),
        "total_rows": len(rows),
        "violations": len(violations),
        "by_category": dict(sorted(by_category.items())),
        "corpus_metadata": corpus_metadata(),
        "violation_details": violations,
    }
    out_json = _HERE / "runs" / "corpus_run_stats.json"
    out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[run_corpus] rows={len(rows)} violations={len(violations)} duration={elapsed:.2f}s", file=sys.stderr)
    print(f"[run_corpus] wrote {tsv}", file=sys.stderr)
    print(f"[run_corpus] wrote {out_json}", file=sys.stderr)

    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())