#!/usr/bin/env python3
"""run_fuzz.py — execute all 3 harnesses + emit per-harness run_stats.json.

Runs each harness with its canonical iteration count, captures stdout
+ stderr + exit code, and writes a run_stats.json with:
  - harness: harness_*.py filename
  - target: iban_pure function under test
  - command: exact CLI invocation (for reproduction)
  - iters_requested: --iters value
  - iters_completed: actual iters executed (from stdout)
  - elapsed_seconds: from stdout
  - rate_it_per_sec: from stdout
  - raise counts (per harness's accounting buckets)
  - invariant_violations
  - crash_log_path: relative path to crash log
  - crash_log_first_line: first line of crash log (None if empty)
  - crash_log_size_bytes
  - exit_code
  - started_at (ISO)
  - ended_at (ISO)
  - duration_seconds
  - seed: RNG seed used

Usage:
    python run_fuzz.py                    # default iters per harness
    python run_fuzz.py --quick            # 100k each
    python run_fuzz.py --iters-validate N --iters-roundtrip N --iters-format-display N

The script is deterministic given --seed. Run it once, commit the output.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

_HERE = Path(__file__).resolve().parent
_HARNESS_DIR = _HERE / "harnesses"
_RUNS_DIR = _HERE / "runs"
_REPO_ROOT = _HERE.parent.parent


# Default iteration counts (matches each harness's argparse default).
DEFAULT_ITERS = {
    "validate": 1_000_000,
    "roundtrip": 200_000,
    "format_display": 500_000,
}
QUICK_ITERS = {
    "validate": 100_000,
    "roundtrip": 100_000,
    "format_display": 100_000,
}


def _parse_harness_output(stdout: str) -> Dict[str, object]:
    """Parse the harness stdout into a structured stats dict.

    Each harness prints a 72-char '=' banner followed by key=value lines,
    then a closing 72-char '=' banner. This parses the key=value lines.
    """
    stats: Dict[str, object] = {}
    # Key = Value  (with optional whitespace and unit suffix in parens)
    # Some lines have the format  key  =  value  (unit)  — we strip the (unit).
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        m = re.match(r"\s*(\w+)\s*=\s*(.+?)\s*(?:\([^)]+\))?\s*$", line)
        if not m:
            continue
        key, raw = m.group(1), m.group(2)
        # Parse the value: int, float, or string.
        v = raw.strip().rstrip(",")
        # Strip thousands separators
        v_nocomma = v.replace(",", "")
        try:
            if "." in v_nocomma and v_nocomma.replace("-", "").replace(".", "").isdigit():
                stats[key] = float(v_nocomma)
            else:
                stats[key] = int(v_nocomma)
        except ValueError:
            stats[key] = v
    return stats


def _run_one(
    harness_name: str,
    iters: int,
    seed: int,
    out_dir: Path,
) -> Dict[str, object]:
    """Execute one harness; return a stats dict ready for run_stats.json."""
    script = _HARNESS_DIR / f"harness_{harness_name}.py"
    if not script.exists():
        return {
            "harness": script.name,
            "error": "harness file not found",
            "exit_code": -1,
        }

    out_dir.mkdir(parents=True, exist_ok=True)
    crash_log = _HARNESS_DIR / f"crash_log_{harness_name}.txt"
    # We let the harness write its own log; copy to runs dir afterward.
    log_copy = out_dir / "crash_log.txt"

    cmd = [
        sys.executable,
        str(script),
        "--iters", str(iters),
        "--seed", str(seed),
        "--log", str(crash_log),
    ]

    started_at = _dt.datetime.now(_dt.timezone.utc)
    t0 = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=2400,  # 40 min hard cap per harness
        check=False,
    )
    elapsed = time.monotonic() - t0
    ended_at = _dt.datetime.now(_dt.timezone.utc)

    # Move crash log into runs/<harness>/ for commit.
    if crash_log.exists():
        log_copy.write_bytes(crash_log.read_bytes())
        crash_log_size = log_copy.stat().st_size
        first_line = log_copy.read_text(encoding="utf-8").splitlines()[0] if crash_log_size > 0 else None
    else:
        log_copy.write_text("")
        crash_log_size = 0
        first_line = None

    parsed = _parse_harness_output(proc.stdout)

    return {
        "harness": script.name,
        "target": {
            "validate": "iban_pure.validate",
            "roundtrip": "iban_pure.compute_check_digits",
            "format_display": "iban_pure.format_display",
        }[harness_name],
        "command": cmd,
        "command_str": " ".join(cmd),
        "iters_requested": iters,
        "seed": seed,
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_seconds": round(elapsed, 3),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout.splitlines()[-30:],
        "stderr_tail": proc.stderr.splitlines()[-10:] if proc.stderr else [],
        "parsed_stats": parsed,
        "crash_log_path": str(log_copy.relative_to(_HERE.parent)),
        "crash_log_size_bytes": crash_log_size,
        "crash_log_first_line": first_line,
        "clean_run": (
            proc.returncode == 0
            and crash_log_size == 0
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20260913, help="RNG seed")
    ap.add_argument("--quick", action="store_true", help="100k iters per harness")
    ap.add_argument("--iters-validate", type=int, default=None)
    ap.add_argument("--iters-roundtrip", type=int, default=None)
    ap.add_argument("--iters-format-display", type=int, default=None)
    args = ap.parse_args()

    if args.quick:
        iters = QUICK_ITERS
    else:
        iters = dict(DEFAULT_ITERS)
        if args.iters_validate is not None:
            iters["validate"] = args.iters_validate
        if args.iters_roundtrip is not None:
            iters["roundtrip"] = args.iters_roundtrip
        if args.iters_format_display is not None:
            iters["format_display"] = args.iters_format_display

    all_stats: List[Dict[str, object]] = []
    overall_t0 = time.monotonic()
    for harness_name in ["validate", "roundtrip", "format_display"]:
        out_dir = _RUNS_DIR / harness_name
        print(f"[run_fuzz] starting {harness_name} iters={iters[harness_name]:,}", file=sys.stderr)
        sys.stderr.flush()
        s = _run_one(harness_name, iters[harness_name], args.seed, out_dir)
        all_stats.append(s)
        print(
            f"[run_fuzz] {harness_name} done: exit={s['exit_code']} "
            f"duration={s.get('duration_seconds', '?')}s "
            f"clean={s.get('clean_run', False)}",
            file=sys.stderr,
        )
        sys.stderr.flush()
    overall_elapsed = time.monotonic() - overall_t0

    # Aggregate summary.
    total_iters = 0
    total_inv_viols = 0
    total_clean = True
    for s in all_stats:
        ps_dict: Dict[str, object] = {}
        raw_ps = s.get("parsed_stats", {})
        if isinstance(raw_ps, dict):
            ps_dict = raw_ps
        # Pull invariant_viols out of each harness's bucket name.
        for k, v in ps_dict.items():
            if "invariant" in k and isinstance(v, (int, float)):
                total_inv_viols += int(v)
        # Sum iters.
        iters_done = ps_dict.get("iters", 0)
        if isinstance(iters_done, (int, float)):
            total_iters += int(iters_done)
        if not s.get("clean_run", False):
            total_clean = False

    summary = {
        "started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "duration_seconds": round(overall_elapsed, 3),
        "seed": args.seed,
        "total_iters": int(total_iters) if isinstance(total_iters, (int, float)) else 0,
        "total_invariant_violations": total_inv_viols,
        "all_clean": total_clean,
        "harness_results": all_stats,
    }

    out = _HERE / "run_stats.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[run_fuzz] wrote {out}", file=sys.stderr)
    print(f"[run_fuzz] all_clean={total_clean} total_iters={summary['total_iters']:,} inv_viols={total_inv_viols}", file=sys.stderr)
    return 0 if total_clean else 1


if __name__ == "__main__":
    sys.exit(main())