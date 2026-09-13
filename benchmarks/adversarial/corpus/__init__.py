"""Canonical corpus loader for the cycle_67 iban-pure adversarial workstream.

This module is the single source of truth for the seed corpus used by all
three harnesses. The harnesses ALSO have inline VALID_IBANS lists as
fallback (for crash recovery + backward compat) but the canonical seed set
lives here.

Public API
----------
load_valid_ibans() -> list[str]
    13 real-world IBANs from DE/GB/FR/ES/IT/NL/BE/AT/CH/SE/NO/DK/FI.
    MUST round-trip through iban_pure.validate() → True.

load_bban_corpus() -> list[tuple[str, str, str]]
    (full_iban, bban_no_check, expected_check_digits) for each entry above.
    For harness_roundtrip.py's R6 cross-check.

load_adversarial_strings() -> list[tuple[str, str, str]]
    (repr_decoded_string, category, expected_behavior_tag) — the hand-picked
    adversarial set from VULN_AUDIT.md §3.1-3.3 edge cases.

corpus_metadata() -> dict
    Hash + row counts + provenance info for the run_stats.json audit trail.
"""
from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Tuple

_HERE = Path(__file__).resolve().parent
_VALID_IBANS_PATH = _HERE / "valid_ibans.txt"
_BBAN_CORPUS_PATH = _HERE / "bban_corpus.tsv"
_ADVERSARIAL_STRINGS_PATH = _HERE / "adversarial_strings.txt"


def _strip_comment(line: str) -> str:
    """Drop trailing '# ...' annotation. Keeps '#' inside string reprs safe
    because we only split on the first '#' that's NOT inside a quote."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def load_valid_ibans() -> List[str]:
    """Return the 13 canonical IBANs as a list of strings.

    Reads corpus/valid_ibans.txt and ignores lines starting with '#' or
    that are empty after stripping the trailing annotation comment.
    """
    out: List[str] = []
    for raw in _VALID_IBANS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Split on whitespace; first token is the IBAN.
        first = line.split()[0]
        if first and first.isascii():
            out.append(first)
    return out


def load_bban_corpus() -> List[Tuple[str, str, str]]:
    """Return list of (full_iban, bban_no_check, expected_check_digits)."""
    out: List[Tuple[str, str, str]] = []
    for raw in _BBAN_CORPUS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        full, bban, expected = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if full and bban and expected:
            out.append((full, bban, expected))
    return out


def load_adversarial_strings() -> List[Tuple[str, str, str]]:
    """Return list of (string, category, expected_behavior_tag).

    Each input line is:  repr|category|expected_behavior
    Fields are separated by literal '|' characters (NOT tabs — tabs would
    collide with the escape sequences inside the string reprs).
    The repr is decoded with ast.literal_eval so escape sequences in the
    file (\\t, \\u202E, etc.) become actual chars in the loaded string.
    """
    out: List[Tuple[str, str, str]] = []
    for raw in _ADVERSARIAL_STRINGS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 3:
            continue
        try:
            decoded = ast.literal_eval(parts[0].strip())
        except (ValueError, SyntaxError):
            continue
        if not isinstance(decoded, str):
            continue
        out.append((decoded, parts[1].strip(), parts[2].strip()))
    return out


def corpus_metadata() -> Dict[str, object]:
    """Return provenance info: file hashes, row counts, source files."""
    valid = load_valid_ibans()
    bban = load_bban_corpus()
    adv = load_adversarial_strings()
    return {
        "valid_ibans_count": len(valid),
        "valid_ibans": valid,
        "bban_corpus_count": len(bban),
        "bban_corpus": [list(t) for t in bban],
        "adversarial_strings_count": len(adv),
        "adversarial_categories": sorted({c for _, c, _ in adv}),
        "adversarial_expected_behaviors": sorted({b for _, _, b in adv}),
        "files": {
            "valid_ibans": str(_VALID_IBANS_PATH),
            "valid_ibans_sha256": _file_sha256(_VALID_IBANS_PATH),
            "bban_corpus": str(_BBAN_CORPUS_PATH),
            "bban_corpus_sha256": _file_sha256(_BBAN_CORPUS_PATH),
            "adversarial_strings": str(_ADVERSARIAL_STRINGS_PATH),
            "adversarial_strings_sha256": _file_sha256(_ADVERSARIAL_STRINGS_PATH),
        },
    }


if __name__ == "__main__":
    import json
    import sys

    md = corpus_metadata()
    print(json.dumps(md, indent=2, ensure_ascii=False))
    sys.exit(0)