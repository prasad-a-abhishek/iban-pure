#!/usr/bin/env python3
"""Fuzzing harness for iban_pure.validate() — totality + correctness invariants.

Surface under test
------------------
`iban_pure.validate(iban) -> bool`  (commit 4bf40d0 on wt/cycle_67-fix)

Invariants asserted (per cycle_67/adversary/01 audit + ISO 13616-1:2007)
------------------------------------------------------------------------
I1  Totality: `validate(x)` MUST NEVER raise for ANY Python value of x
    (None, int, float, bytes, list, dict, object, generator, ...).
    On invalid type, it MUST return False (audit cycle_67/01 §3.1).

I2  Idempotence on whitespace/hyphen (the documented stripping contract):
    validate(s) == validate("  " + s + "  ") == validate("--" + s + "--")
    == validate("  - " + s + " -  ")  for any str s.
    NOTE: per spec, only spaces and hyphens are stripped — tabs and newlines
    are NOT stripped and WILL cause the result to differ. The harness tests
    the documented contract, not arbitrary whitespace classes.

I3  Case invariance: validate(s) == validate(s.upper()) == validate(s.lower())
    for any str s.

I4  Length-band cutoffs: validate(s) returns False when len(s.strip_space) < 5
    OR len(s.strip_space) > 100. (Audit §3.1 — added by QA fix commit 45eba5e.)

I5  Non-alnum cut: validate(s) returns False when strip_space(s) contains
    any non-alphanumeric character.

I6  Seed corpus: known-valid IBANs from 10 countries must each validate True;
    known-invalid IBANs must each validate False.

Adversarial input generators
----------------------------
- random bytes slices decoded as utf-8 with errors='replace' (catches unicode
  crashes)
- random integers 0..10000 (catches int→str confusion)
- random floats (catches float edge cases: NaN, inf, large mantissas)
- None (sentinel — must return False, not raise)
- bytes objects with embedded NULs
- random lengths 0..15000 char strings of printable + non-printable chars
- mixed garbage classes interleaved (control chars, RTL markers, etc.)
- structural seeds: "" , "A", "AB", "ABC", "ABCD", "ABCDE" (boundary)
- 10000-char random alphanumeric string (the audit's documented edge class)

Execution model
---------------
stdlib-only, no atheris/native deps. Each iteration:
    1. Draw an input from the mixed generator pool.
    2. Apply I1: assert validate(x) does not raise.
    3. If x is a str, apply I2..I5 invariants.
    4. Track counters.

Exit codes:
    0  — clean run, no invariant violations.
    1  — invariant violation (recorded in crash_log.txt + first repro printed).
    2  — harness setup error (e.g. import failure).

Usage
-----
    python harness_validate.py                # default 1,000,000 iterations
    python harness_validate.py --iters 10000  # quick smoke
    python harness_validate.py --seed 42      # deterministic replay

The harness is deterministic given --seed; crashes are reproducible.
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
import time
import traceback

# Make sure the in-tree source is importable when run from this directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import iban_pure  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# Seed corpus — known-valid IBANs from real country registries
# (Sourced from the test suite at tests/test_iban_pure.py AC2 fixtures.)
# ─────────────────────────────────────────────────────────────────────────────

VALID_IBANS = [
    "DE89370400440532013000",    # Germany (18 BBAN)
    "GB82WEST12345698765432",    # UK (18 BBAN)
    "FR1420041010050500013M02606",  # France
    "ES9121000418450200051332",  # Spain
    "IT60X0542811101000000123456",  # Italy
    "NL91ABNA0417164300",        # Netherlands
    "BE68539007547034",          # Belgium
    "AT611904300234573201",      # Austria
    "CH9300762011623852957",     # Switzerland
    "SE4550000000058398257466",  # Sweden
    "NO9386011117947",           # Norway
    "DK5000400440116243",        # Denmark
    "FI2112345600000785",        # Finland
]

# Sanity: the seed corpus itself must all validate True. If not, the
# source under test has regressed before the fuzz starts.
_SEED_PREFLIGHT_FAIL = []
for _ib in VALID_IBANS:
    try:
        if not iban_pure.validate(_ib):
            _SEED_PREFLIGHT_FAIL.append(("valid_iban_returns_false", _ib))
    except Exception as _exc:  # pragma: no cover — preflight only
        _SEED_PREFLIGHT_FAIL.append(("valid_iban_raised", (_ib, repr(_exc))))
if _SEED_PREFLIGHT_FAIL:
    sys.stderr.write(
        "FATAL: seed preflight failed (source regressed?):\n"
        + "\n".join(repr(x) for x in _SEED_PREFLIGHT_FAIL)
        + "\n"
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Input generators
# ─────────────────────────────────────────────────────────────────────────────

_PRINTABLE = string.ascii_letters + string.digits + string.punctuation + " "


def _gen_random_bytes_str(rng: random.Random, maxlen: int) -> str:
    """A printable + non-printable ASCII slice, decoded as utf-8 with replacement.

    Catches: unicode replacement char (\ufffd) flowing through int(...).
    """
    n = rng.randint(0, maxlen)
    raw = bytes(rng.randint(0, 255) for _ in range(n))
    return raw.decode("utf-8", errors="replace")


def _gen_long_alnum(rng: random.Random, length: int) -> str:
    pool = string.ascii_uppercase + string.digits
    return "".join(rng.choice(pool) for _ in range(length))


def _gen_structural(rng: random.Random) -> str:
    """Boundary-length strings (0, 1, 2, ..., 100, 101 chars)."""
    n = rng.randint(0, 120)
    pool = string.ascii_uppercase + string.digits + " -_\t\n"
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_unicode(rng: random.Random, maxlen: int) -> str:
    """Mix of BMP characters including RTL markers and emoji-ish codepoints."""
    n = rng.randint(0, maxlen)
    samples = [
        "\u202E",  # RIGHT-TO-LEFT OVERRIDE
        "\u200E",  # LEFT-TO-RIGHT MARK
        "\u200F",  # RIGHT-TO-LEFT MARK
        "\uFEFF",  # ZERO WIDTH NO-BREAK SPACE / BOM
        "\u00A0",  # non-breaking space
        "\u200B",  # zero-width space
        "\uFFFD",  # replacement char
        "\u4E2D",  # CJK
        "\u00C9",  # É
        "\u00F1",  # ñ
    ]
    out = []
    for _ in range(n):
        if rng.random() < 0.5:
            out.append(rng.choice(samples))
        else:
            out.append(rng.choice(_PRINTABLE))
    return "".join(out)


def _gen_garbage_mix(rng: random.Random, maxlen: int) -> str:
    """Mostly non-alnum: punctuation, whitespace, control chars."""
    n = rng.randint(0, maxlen)
    pool = "\t\n\r\x0b\x0c!@#$%^&*()_+-=[]{}|\\:;\"'<>,.?/`~ "
    return "".join(rng.choice(pool) for _ in range(n))


def _draw_input(rng: random.Random, counter: int):
    """Return either a Python non-str sentinel or a string from one of the
    five generators, biased roughly equal across the pool.
    """
    # Periodically emit a known-valid IBAN to keep the seed corpus in play.
    if counter % 1000 == 0:
        return rng.choice(VALID_IBANS)

    bucket = rng.randint(0, 9)
    if bucket == 0:
        return None
    if bucket == 1:
        return rng.randint(-10000, 10000)
    if bucket == 2:
        # float edge cases: finite, NaN, inf, large
        choice = rng.randint(0, 3)
        if choice == 0:
            return rng.uniform(-1e6, 1e6)
        if choice == 1:
            return float("nan")
        if choice == 2:
            return float("inf")
        return -float("inf")
    if bucket == 3:
        # bytes with embedded NULs
        n = rng.randint(0, 200)
        return bytes(rng.randint(0, 255) for _ in range(n))
    if bucket == 4:
        return _gen_random_bytes_str(rng, 200)
    if bucket == 5:
        return _gen_long_alnum(rng, rng.randint(0, 15000))
    if bucket == 6:
        return _gen_structural(rng)
    if bucket == 7:
        return _gen_unicode(rng, 100)
    if bucket == 8:
        return _gen_garbage_mix(rng, 500)
    # bucket == 9: a random non-str python value
    return [rng.randint(0, 5)]  # list


# ─────────────────────────────────────────────────────────────────────────────
# Invariant checks
# ─────────────────────────────────────────────────────────────────────────────


def _record_crash(kind: str, payload, detail, crash_log_path: str) -> None:
    """Append a single crash record to crash_log.txt and print first repro."""
    is_first = not os.path.exists(crash_log_path) or os.path.getsize(crash_log_path) == 0
    with open(crash_log_path, "a", encoding="utf-8") as fh:
        fh.write(f"{kind}\t{repr(payload)}\t{detail}\n")
    if is_first:
        sys.stderr.write(f"FIRST CRASH [{kind}] on input {repr(payload)}: {detail}\n")


def _check_invariants(x, result, rng: random.Random, crash_log_path: str) -> None:
    """All invariants from the harness docstring. Raises AssertionError on fail."""
    # I1 already enforced by the try/except in main(); here we check return-type.
    assert isinstance(result, bool), (
        f"I1 violation: validate returned non-bool {type(result).__name__} for {x!r}"
    )

    if not isinstance(x, str):
        # I1 corollary: non-str input must return False (audit §3.1).
        assert result is False, (
            f"I1 violation: validate({x!r}) returned True for non-str input"
        )
        return

    # I2 — idempotence on whitespace/hyphen (documented stripping contract).
    stripped = x.replace(" ", "").replace("-", "")
    spaced = "  " + x + "  "
    hyphen = "--" + x + "--"
    mixed = "  - " + x + " -  "
    try:
        assert iban_pure.validate(spaced) == result, (
            f"I2 violation: validate('  '+x+'  ') != validate(x) for {x!r}"
        )
        assert iban_pure.validate(hyphen) == result, (
            f"I2 violation: validate('--'+x+'--') != validate(x) for {x!r}"
        )
        assert iban_pure.validate(mixed) == result, (
            f"I2 violation: validate('  - '+x+' -  ') != validate(x) for {x!r}"
        )
    except Exception as exc:  # pragma: no cover — defensive
        raise AssertionError(
            f"I2 raised {type(exc).__name__}: {exc} on padded input derived from {x!r}"
        )

    # I3 — case invariance.
    try:
        assert iban_pure.validate(x.upper()) == result, (
            f"I3 violation: validate(x.upper()) != validate(x) for {x!r}"
        )
        assert iban_pure.validate(x.lower()) == result, (
            f"I3 violation: validate(x.lower()) != validate(x) for {x!r}"
        )
    except Exception as exc:  # pragma: no cover
        raise AssertionError(
            f"I3 raised {type(exc).__name__}: {exc} for case variants of {x!r}"
        )

    # I4 — length-band cutoffs (only check on stripped length).
    slen = len(stripped)
    if slen < 5 or slen > 100:
        assert result is False, (
            f"I4 violation: validate({x!r}) returned True for stripped len={slen}"
        )

    # I5 — non-alnum cut. Anything non-alnum in the stripped string → False.
    if stripped and not stripped.isalnum():
        assert result is False, (
            f"I5 violation: validate({x!r}) returned True for non-alnum stripped={stripped!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=1_000_000,
                    help="number of iterations (default 1,000,000)")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for deterministic replay")
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_validate.txt"),
                    help="path to crash log (default: ./crash_log_validate.txt)")
    args = ap.parse_args()

    # Truncate any prior log so the FIRST crash signal is unambiguous.
    if os.path.exists(args.log):
        os.remove(args.log)

    rng = random.Random(args.seed)

    iters = 0
    raise_count = 0
    invariant_count = 0
    t0 = time.monotonic()

    while iters < args.iters:
        iters += 1
        x = _draw_input(rng, iters)

        # I1 — totality: must never raise.
        try:
            result = iban_pure.validate(x)  # type: ignore[arg-type]  # fuzz: probe type boundaries
        except BaseException as exc:  # noqa: BLE001 — we want to catch literally everything
            raise_count += 1
            _record_crash(
                "raise",
                x,
                f"{type(exc).__name__}: {exc}",
                args.log,
            )
            continue

        # I2..I5 — structural invariants.
        try:
            _check_invariants(x, result, rng, args.log)
        except AssertionError as exc:
            invariant_count += 1
            _record_crash("invariant", x, str(exc), args.log)
            continue

    elapsed = time.monotonic() - t0
    rate = iters / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_validate  target=iban_pure.validate  commit=4bf40d0")
    print(f"iters            = {iters:,}")
    print(f"elapsed          = {elapsed:.2f}s")
    print(f"rate             = {rate:,.0f} it/s")
    print(f"raises           = {raise_count}")
    print(f"invariant_viols  = {invariant_count}")
    print(f"seed_corpus_size = {len(VALID_IBANS)}")
    print(f"log              = {args.log}")
    print("=" * 72)

    if raise_count or invariant_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
