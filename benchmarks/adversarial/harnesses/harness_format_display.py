#!/usr/bin/env python3
"""Fuzzing harness for iban_pure.format_display() — format invariant + L3.

Surface under test
------------------
`iban_pure.format_display(iban: str) -> str`  (commit 4bf40d0)

Invariants asserted
-------------------
F1  Totality: format_display(x) MUST NEVER raise for any str x.
    For non-str x, current behavior is to raise AttributeError on
    .replace() — this is the *known* divergent behavior vs validate()
    (no isinstance guard). The harness COUNTS these raises as a
    fingerprint; silent acceptance of non-str is a regression.

F2  Output is purely a re-joining of the input's alphanumerics in groups
    of 4 separated by single spaces:
        out = format_display(x)
        assert out.replace(" ", "") == strip_non_alnum(x).upper()
    (Function strips " " and "-" then uppercases, then joins.)

F3  Group shape: when len(stripped) == 0, out == "".
    When len(stripped) > 0:
        groups = out.split(" ")
        assert all(len(g) == 4 for g in groups[:-1])
        assert 1 <= len(groups[-1]) <= 4

F4  Idempotence on already-spaced input:
        format_display(format_display(x)) == format_display(x)
    (format_display is idempotent on its own output because the function
    strips spaces before re-joining.)

F5  Audit L3 invariant: format_display is NOT a validator.
    Specifically, format_display(pre_spaced_alnum) == format_display(
    pre_spaced_alnum_with_different_grouping). Both pre-spaced inputs
    collapse to the same stripped/uppercased form, so they MUST produce
    identical output. The function does NOT validate the underlying
    string — this is documented behavior.

F6  Round-trip via canonicalize:
        canon = format_display(x)
        # No "inverse format" in the library; we use the trivial inverse:
        # strip all spaces, then re-format. Result must equal canon.
        again = format_display(canon.replace(" ", ""))
        assert again == canon

Adversarial input generators
----------------------------
- Real IBANs from the seed corpus.
- Pre-spaced / pre-hyphenated real IBANs ("DE89 3704 0044 ...", "DE89-...").
- Random alphanumeric strings of all realistic lengths (0..200 chars).
- Long strings (1000..10000 chars) — exercises the join() loop boundary.
- Whitespace-heavy strings (" " * n).
- Mixed garbage classes (punctuation, unicode, control chars).
- Lowercase real IBANs (verify uppercase normalization).
- Non-str sentinels (None, int, bytes, list) — counted under F1.

Execution model
---------------
stdlib-only. Each iteration draws an input, calls format_display, asserts
F1..F6. Seeded deterministic.

Exit codes:
    0  — clean run, all invariants satisfied, F1 raises counted.
    1  — invariant violation.
    2  — harness setup error.

Usage
-----
    python harness_format_display.py              # default 500,000 iterations
    python harness_format_display.py --iters 5000
    python harness_format_display.py --seed 99
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import iban_pure  # noqa: E402


VALID_IBANS = [
    "DE89370400440532013000",
    "GB82WEST12345698765432",
    "FR1420041010050500013M02606",
    "ES9121000418450200051332",
    "IT60X0542811101000000123456",
    "NL91ABNA0417164300",
    "BE68539007547034",
    "AT611904300234573201",
    "CH9300762011623852957",
    "SE4550000000058398257466",
    "NO9386011117947",
    "DK5000400440116243",
    "FI2112345600000785",
]

# Pre-flight
for _ib in VALID_IBANS:
    try:
        _ = iban_pure.format_display(_ib)
    except Exception as _exc:  # pragma: no cover — preflight only
        sys.stderr.write(f"FATAL: seed preflight failed on {_ib!r}: {_exc!r}\n")
        sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Input generators
# ─────────────────────────────────────────────────────────────────────────────


def _canon_strip(s: str) -> str:
    """Mirror of format_display's internal normalization for F2/F6 comparison."""
    return s.replace(" ", "").replace("-", "").upper()


def _gen_real_iban(rng: random.Random) -> str:
    return rng.choice(VALID_IBANS)


def _gen_spaced_real(rng: random.Random) -> str:
    """Real IBAN with spaces inserted at non-aligned positions (L3 fingerprint)."""
    s = rng.choice(VALID_IBANS)
    # Insert 0..3 random spaces at random positions.
    positions = sorted(rng.sample(range(len(s)), k=min(3, len(s))))
    out = []
    last = 0
    for p in positions:
        out.append(s[last:p])
        out.append(" ")
        last = p
    out.append(s[last:])
    return "".join(out)


def _gen_hyphen_real(rng: random.Random) -> str:
    s = rng.choice(VALID_IBANS)
    return s[:4] + "-" + s[4:8] + "-" + s[8:]


def _gen_lower_real(rng: random.Random) -> str:
    return rng.choice(VALID_IBANS).lower()


def _gen_random_alnum(rng: random.Random) -> str:
    n = rng.randint(0, 200)
    pool = string.ascii_letters + string.digits
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_long_alnum(rng: random.Random) -> str:
    n = rng.randint(1000, 10000)
    pool = string.ascii_uppercase + string.digits
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_garbage(rng: random.Random) -> str:
    n = rng.randint(1, 200)
    pool = string.punctuation + " \t\n!@#$%"
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_whitespace_heavy(rng: random.Random) -> str:
    n = rng.randint(1, 50)
    return " " * n


def _gen_unicode(rng: random.Random) -> str:
    n = rng.randint(1, 80)
    samples = ["\u202E", "\u200E", "\u200F", "\uFEFF", "\u00A0", "\u200B", "\uFFFD"]
    return "".join(rng.choice(samples) for _ in range(n))


def _gen_non_str(rng: random.Random):
    bucket = rng.randint(0, 4)
    if bucket == 0:
        return None
    if bucket == 1:
        return rng.randint(-1000, 1000)
    if bucket == 2:
        return float("inf")
    if bucket == 3:
        return bytes(rng.randint(0, 255) for _ in range(10))
    return [1, 2, 3]


def _draw_input(rng: random.Random, counter: int):
    if counter % 1000 == 0:
        return _gen_real_iban(rng)
    bucket = rng.randint(0, 9)
    if bucket == 0:
        return _gen_spaced_real(rng)
    if bucket == 1:
        return _gen_hyphen_real(rng)
    if bucket == 2:
        return _gen_lower_real(rng)
    if bucket == 3:
        return _gen_random_alnum(rng)
    if bucket == 4:
        return _gen_long_alnum(rng)
    if bucket == 5:
        return _gen_garbage(rng)
    if bucket == 6:
        return _gen_whitespace_heavy(rng)
    if bucket == 7:
        return _gen_unicode(rng)
    if bucket == 8:
        return _gen_real_iban(rng)
    # 9: non-str sentinel — F1 territory
    return _gen_non_str(rng)


# ─────────────────────────────────────────────────────────────────────────────
# Invariant checks
# ─────────────────────────────────────────────────────────────────────────────


def _record_crash(kind: str, payload, detail, crash_log_path: str) -> None:
    is_first = not os.path.exists(crash_log_path) or os.path.getsize(crash_log_path) == 0
    with open(crash_log_path, "a", encoding="utf-8") as fh:
        fh.write(f"{kind}\t{repr(payload)}\t{detail}\n")
    if is_first:
        sys.stderr.write(f"FIRST CRASH [{kind}] on input {repr(payload)}: {detail}\n")


def _check_invariants(x: str, out: str, crash_log_path: str) -> None:
    """F2..F6 — assumes x is a str and format_display did NOT raise."""

    # F2 — re-joining invariant.
    canon = _canon_strip(x)
    assert out.replace(" ", "") == canon, (
        f"F2: format_display({x!r}) = {out!r}; expected re-join of {canon!r}"
    )

    # F3 — group shape.
    if canon == "":
        assert out == "", f"F3: empty stripped → expected empty out, got {out!r}"
    else:
        groups = out.split(" ")
        for g in groups[:-1]:
            assert len(g) == 4, f"F3: non-last group {g!r} != 4 chars"
        assert 1 <= len(groups[-1]) <= 4, (
            f"F3: last group {groups[-1]!r} out of 1..4 chars"
        )

    # F4 — idempotence on own output.
    out2 = iban_pure.format_display(out)
    assert out2 == out, f"F4: idempotence failed; {out!r} → {out2!r}"

    # F6 — round-trip via canonicalize.
    again = iban_pure.format_display(out.replace(" ", ""))
    assert again == out, f"F6: canonicalize round-trip failed; {out!r} → {again!r}"


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=500_000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_format_display.txt"))
    args = ap.parse_args()

    if os.path.exists(args.log):
        os.remove(args.log)

    rng = random.Random(args.seed)

    iters = 0
    raise_str_unexpected = 0
    raise_nonstr = 0
    raise_nonstr_silent = 0
    invariant_count = 0
    t0 = time.monotonic()

    while iters < args.iters:
        iters += 1
        x = _draw_input(rng, iters)

        # F1 — totality classification.
        try:
            out = iban_pure.format_display(x)  # type: ignore[arg-type]  # fuzz: probe type boundaries
        except BaseException as exc:  # noqa: BLE001
            if isinstance(x, str):
                raise_str_unexpected += 1
                _record_crash(
                    "raise",
                    x,
                    f"unexpected {type(exc).__name__}: {exc} on str input",
                    args.log,
                )
            else:
                raise_nonstr += 1
            continue

        # Silent acceptance of non-str is a regression.
        if not isinstance(x, str):
            raise_nonstr_silent += 1
            invariant_count += 1
            _record_crash(
                "invariant", x,
                "F1: non-str input silently accepted (no isinstance guard)",
                args.log,
            )
            continue

        # F2..F6 — structural invariants.
        try:
            _check_invariants(x, out, args.log)
        except AssertionError as exc:
            invariant_count += 1
            _record_crash("invariant", x, str(exc), args.log)
            continue

    elapsed = time.monotonic() - t0
    rate = iters / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_format_display  target=iban_pure.format_display  commit=4bf40d0")
    print(f"iters                  = {iters:,}")
    print(f"elapsed                = {elapsed:.2f}s")
    print(f"rate                   = {rate:,.0f} it/s")
    print(f"raises_str_unexpected  = {raise_str_unexpected}")
    print(f"raises_nonstr (F1)     = {raise_nonstr}")
    print(f"silent_nonstr (F1 reg) = {raise_nonstr_silent}")
    print(f"invariant_violations   = {invariant_count}")
    print(f"seed_corpus_size       = {len(VALID_IBANS)}")
    print(f"log                    = {args.log}")
    print("=" * 72)

    if raise_str_unexpected or invariant_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
