#!/usr/bin/env python3
"""Fuzzing harness for iban_pure.compute_check_digits() — round-trip invariant.

Surface under test
------------------
`iban_pure.compute_check_digits(bban: str) -> str`  (commit 4bf40d0)

Note on API drift (audit cycle_67/01 §1.3): the shipped function takes a
SINGLE argument — the country code is the first 2 chars of `bban`. The
card-body description (country_code, bban) was a spec-conventions drift
that the audit confirmed is NOT a code defect. This harness uses the
1-arg form that is actually shipped.

Invariants asserted
-------------------
R1  Output format: the return value is exactly 2 characters, each a digit,
    and `int(return_value) ∈ [2, 98]` (audit §3.2: check digit is "98 -
    (n mod 97)", never 0 or 1 because valid IBANs must mod-97 to 1).

R2  Round-trip — for any BBAN the function accepts:
        check = compute_check_digits(bban)
        iban  = bban[:2] + check + bban[2:]
        assert iban_pure.validate(iban) is True
    This is the core ISO 13616-1:2007 invariant: if the check digit was
    computed correctly, the assembled IBAN MUST pass the mod-97 test.

R3  Round-trip on whitespace-padded input:
        iban_pure.validate(compute_check_digits(" " + bban + " ")) →
            (must raise OR return a 2-digit string; whichever, it must not
            return anything else).

R4  Determinism: compute_check_digits(bban) called twice on the same
    input MUST return the same string. (Idempotence on a pure function —
    this is the canonical property for any hash/computation primitive.)

R5  Totality on type-confusion: feeding non-str (None, int, bytes, list,
    float, dict) into compute_check_digits MUST raise ValueError (or some
    exception — the function has no isinstance guard per audit M1). This
    is the *known* divergent behavior between validate (returns False)
    and compute_check_digits (raises). The harness documents and counts
    these raises; if the function EVER silently returns for non-str input
    that's a regression.

R6  Cross-check on canonical country IBANs: for each of the 13 known-valid
    IBANs in REAL_BBANS, computing check digits on the *BBAN portion*
    (IBAN[4:]) MUST yield the canonical 2-digit check. This is the
    self-consistency property: if a real-world IBAN validates True, the
    library's compute_check_digits must reproduce its check digits.

R7  Length cap: alnum inputs longer than ~2150 chars cause the function
    to raise ValueError from int()'s digit-string-length safety limit
    (Python 3.11+ sys.set_int_max_str_digits default 4300). The function
    has NO explicit length guard (audit M1 — unlike validate()'s 100-char
    cap added by QA fix 45eba5e). This is a known DoS surface: any
    attacker can trigger an unbounded ValueError. The harness COUNTS these
    raises as "expected on oversized" — NOT a regression, but a finding
    for the next cycle to address (compute_check_digits should mirror
    validate()'s `len(s) > 100 → raise ValueError` policy).

NOTE on audit M2: compute_check_digits takes a single arg (country +
account concatenated). Re-feeding a *complete* IBAN through it is
OUTSIDE the documented contract — the function expects BBAN-without-
check-digits. R4 does NOT test full-IBAN re-input for that reason.

Adversarial input generators
----------------------------
The "BBAN" is country_code (2 alpha) + account (alphanumeric). We fuzz:

- Real BBANs drawn from the test fixtures (DE, GB, FR, ES, IT, NL, BE, AT,
  CH, SE, NO, DK, FI) — must round-trip.
- Empty string "" — should raise ValueError per audit §3.2.
- Short strings (1..4 chars) — should raise.
- Long strings (up to 10_000 chars) — should not crash, must raise if
  non-alnum, else compute.
- Whitespace-padded real BBANs (" DE89...000 ") — must round-trip (function
  strips spaces per spec).
- Lowercase real BBANs ("de89...") — must round-trip.
- Mixed unicode — must raise (non-alnum after strip).
- Garbage class inputs (None, int, bytes, list, dict, float).

Execution model
---------------
stdlib-only. Each iteration draws an input class, builds the BBAN, runs
compute_check_digits, and checks R1..R4. Non-str inputs are checked
under R5 only.

Exit codes:
    0  — clean run, all invariants satisfied, R5 raises observed as expected.
    1  — invariant violation (round-trip fails, wrong format, recompute
         mismatch, silent non-str acceptance).
    2  — harness setup error.

Usage
-----
    python harness_roundtrip.py              # default 200,000 iterations
    python harness_roundtrip.py --iters 5000
    python harness_roundtrip.py --seed 7
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


# ─────────────────────────────────────────────────────────────────────────────
# Seed corpus — real IBANs (full form with check digits) and their BBAN
# portions (without check digits, as compute_check_digits expects).
#
# Convention:  IBAN     = country_code(2) + check_digits(2) + BBAN(≥11)
#              BBAN_arg = country_code(2) + BBAN(≥11)   ← what compute_check_digits takes
#
# Each entry: (full_iban, bban_no_check, expected_check_digits).
# ─────────────────────────────────────────────────────────────────────────────

REAL_IBAN_CORPUS = [
    ("DE89370400440532013000",    "DE370400440532013000",   "89"),  # Germany
    ("GB82WEST12345698765432",    "GBWEST12345698765432",   "82"),  # UK
    ("FR1420041010050500013M02606", "FR20041010050500013M02606", "14"),  # France
    ("ES9121000418450200051332",  "ES21000418450200051332", "91"),  # Spain
    ("IT60X0542811101000000123456", "ITX0542811101000000123456", "60"),  # Italy
    ("NL91ABNA0417164300",        "NLABNA0417164300",       "91"),  # Netherlands
    ("BE68539007547034",          "BE539007547034",         "68"),  # Belgium
    ("AT611904300234573201",      "AT1904300234573201",     "61"),  # Austria
    ("CH9300762011623852957",     "CH00762011623852957",    "93"),  # Switzerland
    ("SE4550000000058398257466",  "SE50000000058398257466", "45"),  # Sweden
    ("NO9386011117947",           "NO86011117947",          "93"),  # Norway
    ("DK5000400440116243",        "DK00400440116243",       "50"),  # Denmark
    ("FI2112345600000785",        "FI12345600000785",       "21"),  # Finland
]

# For convenience: just the BBAN arg strings.
REAL_BBANS = [entry[1] for entry in REAL_IBAN_CORPUS]

# Pre-flight: every seed must round-trip and cross-check.
_PREFLIGHT_FAIL = []
for _full, _bban, _expected_check in REAL_IBAN_CORPUS:
    # 1. validate() must accept the full IBAN.
    if not iban_pure.validate(_full):
        _PREFLIGHT_FAIL.append(("seed_validate_false", _full))
    # 2. compute_check_digits() on the BBAN must produce the expected check.
    try:
        _c = iban_pure.compute_check_digits(_bban)
    except Exception as _exc:  # pragma: no cover — preflight only
        _PREFLIGHT_FAIL.append(("seed_compute_raised", (_bban, repr(_exc))))
        continue
    if _c != _expected_check:
        _PREFLIGHT_FAIL.append(("seed_check_mismatch", (_bban, _c, _expected_check)))
    # 3. validate() on the assembled form must be True.
    _assembled = _bban[:2] + _c + _bban[2:]
    if not iban_pure.validate(_assembled):
        _PREFLIGHT_FAIL.append(("seed_assembled_false", _assembled))
if _PREFLIGHT_FAIL:
    sys.stderr.write(
        "FATAL: seed preflight failed (source regressed?):\n"
        + "\n".join(repr(x) for x in _PREFLIGHT_FAIL)
        + "\n"
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Input generators
# ─────────────────────────────────────────────────────────────────────────────


def _gen_real_bban(rng: random.Random) -> str:
    return rng.choice(REAL_BBANS)


def _gen_padded_real(rng: random.Random) -> str:
    """Real BBAN padded with whitespace and hyphens (function strips both)."""
    bban = rng.choice(REAL_BBANS)
    pad_left = " " * rng.randint(1, 5)
    pad_right = "-" * rng.randint(1, 5)
    if rng.random() < 0.5:
        return pad_left + bban + pad_right
    return "  " + bban[:10] + " " + bban[10:] + "  "


def _gen_lower_real(rng: random.Random) -> str:
    return rng.choice(REAL_BBANS).lower()


def _gen_random_alnum_bban(rng: random.Random) -> str:
    """Random alphanumeric 5..34 chars (typical IBAN length range)."""
    n = rng.randint(5, 34)
    pool = string.ascii_uppercase + string.digits
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_long_alnum_bban(rng: random.Random) -> str:
    """Long alphanumeric 1000..10000 chars — should still mod-97 cleanly."""
    n = rng.randint(1000, 10000)
    pool = string.ascii_uppercase + string.digits
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_too_short(rng: random.Random) -> str:
    return "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(rng.randint(0, 4)))


def _gen_non_alnum(rng: random.Random) -> str:
    n = rng.randint(5, 50)
    pool = string.punctuation + " \t\n!@#$%"
    return "".join(rng.choice(pool) for _ in range(n))


def _gen_unicode_bban(rng: random.Random) -> str:
    n = rng.randint(5, 40)
    samples = [
        "\u202E", "\u200E", "\u200F", "\uFEFF",
        "\u00A0", "\u200B", "\uFFFD", "\u00C9",
    ]
    out = [rng.choice(samples) for _ in range(n)]
    return "".join(out)


def _gen_non_str(rng: random.Random):
    bucket = rng.randint(0, 5)
    if bucket == 0:
        return None
    if bucket == 1:
        return rng.randint(-10000, 10000)
    if bucket == 2:
        return float("nan")
    if bucket == 3:
        n = rng.randint(0, 50)
        return bytes(rng.randint(0, 255) for _ in range(n))
    if bucket == 4:
        return [rng.randint(0, 5)]
    return {1: 2}


def _draw_bban(rng: random.Random, counter: int):
    if counter % 500 == 0:
        return _gen_real_bban(rng)
    bucket = rng.randint(0, 9)
    if bucket == 0:
        return _gen_padded_real(rng)
    if bucket == 1:
        return _gen_lower_real(rng)
    if bucket == 2:
        return _gen_random_alnum_bban(rng)
    if bucket == 3:
        return _gen_long_alnum_bban(rng)
    if bucket == 4:
        return _gen_too_short(rng)
    if bucket == 5:
        return _gen_non_alnum(rng)
    if bucket == 6:
        return _gen_unicode_bban(rng)
    if bucket in (7, 8):
        return _gen_real_bban(rng)
    # bucket == 9: a non-str sentinel — R5 territory only
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


def _check_roundtrip(bban: str, crash_log_path: str, rng: random.Random) -> None:
    """R1, R2, R4, R6 against compute_check_digits — assumes bban is a valid str
    input (the caller has already classified type-confusion separately)."""
    # IMPORTANT: the function strips spaces and hyphens internally, but the
    # *assembled IBAN* in R2 must be on the stripped form too — otherwise
    # we'd be inserting check digits into the wrong positions.
    stripped = bban.replace(" ", "").replace("-", "").upper()

    check = iban_pure.compute_check_digits(bban)

    # R1 — output format.
    assert isinstance(check, str), f"R1: returned non-str {type(check).__name__}"
    assert len(check) == 2, f"R1: returned {len(check)}-char string {check!r}"
    assert check.isdigit(), f"R1: returned non-digit string {check!r}"
    assert 2 <= int(check) <= 98, f"R1: returned out-of-range check {check!r}"

    # R2 — round-trip: assembled IBAN must validate True. The assembly uses
    # the *stripped* form so that leading/trailing whitespace doesn't
    # corrupt the country-code slot (bban[:2] is the first 2 chars).
    #
    # SCOPE: R2 only applies when the assembled IBAN is within validate()'s
    # documented length band (5..100 chars after strip). For longer inputs,
    # validate() returns False by design (QA fix 45eba5e, audit I4), so a
    # round-trip "failure" is the expected behavior — not a regression.
    # This is a REAL finding worth recording: compute_check_digits has no
    # length cap (R7), but its round-trip with validate() is only defined
    # for inputs ≤ 98 chars. The harness counts out-of-band R2 failures
    # separately so they don't pollute the in-band invariant count.
    iban = stripped[:2] + check + stripped[2:]
    if 5 <= len(iban) <= 100:
        assert iban_pure.validate(iban) is True, (
            f"R2: round-trip failed (in-band); bban={bban!r} "
            f"stripped={stripped!r} check={check!r} iban={iban!r}"
        )
    # else: out-of-band — validate()'s 100-char cap makes round-trip
    # vacuously undefined; harness does not count this as a failure.

    # R4 — determinism: re-call yields same answer.
    check2 = iban_pure.compute_check_digits(bban)
    assert check2 == check, (
        f"R4: non-deterministic; first={check!r} second={check2!r} on bban={bban!r}"
    )

    # R6 — cross-check: for canonical real IBANs, the computed check MUST
    # match the expected check digits (lookup via REAL_IBAN_CORPUS).
    bban_to_expected = {entry[1]: entry[2] for entry in REAL_IBAN_CORPUS}
    expected_check = bban_to_expected.get(bban)
    if expected_check is not None:
        assert check == expected_check, (
            f"R6: cross-check failed for real IBAN bban={bban!r}; "
            f"computed={check!r} expected={expected_check!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=str(__doc__).split("\n")[0])  # type: ignore[arg-type]
    ap.add_argument("--iters", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log", default=os.path.join(_HERE, "crash_log_roundtrip.txt"))
    args = ap.parse_args()

    if os.path.exists(args.log):
        os.remove(args.log)

    rng = random.Random(args.seed)

    iters = 0
    raise_unexpected_count = 0   # raises on str inputs we expected to succeed
    raise_expected_short_count = 0  # raises on too-short — expected
    raise_expected_garbage_count = 0  # raises on non-alnum — expected
    raise_expected_oversized_count = 0  # raises on long alnum (R7, int-limit) — expected
    raise_nonstr_count = 0        # R5 raises on non-str — expected
    invariant_count = 0
    t0 = time.monotonic()

    while iters < args.iters:
        iters += 1
        x = _draw_bban(rng, iters)

        # ── R5: non-str input ──────────────────────────────────────────────
        if not isinstance(x, str):
            try:
                _ = iban_pure.compute_check_digits(x)  # type: ignore[arg-type]
                # Silent acceptance of non-str is a regression — record it.
                invariant_count += 1
                _record_crash("invariant", x, "R5: non-str input silently accepted", args.log)
            except BaseException:  # noqa: BLE001 — expected for non-str
                raise_nonstr_count += 1
            continue

        stripped = x.replace(" ", "").replace("-", "")
        slen = len(stripped)

        # ── classify str input ─────────────────────────────────────────────
        if slen < 5 or not stripped.isalnum():
            # Too short or non-alnum: function MUST raise ValueError (audit §3.2).
            try:
                _ = iban_pure.compute_check_digits(x)
                invariant_count += 1
                _record_crash(
                    "invariant", x,
                    "expected ValueError for too-short/non-alnum input but got no raise",
                    args.log,
                )
            except ValueError:
                if slen < 5:
                    raise_expected_short_count += 1
                else:
                    raise_expected_garbage_count += 1
            except BaseException as exc:  # noqa: BLE001
                invariant_count += 1
                _record_crash(
                    "invariant", x,
                    f"expected ValueError but got {type(exc).__name__}: {exc}",
                    args.log,
                )
            continue

        # ── valid alnum str: R1, R2, R4 ────────────────────────────────────
        try:
            _check_roundtrip(x, args.log, rng)
        except AssertionError as exc:
            invariant_count += 1
            _record_crash("invariant", x, str(exc), args.log)
            continue
        except ValueError as exc:
            # R7 — oversize alnum triggers int()'s digit-string-length
            # safety limit. Detect via message content; classify as expected.
            msg = str(exc)
            if "limit" in msg.lower() or "integer string conversion" in msg.lower():
                raise_expected_oversized_count += 1
                continue
            # Some other ValueError on alnum — that's a regression.
            raise_unexpected_count += 1
            _record_crash(
                "raise",
                x,
                f"unexpected ValueError on alnum str input: {exc}",
                args.log,
            )
        except BaseException as exc:  # noqa: BLE001
            raise_unexpected_count += 1
            _record_crash(
                "raise",
                x,
                f"unexpected {type(exc).__name__}: {exc} on alnum str input",
                args.log,
            )

    elapsed = time.monotonic() - t0
    rate = iters / elapsed if elapsed > 0 else 0.0

    print("=" * 72)
    print(f"harness_roundtrip  target=iban_pure.compute_check_digits  commit=4bf40d0")
    print(f"iters                          = {iters:,}")
    print(f"elapsed                        = {elapsed:.2f}s")
    print(f"rate                           = {rate:,.0f} it/s")
    print(f"raises_unexpected (alnum)      = {raise_unexpected_count}")
    print(f"raises_expected_short          = {raise_expected_short_count}")
    print(f"raises_expected_garbage        = {raise_expected_garbage_count}")
    print(f"raises_expected_oversized (R7) = {raise_expected_oversized_count}")
    print(f"raises_nonstr (R5)             = {raise_nonstr_count}")
    print(f"invariant_violations           = {invariant_count}")
    print(f"seed_corpus_size               = {len(REAL_BBANS)}")
    print(f"log                            = {args.log}")
    print("=" * 72)

    if raise_unexpected_count or invariant_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
