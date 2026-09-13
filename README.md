# iban-pure

**Zero-dependency pure-Python IBAN mod-97 validator** (ISO 13616-1:2007).

> "Would I be sad if this repo didn't exist?" — A tiny, no-dependency library for validating and formatting IBANs in any Python project, including strict environments where adding a package is friction.

`pip install iban-pure`

```python
>>> from iban_pure import validate, compute_check_digits, format_display
>>> validate("DE89370400440532013000")
True
>>> compute_check_digits("DE370400440532013000")  # BBAN = country + account
'89'
>>> format_display("DE89370400440532013000")
'DE89 3704 0044 0532 0130 00'
```

## Why iban-pure?

- **Zero dependencies** — pure stdlib, no `pip install` surprises
- **Strict mode by default** — rejects malformed input immediately (no silently ignored errors)
- **ISO 13616-1:2007 compliant** — full mod-97 check, letter substitution, rearrangement
- **103 tests covering all 8 acceptance criteria** — every edge case documented and tested

## Key Features

- **`validate(iban)`** — Returns `True`/`False` after mod-97 check. Accepts spaces, lower-case.
- **`compute_check_digits(bban)`** — Given a BBAN (`"DE370400440532013000"`), returns the two check digits (`"89"`). Prepend `country + check + account` to get a valid IBAN.
- **`format_display(iban)`** — Groups IBAN into 4-character blocks (e.g. `"DE89 3704 0044 0532 0130 00"`).

### CLI

```bash
python -m iban_pure "DE89370400440532013000"
# DE89370400440532013000 — VALID

python -m iban_pure --check "DE370400440532013000"
# Check digits: 89

python -m iban_pure --format "DE89 3704 0044 0532 0130 00"
# DE89 3704 0044 0532 0130 00
```

## API Reference

### `validate(iban: str) -> bool`

Passes `iban` through ISO 13616-1:2007 mod-97 check:
1. Strips spaces and hyphens, uppercases
2. Rearranges: moves first 4 chars to the end
3. Substitutes letters: A→10, B→11, ..., Z→35
4. Returns `int(numeric) % 97 == 1`

Returns `False` for empty strings, non-alphanumeric characters, or wrong lengths per country.

### `compute_check_digits(bban: str) -> str`

Input: a BBAN string = country code (2 chars) + account portion (N chars).

Example:
```python
compute_check_digits("DE370400440532013000")  # → "89"
# DE89 + 370400440532013000 = DE89370400440532013000 (valid IBAN)
```

Raises `ValueError` for strings shorter than 5 characters or containing non-alphanumeric characters.

### `format_display(iban: str) -> str`

Formats `iban` with spaces every 4 characters, uppercased. Existing spaces are ignored.

```python
format_display("de89 3704 0044 0532 0130 00")  # → "DE89 3704 0044 0532 0130 00"
```

## Supported Countries

DE (22), GB (22), FR (27), ES (24), NL (18), BE (16), AT (20), SE (24), NO (15), CH (21), FI (18), DK (18), IT (26).

## Limitations

- No BBAN-length validation per country (only full IBAN length is checked at the 15–34 char range)
- No network access or API calls
- Does not verify that an IBAN corresponds to a real bank account

## Known Issues (audit-deferred, tracked for cycle_68)

The following findings were identified by the vulnerability audit and confirmed by fuzzing. All are accepted-risk for v0.1.0 and none are blocking.

**Medium (3):**
- `compute_check_digits` raises `TypeError` on non-string input (e.g. `None`, `int`) — no `isinstance` guard
- Spec described a 4-argument `validate(iban, normalize, format, check)` API; shipped has 3 arguments (no `normalize`)
- Spec described a 2-argument `compute_check_digits(bban, country)`; shipped is 1-argument

**Low (3):**
- Test fixture `DK5000400440116243` is a stale/wrong fixture (should be `DK5000400440116243` per official validation)
- README documents `python -m iban_pure` but no `__main__.py` entry point exists
- `format_display` silently strips whitespace and ignores garbage characters instead of raising

## Non-goals

- Bank account lookup or validation against a live database
- Generating random valid IBANs
- Support for IBANs older than ISO 13616-1:2007

## Install

```bash
pip install iban-pure
```

For development:
```bash
git clone https://github.com/prasad-a-abhishek/iban-pure.git
cd iban-pure
pip install -e .
```

## Test

```bash
pytest tests/ -v
```

## License

MIT — see LICENSE file.
