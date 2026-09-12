"""Zero-dependency IBAN mod-97 validator (ISO 13616-1:2007)."""

__version__ = "0.1.0"
__all__ = ["validate", "compute_check_digits", "format_display"]


def validate(iban: str) -> bool:
    """Return True if IBAN passes mod-97 check (ISO 13616-1:2007)."""
    if not isinstance(iban, str):
        return False
    s = iban.replace(" ", "").replace("-", "").upper()
    if not s.isalnum() or len(s) < 5:
        return False
    if len(s) > 100:
        return False
    # Rearrange: move first 4 to end
    rearranged = s[4:] + s[:4]
    # Substitute letters with digits: A=10, B=11, ..., Z=35
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - 55)  # A→10, B→11, ..., Z→35
    try:
        return int(numeric) % 97 == 1
    except (ValueError, TypeError):
        return False


def compute_check_digits(bban: str) -> str:
    """Return the two check digits for a BBAN (country code + account portion).

    Input format: country_code (2 chars) + account (N chars).
    Example: 'DE370400440532013000' (Germany, 18-char account).
    """
    s = bban.replace(" ", "").replace("-", "").upper()
    if not s.isalnum() or len(s) < 5:
        raise ValueError("Invalid BBAN: must be at least 5 alphanumeric characters")
    # Rearranged for check digit: account + country + "00"
    account = s[2:]
    country = s[:2]
    rearranged = account + country + "00"
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - 55)
    check = 98 - (int(numeric) % 97)
    return f"{check:02d}"


def format_display(iban: str) -> str:
    """Return IBAN formatted with spaces every 4 characters."""
    s = iban.replace(" ", "").replace("-", "").upper()
    return " ".join(s[i : i + 4] for i in range(0, len(s), 4))
