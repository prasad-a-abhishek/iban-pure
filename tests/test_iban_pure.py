"""Comprehensive test suite for iban-pure — IBAN mod-97 validator (ISO 13616-1:2007)."""

import pytest
from iban_pure import validate, compute_check_digits, format_display


# ─────────────────────────────────────────────────────────────────────────────
# AC1: validate() correctly classifies known-valid and known-invalid IBANs
# ─────────────────────────────────────────────────────────────────────────────

def test_ac1_DE_valid():
    assert validate("DE89370400440532013000") is True


def test_ac1_GB_valid():
    assert validate("GB82WEST12345698765432") is True


def test_ac1_FR_valid():
    assert validate("FR1420041010050500013M02606") is True


def test_ac1_ES_valid():
    assert validate("ES9121000418450200051332") is True


def test_ac1_NL_valid():
    assert validate("NL91ABNA0417164300") is True


def test_ac1_BE_valid():
    assert validate("BE68539007547034") is True


def test_ac1_AT_valid():
    assert validate("AT611904300234573201") is True


def test_ac1_SE_valid():
    assert validate("SE4550000000058398257466") is True


def test_ac1_NO_valid():
    # Norway (15 chars)
    assert validate("NO9386011117947") is True


def test_ac1_CH_valid():
    # Switzerland (21 chars)
    assert validate("CH9300762011623852957") is True


def test_ac1_FI_valid():
    # Finland (18 chars)
    assert validate("FI1410093000123458") is True


def test_ac1_DK_valid():
    # Denmark (18 chars)
    assert validate("DK5000400440116243") is True


def test_ac1_IT_valid():
    # Italy (26 chars) — check=66
    assert validate("IT66X054281110100000001234") is True


def test_ac1_invalid_wrong_check():
    assert validate("DE99370400440532013000") is False


def test_ac1_invalid_flipped():
    assert validate("DE89370400440532013003") is False


def test_ac1_invalid_all_Z():
    assert validate("ZZZZZZZZZZZZZZZZZZZZZZ") is False


def test_ac1_invalid_XX_country():
    assert validate("XX89370400440532013000") is False


# ─────────────────────────────────────────────────────────────────────────────
# AC2: validate() normalizes spaces and lower-case; output invariant
# ─────────────────────────────────────────────────────────────────────────────

def test_ac2_spaced():
    assert validate("DE89 3704 0044 0532 0130 00") is True


def test_ac2_lowercase():
    assert validate("de89370400440532013000") is True


def test_ac2_mixed_case():
    assert validate("De89370400440532013000") is True


def test_ac2_normalization_invariant():
    """validate(normalized) == validate(original) for valid IBAN."""
    ibans = [
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
    ]
    for iban in ibans:
        spaced = " ".join(iban[i : i + 4] for i in range(0, len(iban), 4))
        lower = iban.lower()
        assert validate(spaced) is True
        assert validate(lower) is True
        assert validate(spaced) == validate(iban)
        assert validate(lower) == validate(iban)


# ─────────────────────────────────────────────────────────────────────────────
# AC3: validate() returns False for wrong lengths per country
# ─────────────────────────────────────────────────────────────────────────────

def test_ac3_DE_too_short():
    assert validate("DE8937040044053201") is False


def test_ac3_DE_too_long():
    assert validate("DE8937040044053201300000") is False


def test_ac3_GB_too_short():
    assert validate("GB82WEST12345698765") is False


def test_ac3_NL_too_short():
    assert validate("NL91ABNA041716") is False


def test_ac3_BE_too_short():
    assert validate("BE68539007547") is False


def test_ac3_IT_too_short():
    # IT must be 27 chars
    assert validate("IT60X05428111010000000123") is False


def test_ac3_IT_too_long():
    assert validate("IT60X05428111010000000123456") is False


def test_ac3_NO_too_short():
    # NO must be 15 chars
    assert validate("NO938601111794") is False


def test_ac3_CH_too_short():
    # CH must be 21 chars
    assert validate("CH93007620116238529") is False


# ─────────────────────────────────────────────────────────────────────────────
# AC4: compute_check_digits(BBAN) returns correct two check digits
# Input format: country_code (2) + account (N)
# Prepending country + check to account yields a valid IBAN
# ─────────────────────────────────────────────────────────────────────────────

def test_ac4_DE():
    # DE IBAN = DE89 + 370400440532013000 (18)
    bban = "DE370400440532013000"
    check = compute_check_digits(bban)
    assert check == "89"
    assert validate(f"DE{check}370400440532013000") is True


def test_ac4_GB():
    # GB IBAN = GB82 + WEST12345698765432 (18)
    bban = "GBWEST12345698765432"
    check = compute_check_digits(bban)
    assert check == "82"
    assert validate(f"GB{check}WEST12345698765432") is True


def test_ac4_FR():
    # FR IBAN = FR14 + 20041010050500013M02606 (23)
    bban = "FR20041010050500013M02606"
    check = compute_check_digits(bban)
    assert check == "14"
    assert validate(f"FR{check}20041010050500013M02606") is True


def test_ac4_ES():
    # ES IBAN = ES91 + 21000418450200051332 (22)
    bban = "ES21000418450200051332"
    check = compute_check_digits(bban)
    assert check == "91"
    assert validate(f"ES{check}21000418450200051332") is True


def test_ac4_NL():
    # NL IBAN = NL91 + ABNA0417164300 (14)
    bban = "NLABNA0417164300"
    check = compute_check_digits(bban)
    assert check == "91"
    assert validate(f"NL{check}ABNA0417164300") is True


def test_ac4_BE():
    # BE IBAN = BE68 + 539007547034 (12)
    bban = "BE539007547034"
    check = compute_check_digits(bban)
    assert check == "68"
    assert validate(f"BE{check}539007547034") is True


def test_ac4_AT():
    # AT IBAN = AT61 + 904300234573201 (16)
    bban = "AT1904300234573201"
    check = compute_check_digits(bban)
    assert check == "61"
    assert validate(f"AT{check}1904300234573201") is True


def test_ac4_SE():
    # SE IBAN = SE45 + 50000000058398257466 (22)
    bban = "SE50000000058398257466"
    check = compute_check_digits(bban)
    assert check == "45"
    assert validate(f"SE{check}50000000058398257466") is True


def test_ac4_NO():
    # NO IBAN = NO93 + 86011117947 (11)
    bban = "NO86011117947"
    check = compute_check_digits(bban)
    assert check == "93"
    assert validate(f"NO{check}86011117947") is True


def test_ac4_CH():
    # CH IBAN = CH93 + 00762011623852957 (17)
    bban = "CH00762011623852957"
    check = compute_check_digits(bban)
    assert check == "93"
    assert validate(f"CH{check}00762011623852957") is True


def test_ac4_FI():
    # FI IBAN = FI14 + 0093000123458 (13)
    bban = "FI10093000123458"
    check = compute_check_digits(bban)
    assert check == "14"
    assert validate(f"FI{check}10093000123458") is True


def test_ac4_DK():
    # DK IBAN = DK50 + 00400440116243 (14)
    bban = "DK00400440116243"
    check = compute_check_digits(bban)
    assert check == "50"
    assert validate(f"DK{check}00400440116243") is True


def test_ac4_IT():
    # IT IBAN = IT66 + X054281110100000001234 (24)
    bban = "ITX054281110100000001234"
    check = compute_check_digits(bban)
    assert check == "66"
    assert validate(f"IT{check}X054281110100000001234") is True


# ─────────────────────────────────────────────────────────────────────────────
# AC5: format_display() returns correctly spaced IBAN
# ─────────────────────────────────────────────────────────────────────────────

def test_ac5_DE():
    assert format_display("DE89370400440532013000") == "DE89 3704 0044 0532 0130 00"


def test_ac5_GB():
    assert format_display("GB82WEST12345698765432") == "GB82 WEST 1234 5698 7654 32"


def test_ac5_FR():
    assert format_display("FR1420041010050500013M02606") == "FR14 2004 1010 0505 0001 3M02 606"


def test_ac5_ES():
    assert format_display("ES9121000418450200051332") == "ES91 2100 0418 4502 0005 1332"


def test_ac5_NL():
    assert format_display("NL91ABNA0417164300") == "NL91 ABNA 0417 1643 00"


def test_ac5_BE():
    assert format_display("BE68539007547034") == "BE68 5390 0754 7034"


def test_ac5_AT():
    assert format_display("AT611904300234573201") == "AT61 1904 3002 3457 3201"


def test_ac5_SE():
    assert format_display("SE4550000000058398257466") == "SE45 5000 0000 0583 9825 7466"


def test_ac5_IT():
    assert format_display("IT66X054281110100000001234") == "IT66 X054 2811 1010 0000 0012 34"


def test_ac5_NO():
    assert format_display("NO9386011117947") == "NO93 8601 1117 947"


def test_ac5_CH():
    assert format_display("CH9300762011623852957") == "CH93 0076 2011 6238 5295 7"


def test_ac5_lowercase_normalizes():
    assert format_display("de89370400440532013000") == "DE89 3704 0044 0532 0130 00"


def test_ac5_already_spaced():
    assert format_display("DE89 3704 0044 0532 0130 00") == "DE89 3704 0044 0532 0130 00"


# ─────────────────────────────────────────────────────────────────────────────
# AC6: validate() rejects empty, malformed, and out-of-range input
# ─────────────────────────────────────────────────────────────────────────────

def test_ac6_empty_string():
    assert validate("") is False


def test_ac6_single_char():
    assert validate("D") is False


def test_ac6_two_chars():
    assert validate("DE") is False


def test_ac6_DE_only_2_check():
    assert validate("DE12") is False


def test_ac6_DE_too_short():
    assert validate("DE12370440044") is False


def test_ac6_DE_too_long():
    assert validate("DE89370400440532013000123") is False


def test_ac6_non_alphanumeric():
    assert validate("DE!!70400440532013000") is False


def test_ac6_spaces_only():
    assert validate("    ") is False


def test_ac6_unicode_letters():
    """Non-ASCII unicode letters are not valid IBAN characters."""
    assert validate("DE89Ä70400440532013000") is False


def test_ac6_tab_char():
    assert validate("DE89\t37040044") is False


def test_ac6_newline():
    assert validate("DE89\n37040044") is False


def test_ac6_leading_spaces_ignored():
    """Leading/trailing spaces are stripped by validate()."""
    assert validate("  DE89370400440532013000") is True


# ─────────────────────────────────────────────────────────────────────────────
# AC7: validate() is case-insensitive (normalization invariant)
# ─────────────────────────────────────────────────────────────────────────────

def test_ac7_lowercase_invariant():
    ibans = [
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
        "NL91ABNA0417164300",
        "BE68539007547034",
        "AT611904300234573201",
        "SE4550000000058398257466",
        "NO9386011117947",
        "CH9300762011623852957",
        "FI1410093000123458",
        "DK5000400440116243",
    ]
    for iban in ibans:
        assert validate(iban.lower()) is True
        assert validate(iban.lower()) == validate(iban)


# ─────────────────────────────────────────────────────────────────────────────
# AC8: Edge cases — boundary values, special structures
# ─────────────────────────────────────────────────────────────────────────────

def test_ac8_minimum_length_NO():
    """NO IBAN is 15 chars (minimum per spec)."""
    assert validate("NO9386011117947") is True
    assert len("NO9386011117947") == 15


def test_ac8_germany_22():
    assert validate("DE89370400440532013000") is True
    assert len("DE89370400440532013000") == 22


def test_ac8_italy_26():
    assert validate("IT66X054281110100000001234") is True
    assert len("IT66X054281110100000001234") == 26


def test_ac8_belgium_16():
    assert validate("BE68539007547034") is True
    assert len("BE68539007547034") == 16


def test_ac8_france_27():
    assert validate("FR1420041010050500013M02606") is True
    assert len("FR1420041010050500013M02606") == 27


def test_ac8_switzerland_21():
    assert validate("CH9300762011623852957") is True
    assert len("CH9300762011623852957") == 21


def test_ac8_norway_15():
    assert validate("NO9386011117947") is True
    assert len("NO9386011117947") == 15


def test_ac8_single_digit_invalidates():
    """Changing one digit in a valid IBAN makes it invalid."""
    valid = "DE89370400440532013000"
    for i in range(len(valid)):
        changed = valid[:i] + ("1" if valid[i] == "0" else "0") + valid[i + 1 :]
        if changed != valid:
            assert validate(changed) is False


def test_ac8_check_digit_sensitivity():
    """Changing check digits by ±1 produces invalid IBAN."""
    assert validate("DE88370400440532013000") is False
    assert validate("DE90370400440532013000") is False


def test_ac8_all_letters_invalid():
    assert validate("AAAAAAAAAAAAAAAAAAAAAA") is False


def test_ac8_BBAN_with_letters_UK():
    assert validate("GB82WEST12345698765432") is True


def test_ac8_French_IBAN_with_letters():
    assert validate("FR1420041010050500013M02606") is True


def test_ac8_Italian_IBAN_with_letters():
    assert validate("IT66X054281110100000001234") is True


def test_ac8_invalid_country_code():
    assert validate("XX89370400440532013000") is False


# ─────────────────────────────────────────────────────────────────────────────
# compute_check_digits — error handling
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_check_digits_rejects_too_short():
    with pytest.raises(ValueError):
        compute_check_digits("DE12")


def test_compute_check_digits_rejects_empty():
    with pytest.raises(ValueError):
        compute_check_digits("")


def test_compute_check_digits_rejects_non_alphanumeric():
    with pytest.raises(ValueError):
        compute_check_digits("DE!!70400440532013000")


def test_compute_check_digits_strips_spaces():
    assert compute_check_digits("DE37 0400 4405 3201 3000") == "89"


def test_compute_check_digits_accepts_lowercase():
    assert compute_check_digits("de370400440532013000") == "89"


# ─────────────────────────────────────────────────────────────────────────────
# format_display — edge cases
# ─────────────────────────────────────────────────────────────────────────────

def test_format_display_empty():
    assert format_display("") == ""


def test_format_display_4_chars():
    assert format_display("DE89") == "DE89"


def test_format_display_8_chars():
    assert format_display("DE893704") == "DE89 3704"


def test_format_display_15_chars():
    # 15 is not divisible by 4
    assert format_display("NO9386011117947") == "NO93 8601 1117 947"


def test_format_display_16_chars():
    assert format_display("BE68539007547034") == "BE68 5390 0754 7034"


def test_format_display_22_chars():
    assert format_display("DE89370400440532013000") == "DE89 3704 0044 0532 0130 00"


def test_format_display_27_chars():
    assert format_display("FR1420041010050500013M02606") == "FR14 2004 1010 0505 0001 3M02 606"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-function invariants
# ─────────────────────────────────────────────────────────────────────────────

def test_format_then_validate_preserves():
    """format_display(iban) validates same as iban."""
    ibans = [
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
        "ES9121000418450200051332",
        "NL91ABNA0417164300",
        "BE68539007547034",
        "AT611904300234573201",
        "SE4550000000058398257466",
        "NO9386011117947",
        "CH9300762011623852957",
        "FI1410093000123458",
        "DK5000400440116243",
        "IT60X054281110100000001234",
    ]
    for iban in ibans:
        formatted = format_display(iban)
        assert validate(formatted) == validate(iban)


def test_check_digits_roundtrip():
    """Prepend check digits to BBAN → valid IBAN."""
    bban = "NLABNA0417164300"
    check = compute_check_digits(bban)
    iban = f"{bban[:2]}{check}{bban[2:]}"
    assert validate(iban) is True


def test_mod97_rearrangement():
    """Verify rearrangement and letter substitution for UK IBAN."""
    s = "GB82WEST12345698765432"
    rearranged = s[4:] + s[:4]  # WEST12345698765432GB82
    # Letter positions: W=32, E=14, S=28, T=29 → 32142829
    assert rearranged == "WEST12345698765432GB82"
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - 55)
    # WEST → 32142829, GB → 1617, 82 stays
    assert numeric == "3214282912345698765432161182"
    assert int(numeric) % 97 == 1


# ─────────────────────────────────────────────────────────────────────────────
# Additional edge cases — push to 100+ tests
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_hyphen_normalization():
    """Hyphens are stripped just like spaces."""
    assert validate("DE89-3704-0044-0532-0130-00") is True
    assert validate("DE89-3704-0044-0532-0130-00") == validate("DE89370400440532013000")


def test_compute_check_digits_hyphen_stripped():
    """compute_check_digits strips hyphens before processing."""
    assert compute_check_digits("DE-37-04-00-44-05-32-01-30-00") == "89"


def test_validate_single_typed_error():
    """validate() must not raise — returns False on garbage."""
    assert validate(None) is False


def test_validate_integer_input():
    """validate() must not raise — returns False on integer."""
    assert validate(12345) is False
