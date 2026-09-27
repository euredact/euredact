"""Tests for checksum validators."""

import pytest

from euredact.rules.validators import (
    validate_belgian_nn,
    validate_belgian_vat,
    validate_bic,
    validate_bsn,
    validate_czech_birth_number,
    validate_french_nir,
    validate_german_tax_id,
    validate_iban,
    validate_kvk,
    validate_luhn,
    validate_vat_de,
    validate_vat_nl,
    validate_vin,
)


class TestIBAN:
    def test_valid_dutch_iban(self):
        assert validate_iban("NL91ABNA0417164300") is True

    def test_valid_belgian_iban(self):
        assert validate_iban("BE68539007547034") is True

    def test_valid_german_iban(self):
        assert validate_iban("DE89370400440532013000") is True

    def test_valid_french_iban(self):
        assert validate_iban("FR7630006000011234567890189") is True

    def test_valid_iban_with_spaces(self):
        assert validate_iban("NL91 ABNA 0417 1643 00") is True

    def test_invalid_iban_bad_checksum(self):
        assert validate_iban("NL00ABNA0417164300") is False

    def test_invalid_iban_wrong_length(self):
        assert validate_iban("NL91ABNA041716430") is False

    def test_invalid_iban_short(self):
        assert validate_iban("NL91") is False


class TestBSN:
    def test_valid_bsn(self):
        assert validate_bsn("111222333") is True

    def test_valid_bsn_with_dots(self):
        assert validate_bsn("111.222.333") is True

    def test_invalid_bsn_bad_checksum(self):
        assert validate_bsn("123456789") is False

    def test_invalid_bsn_all_zeros(self):
        assert validate_bsn("000000000") is False

    def test_invalid_bsn_wrong_length(self):
        assert validate_bsn("12345678") is False


class TestBelgianNN:
    def test_valid_nn(self):
        # first 9 = 850412123, 850412123 % 97 = 28, check = 97 - 28 = 69
        assert validate_belgian_nn("85041212369") is True

    def test_valid_nn_formatted(self):
        assert validate_belgian_nn("85.04.12-123.69") is True

    def test_invalid_nn_bad_checksum(self):
        assert validate_belgian_nn("85041212399") is False

    def test_valid_nn_born_after_2000(self):
        # For 2000+: prepend '2' -> 2030101001, check = 97 - (2030101001 % 97)
        first_nine = int("2" + "030101001")
        check = 97 - (first_nine % 97)
        nn = "030101001" + f"{check:02d}"
        assert validate_belgian_nn(nn) is True


class TestLuhn:
    def test_valid_visa(self):
        assert validate_luhn("4532015112830366") is True

    def test_valid_mastercard(self):
        assert validate_luhn("5425233430109903") is True

    def test_invalid_card(self):
        assert validate_luhn("4532015112830367") is False

    def test_too_short(self):
        assert validate_luhn("1234") is False


class TestBelgianVAT:
    def test_valid_vat(self):
        # first8 = 01234567 (int 1234567), 1234567 % 97 = 48, check = 97-48 = 49
        assert validate_belgian_vat("BE0123456749") is True

    def test_valid_vat_formatted(self):
        assert validate_belgian_vat("BE 0123.456.749") is True

    def test_invalid_vat(self):
        assert validate_belgian_vat("BE0123456700") is False


class TestVATNL:
    def test_valid(self):
        assert validate_vat_nl("NL123456789B01") is True

    def test_invalid_no_b(self):
        assert validate_vat_nl("NL12345678901") is False


class TestVATDE:
    def test_valid(self):
        assert validate_vat_de("DE123456789") is True

    def test_invalid_too_short(self):
        assert validate_vat_de("DE12345678") is False


class TestGermanTaxID:
    def test_valid(self):
        assert validate_german_tax_id("65929970489") is True

    def test_invalid_starts_with_zero(self):
        assert validate_german_tax_id("01234567890") is False

    def test_invalid_wrong_check(self):
        assert validate_german_tax_id("65929970488") is False


class TestFrenchNIR:
    def test_valid_male(self):
        digits = "1850475123456"
        first_13 = int(digits)
        check = 97 - (first_13 % 97)
        nir = digits + f"{check:02d}"
        assert validate_french_nir(nir) is True

    def test_invalid_bad_check(self):
        assert validate_french_nir("185047512345600") is False


class TestVIN:
    def test_valid_vin(self):
        assert validate_vin("11111111111111111") is True

    def test_invalid_contains_forbidden_chars(self):
        assert validate_vin("WBAIO5C55CF256789") is False

    def test_invalid_too_short(self):
        assert validate_vin("WBA3A5C55CF2567") is False


class TestBIC:
    def test_valid_8_char(self):
        assert validate_bic("DEUTDEFF") is True

    def test_valid_11_char(self):
        assert validate_bic("DEUTDEFFXXX") is True

    def test_invalid_wrong_length(self):
        assert validate_bic("DEUTDE") is False

    def test_invalid_numbers_in_bank(self):
        assert validate_bic("D3UTDEFF") is False


class TestKVK:
    def test_valid(self):
        assert validate_kvk("12345678") is True

    def test_leading_zero_valid(self):
        assert validate_kvk("01234567") is True

    def test_invalid_too_short(self):
        assert validate_kvk("1234567") is False


class TestCzechBirthNumberDate:
    """The date component, not only the checksum.

    A Czech mobile number is nine digits opening 6 or 7, which is the rodné
    číslo shape, so a validator that checks only mod 11 accepts any mobile that
    happens to be divisible by 11 -- and the engine then types it NATIONAL_ID at
    ``confidence="high"``. 284 per corpus pass, the largest single
    false-positive bucket in the evaluation (rules-engine#37).
    """

    @pytest.mark.parametrize("value", [
        "606666032",   # YY=60 MM=66 DD=60 -- month and day both impossible
        "778836400",   # MM=88
        "728990603",   # MM=89
        "724556554",   # MM=45
        "8002300009",  # 30 February
        "8002310008",  # 31 February
        "8002000006",  # day 00
        "8013150004",  # month 13
        "8033150002",  # month 33, past the +20 range
        "8063150007",  # month 63, past the +50 range
        "8083150005",  # month 83, past the +70 range
    ])
    def test_an_impossible_date_is_rejected(self, value: str) -> None:
        assert validate_czech_birth_number(value) is False

    @pytest.mark.parametrize("value", [
        "561201/1812",   # a real corpus value
        "001121/3367",   # a real corpus value
        "8001150003",    # month field 01 -- man
        "8021150005",    # month field 21 -- +20, exhausted day
        "8051150008",    # month field 51 -- +50, woman
        "8071150010",    # month field 71 -- +70, woman on an exhausted day
        "8002290010",    # 29 February: the century is unknown, so it is allowed
        "8002010005",    # day 01
        "8002280000",    # day 28
    ])
    def test_a_legal_date_is_accepted(self, value: str) -> None:
        assert validate_czech_birth_number(value) is True

    def test_the_checksum_still_applies(self) -> None:
        # A legal date does not excuse a failed mod 11.
        assert validate_czech_birth_number("8001150004") is False
        assert validate_czech_birth_number("8001150003") is True

    def test_nine_digit_numbers_keep_having_no_checksum(self) -> None:
        # Pre-1954 numbers carry no check digit, so only the date gates them.
        assert validate_czech_birth_number("560101123") is True
        assert validate_czech_birth_number("566601123") is False
