"""Tests for checksum validators."""

from euredact.rules.validators import (
    validate_bsn,
    validate_belgian_nn,
    validate_iban,
    validate_luhn,
    validate_belgian_vat,
    validate_vat_nl,
    validate_vat_de,
    validate_german_tax_id,
    validate_french_nir,
    validate_vin,
    validate_bic,
    validate_kvk,
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
