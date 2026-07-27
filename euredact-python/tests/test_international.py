"""Self-identifying identifiers must not depend on ``countries=[...]``.

Two detectors carry enough evidence to stand on their own:

* an **IBAN** carries its own country code and a mod-97 checksum;
* an **international phone number** carries a ``+`` country prefix.

Both were previously gated: an IBAN was only found when its country happened
to be requested, and phone numbers were matched by per-country patterns that
each hard-code a single grouping — ``+43 664 8213 907`` was invisible because
the Austrian pattern expects an unbroken subscriber number. Missing either is
leaked PII, the worse failure direction.

The phone gap was also the root cause of the POSTAL_CODE split: with no phone
match to claim the span, the bare-4-digit rule took ``8213`` out of the middle
of ``+43 664 8213 907``.
"""

import pytest

from euredact.rules.validators import validate_e164, validate_iban
from euredact.sdk import EuRedact
from euredact.types import EntityType


@pytest.fixture(scope="module")
def intl_sdk():
    return EuRedact()


def _of_type(sdk, text, country, etype):
    result = sdk.redact(text, countries=[country] if country else None)
    return [d.text for d in result.detections if d.entity_type == etype]


# ═══════════════════════════════════════════════════════════════════════
# BUG 3 — international phone formats, several groupings per country.
# ═══════════════════════════════════════════════════════════════════════

PHONE_CASES = [
    ("ph-at-grouped", "+43 664 8213 907", "AT"),
    ("ph-at-compact", "+43 664 8213907", "AT"),
    ("ph-at-landline", "+43 1 5551234", "AT"),
    ("ph-at-trunk-paren", "+43 (0)664 8213907", "AT"),
    ("ph-at-hyphens", "+43-664-8213907", "AT"),
    ("ph-be-pairs", "+32 498 22 67 31", "BE"),
    ("ph-be-landline", "+32 2 555 12 34", "BE"),
    ("ph-be-trunk-paren", "+32 (0)2 555 12 34", "BE"),
    ("ph-nl-grouped", "+31 6 1234 5678", "NL"),
    ("ph-nl-compact", "+31 6 12345678", "NL"),
    ("ph-nl-trunk-paren", "+31 (0)6 12345678", "NL"),
    ("ph-de-grouped", "+49 30 1234 5678", "DE"),
    ("ph-de-mobile", "+49 170 1234567", "DE"),
    ("ph-de-trunk-paren", "+49 (0)30 12345678", "DE"),
    ("ph-fr-pairs", "+33 6 12 34 56 78", "FR"),
    ("ph-fr-landline", "+33 1 42 68 53 00", "FR"),
    ("ph-ie-mobile", "+353 87 123 4567", "IE"),
    ("ph-ie-landline", "+353 1 234 5678", "IE"),
    ("ph-ch-pairs", "+41 79 123 45 67", "CH"),
    ("ph-uk-mobile", "+44 7911 123456", "UK"),
    ("ph-uk-landline", "+44 20 7946 0958", "UK"),
    ("ph-it-landline", "+39 06 1234 5678", "IT"),
    ("ph-es-pairs", "+34 612 34 56 78", "ES"),
    ("ph-es-landline", "+34 91 123 45 67", "ES"),
    ("ph-pt-landline", "+351 21 123 4567", "PT"),
    ("ph-pl-landline", "+48 22 123 45 67", "PL"),
    ("ph-se-mobile", "+46 70 123 45 67", "SE"),
    ("ph-dk-pairs", "+45 32 12 34 56", "DK"),
    ("ph-no-grouped", "+47 412 34 567", "NO"),
    ("ph-fi-mobile", "+358 40 123 4567", "FI"),
    ("ph-lu-pairs", "+352 26 12 34 56", "LU"),
    ("ph-cz-landline", "+420 2 1234 5678", "CZ"),
    ("ph-hu-mobile", "+36 30 123 4567", "HU"),
    ("ph-ro-landline", "+40 21 123 4567", "RO"),
    ("ph-el-mobile", "+30 694 123 4567", "EL"),
    ("ph-is-short", "+354 611 2345", "IS"),
]

# A foreign number in a document processed for another country. The "+" is
# self-identifying, so country gating must not apply.
PHONE_CROSS_BORDER = [
    ("xb-be-number-at-doc", "Kontakt: +32 498 22 67 31", "AT"),
    ("xb-nl-number-de-doc", "Kontakt: +31 6 1234 5678", "DE"),
    ("xb-fr-number-be-doc", "Contact: +33 6 12 34 56 78", "BE"),
    ("xb-uk-number-ie-doc", "Contact: +44 7911 123456", "IE"),
    ("xb-at-number-nl-doc", "Contact: +43 664 8213 907", "NL"),
]

PHONE_MUST_NOT = [
    ("nph-too-short", "Zimmer +43 12", "AT"),
    ("nph-arithmetic", "Saldo +5 3 2 EUR", "AT"),
    ("nph-gps", "Position +43.1234, 16.5678", "AT"),
]

# ═══════════════════════════════════════════════════════════════════════
# BUG 4 — IBANs are self-identifying and self-validating.
# ═══════════════════════════════════════════════════════════════════════

# Each detected while a *different* country is requested.
IBAN_CROSS_BORDER = [
    ("ib-be-in-at", "BE68 5390 0754 7034", "AT"),
    ("ib-nl-in-at", "NL91 ABNA 0417 1643 00", "AT"),
    ("ib-de-in-be", "DE89 3704 0044 0532 0130 00", "BE"),
    ("ib-fr-in-de", "FR76 3000 6000 0112 3456 7890 189", "DE"),
    ("ib-at-in-nl", "AT61 1904 3002 3457 3201", "NL"),
    ("ib-ch-in-fr", "CH93 0076 2011 6238 5295 7", "FR"),
    ("ib-gb-in-ie", "GB33 BUKB 2020 1555 5555 55", "IE"),
    ("ib-ie-in-uk", "IE29 AIBK 9311 5212 3456 78", "UK"),
    ("ib-es-in-pt", "ES91 2100 0418 4502 0005 1332", "PT"),
    ("ib-it-in-ch", "IT60 X054 2811 1010 0000 0123 456", "CH"),
    ("ib-pt-in-es", "PT50 0002 0123 1234 5678 9015 4", "ES"),
    ("ib-lu-in-be", "LU28 0019 4006 4475 0000", "BE"),
    ("ib-dk-in-se", "DK50 0040 0440 1162 43", "SE"),
    ("ib-no-in-dk", "NO93 8601 1117 947", "DK"),
    ("ib-fi-in-no", "FI21 1234 5600 0007 85", "NO"),
    ("ib-se-in-fi", "SE45 5000 0000 0583 9825 7466", "FI"),
    ("ib-pl-in-cz", "PL61 1090 1014 0000 0712 1981 2874", "CZ"),
    ("ib-cz-in-pl", "CZ65 0800 0000 1920 0014 5399", "PL"),
    ("ib-hu-in-ro", "HU42 1177 3016 1111 1018 0000 0000", "RO"),
    ("ib-ro-in-hu", "RO49 AAAA 1B31 0075 9384 0000", "HU"),
    ("ib-gr-in-it", "GR16 0110 1250 0000 0001 2300 695", "IT"),
    ("ib-is-in-no", "IS14 0159 2600 7654 5510 7303 39", "NO"),
]


# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "number,country", [pytest.param(n, c, id=i) for i, n, c in PHONE_CASES]
)
def test_international_phone_formats_detected(intl_sdk, number, country):
    """Whole number claimed, whatever the grouping."""
    text = f"Telefon: {number} erreichbar."
    got = _of_type(intl_sdk, text, country, EntityType.PHONE)
    assert got, f"{number!r} not detected"
    assert number.replace(" ", "") in got[0].replace(" ", "")


@pytest.mark.parametrize(
    "text,country", [pytest.param(t, c, id=i) for i, t, c in PHONE_CROSS_BORDER]
)
def test_foreign_phone_detected_regardless_of_country(intl_sdk, text, country):
    assert _of_type(intl_sdk, text, country, EntityType.PHONE)


@pytest.mark.parametrize(
    "text,country", [pytest.param(t, c, id=i) for i, t, c in PHONE_MUST_NOT]
)
def test_short_and_numeric_fragments_are_not_phones(intl_sdk, text, country):
    assert _of_type(intl_sdk, text, country, EntityType.PHONE) == []


@pytest.mark.parametrize(
    "iban,country", [pytest.param(n, c, id=i) for i, n, c in IBAN_CROSS_BORDER]
)
def test_iban_detected_regardless_of_requested_country(intl_sdk, iban, country):
    """An IBAN carries its own country code and checksum; `countries=[...]`
    must never gate it."""
    text = f"Betaling naar {iban} uitgevoerd."
    got = _of_type(intl_sdk, text, country, EntityType.IBAN)
    assert got == [iban]


def test_iban_detected_with_no_country_requested(intl_sdk):
    got = _of_type(intl_sdk, "Payment to BE68 5390 0754 7034 please.", None, EntityType.IBAN)
    assert got == ["BE68 5390 0754 7034"]


def test_iban_does_not_absorb_a_following_uppercase_word(intl_sdk):
    """The pattern pins each country's exact IBAN length. Without that, greedy
    matching swallows the next word, fails mod-97 and loses the IBAN entirely."""
    got = _of_type(intl_sdk, "IBAN BE68 5390 0754 7034 KBC BRUSSEL", "AT", EntityType.IBAN)
    assert got == ["BE68 5390 0754 7034"]


def test_invalid_checksum_iban_is_not_detected(intl_sdk):
    assert _of_type(intl_sdk, "Rekening BE68 5390 0754 7035 hier.", "AT", EntityType.IBAN) == []


def test_phone_claims_span_instead_of_postal_code(intl_sdk):
    """Bug 3 was the root cause of the Bug 2 postal split."""
    text = "Anschrift: Hauptstrasse 5, 1010 Wien. Telefon: +43 664 8213 907"
    result = intl_sdk.redact(text, countries=["AT"])
    assert "[PHONE]" in result.redacted_text
    assert "8213" not in result.redacted_text
    assert _of_type(intl_sdk, text, "AT", EntityType.POSTAL_CODE) == ["1010"]


def test_phone_wins_over_national_id_lookalike(intl_sdk):
    """`+31 621036924` is a phone number, not a Dutch BSN."""
    text = "Bereikbaar op telefoon +31 621036924 voor vragen."
    result = intl_sdk.redact(text, countries=["NL"])
    types = {d.entity_type for d in result.detections}
    assert EntityType.PHONE in types
    assert EntityType.NATIONAL_ID not in types
    assert "621036924" not in result.redacted_text


def test_iban_wins_over_vat_lookalike(intl_sdk):
    """`RO57` at the head of an IBAN is not a Romanian VAT number."""
    text = "Payment to IBAN RO57 ASAI 0045 9289 4075 9966 today."
    result = intl_sdk.redact(text, countries=["RO"])
    types = {d.entity_type for d in result.detections}
    assert EntityType.IBAN in types
    assert EntityType.VAT not in types


class TestE164Validator:
    def test_accepts_minimum_length(self):
        assert validate_e164("+3161234567") is True

    def test_rejects_too_few_digits(self):
        assert validate_e164("+431234") is False

    def test_rejects_more_than_15_digits(self):
        assert validate_e164("+43 664 8213 907 1234 5678") is False

    def test_rejects_without_plus(self):
        assert validate_e164("0664 8213907") is False

    def test_trunk_prefix_not_counted(self):
        assert validate_e164("+43 (0)664 8213907") is True


class TestIbanLengthTable:
    def test_short_iban_country(self):
        assert validate_iban("NO93 8601 1117 947") is True

    def test_long_iban_country(self):
        assert validate_iban("MT84 MALT 0110 0001 2345 MTLC AST0 01S") is True

    def test_wrong_length_for_country_rejected(self):
        assert validate_iban("BE68 5390 0754 70345") is False
