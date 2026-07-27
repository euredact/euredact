"""Public API contract: country codes, canonical type names, spaced identifiers.

Covers three defects that are about the *contract* rather than the patterns:

* ``countries=["GB"]`` raised ``ValueError`` because the registry uses the
  EU/VAT spellings (``UK``, ``EL``) while the documented contract is ISO
  3166-1 alpha-2 (``GB``, ``GR``);
* the engine emitted the legacy type name ``IBAN`` instead of the canonical
  ``BANK_ACCOUNT``;
* space-separated bank codes (``RZBA AT WW``) were missed.
"""

import warnings

import pytest

from euredact.rules.registry import CountryRegistry, UnknownCountryWarning
from euredact.sdk import EuRedact
from euredact.types import LEGACY_TYPE_ALIASES, EntityType


@pytest.fixture(scope="module")
def sdk():
    return EuRedact()


def _types(result):
    return {d.entity_type for d in result.detections}


# ═══════════════════════════════════════════════════════════════════════
# BUG 5 — country code handling must not crash
# ═══════════════════════════════════════════════════════════════════════

class TestCountryCodes:
    @pytest.mark.parametrize("iso,eu", [("GB", "UK"), ("GR", "EL")])
    def test_iso_and_eu_spellings_are_equivalent(self, sdk, iso, eu):
        """ISO 3166-1 alpha-2 is the documented contract; the EU/VAT spelling
        is what the country modules use. Both must work identically."""
        text = "NHS Number: 943 476 5919, postcode SW1A 1AA"
        assert sdk.redact(text, countries=[iso]).redacted_text == \
               sdk.redact(text, countries=[eu]).redacted_text

    def test_iso_code_actually_loads_country_patterns(self, sdk):
        """`GB` must run the UK patterns, not silently fall back to SHARED."""
        result = sdk.redact("NHS Number: 943 476 5919", countries=["GB"])
        assert EntityType.HEALTH_INSURANCE in _types(result)

    @pytest.mark.parametrize("code", ["GB", "gb", " GB ", "Gb"])
    def test_codes_are_normalised(self, sdk, code):
        result = sdk.redact("NHS Number: 943 476 5919", countries=[code])
        assert EntityType.HEALTH_INSURANCE in _types(result)

    def test_unknown_code_does_not_raise(self, sdk):
        """A redaction library that throws on an unknown locale invites
        callers to wrap it in try/except and skip redaction — failing open
        with unredacted PII. Degrade instead."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = sdk.redact("Mail a@b.com", countries=["ZZ"])
        assert EntityType.EMAIL in _types(result)

    def test_unknown_code_warns(self, sdk):
        # cache=False: a cached result short-circuits detection, so the
        # warning would not be re-emitted for an input seen earlier.
        with pytest.warns(UnknownCountryWarning, match="ZZ"):
            sdk.redact("Contact QQ99 for details", countries=["ZZ"], cache=False)

    def test_unknown_code_still_applies_shared_patterns(self, sdk):
        """Country-independent detection keeps working on an unknown locale."""
        text = "Call +44 7911 123456, mail a@b.com, IBAN BE68 5390 0754 7034"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = sdk.redact(text, countries=["ZZ"])
        assert {EntityType.PHONE, EntityType.EMAIL, EntityType.BANK_ACCOUNT} <= _types(result)

    def test_mixed_known_and_unknown_codes(self, sdk):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = sdk.redact("NHS Number: 943 476 5919", countries=["ZZ", "GB"])
        assert EntityType.HEALTH_INSURANCE in _types(result)

    def test_registry_resolve(self):
        reg = CountryRegistry()
        assert reg.resolve("GB") == "UK"
        assert reg.resolve("GR") == "EL"
        assert reg.resolve("be") == "BE"
        assert reg.resolve("ZZ") is None


# ═══════════════════════════════════════════════════════════════════════
# BUG 6 — canonical type names
# ═══════════════════════════════════════════════════════════════════════

class TestCanonicalTypeNames:
    def test_bank_account_is_the_emitted_name(self, sdk):
        result = sdk.redact("Rekening: BE68 5390 0754 7034", countries=["BE"])
        assert result.detections[0].entity_type.value == "BANK_ACCOUNT"

    def test_placeholder_uses_canonical_name(self, sdk):
        result = sdk.redact("Rekening: BE68 5390 0754 7034", countries=["BE"])
        assert result.redacted_text == "Rekening: [BANK_ACCOUNT]"

    def test_legacy_member_is_an_alias(self):
        """Existing code using EntityType.IBAN keeps working."""
        assert EntityType.IBAN is EntityType.BANK_ACCOUNT

    def test_legacy_value_lookup_resolves(self):
        assert EntityType("IBAN") is EntityType.BANK_ACCOUNT

    def test_alias_map_is_published(self):
        assert LEGACY_TYPE_ALIASES["IBAN"] == "BANK_ACCOUNT"

    def test_no_emitted_type_is_a_legacy_alias(self):
        """Guard: the engine must never emit a name listed as legacy."""
        emitted = {e.value for e in EntityType}
        assert emitted.isdisjoint(LEGACY_TYPE_ALIASES.keys())


# ═══════════════════════════════════════════════════════════════════════
# BUG 7 — space-separated bank codes
# ═══════════════════════════════════════════════════════════════════════

class TestSpacedBIC:
    @pytest.mark.parametrize("bic,country", [
        ("RZBA AT WW", "AT"),
        ("NICA BE BB", "BE"),
        ("GIBA AT WW", "AT"),
        ("KRED BE BB", "BE"),
        ("ABNA NL 2A", "NL"),
        ("BNPA FR PP XXX", "FR"),
    ])
    def test_spaced_bic_detected(self, sdk, bic, country):
        result = sdk.redact(f"SWIFT: {bic}", countries=[country])
        got = [d.text for d in result.detections if d.entity_type == EntityType.BIC]
        assert got == [bic]

    def test_spaced_pattern_does_not_absorb_following_word(self, sdk):
        """The spaced form requires a space between *every* group. Making the
        spaces optional in the unspaced pattern instead would let
        'GEBABEBB KBC' match as one 11-character code."""
        result = sdk.redact("SWIFT: GEBABEBB KBC", countries=["BE"])
        got = [d.text for d in result.detections if d.entity_type == EntityType.BIC]
        assert got == ["GEBABEBB"]

    def test_spaced_form_still_gated(self, sdk):
        """The tier gates apply to the spaced form too — an all-caps heading
        made of 4+2+2 letter groups is not a bank code."""
        result = sdk.redact("VOOR ALLE ZAKEN", countries=["NL"])
        assert EntityType.BIC not in _types(result)

    def test_spaced_form_does_not_span_a_line_break(self, sdk):
        result = sdk.redact("SWIFT: RZBA\nAT WW", countries=["AT"])
        got = [d.text for d in result.detections if d.entity_type == EntityType.BIC]
        assert got == []


# ═══════════════════════════════════════════════════════════════════════
# BUG 3 remainder — Austrian national numbers with a short area code
# ═══════════════════════════════════════════════════════════════════════

class TestAustrianNationalPhone:
    @pytest.mark.parametrize("number", [
        "01 53460 2215",     # Vienna, area code "1"
        "01 5346 0221",
        "0664 8213907",
        "0664 8213 907",
        "0512 507 1234",     # Innsbruck
        "0316 380 1000",     # Graz
    ])
    def test_national_formats_detected(self, sdk, number):
        result = sdk.redact(f"Tel: {number}", countries=["AT"])
        got = [d.text for d in result.detections if d.entity_type == EntityType.PHONE]
        assert got, f"{number!r} not detected"
        assert number.replace(" ", "") in got[0].replace(" ", "")

    @pytest.mark.parametrize("text", [
        "Termin am 01 2025 vereinbart",   # date fragment, too few digits
        "Position 01 12",
    ])
    def test_date_fragments_are_not_phones(self, sdk, text):
        result = sdk.redact(text, countries=["AT"])
        assert EntityType.PHONE not in _types(result)
