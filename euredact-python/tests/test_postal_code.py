"""POSTAL_CODE test data — bare digit runs must not shred longer identifiers.

A bare 4- or 5-digit run is the weakest shape in the engine. When it claims
digits belonging to a longer identifier the damage is worse than an ordinary
false positive, because the masked text is what the annotator downstream is
trained on: ``SV-Nummer: [POSTAL_CODE] 040390`` leaves half an Austrian social
security number visible with no way to label the remainder.

Two rules carry this:

* a digits-only match adjacent to another digit, to ``. - / _``, or followed
  by a further digit group on the same line, is part of a longer number;
* POSTAL_CODE resolves last in the engine, so it can only claim spans no
  structured detector (PHONE, SSN, NATIONAL_ID, IBAN, VAT...) wants.

Structured postal forms — NL ``1234 AB``, PT ``1234-567``, LU ``L-1234`` —
are untouched by the digit-adjacency rules.
"""

import pytest

from euredact.sdk import EuRedact
from euredact.types import EntityType

# Types that must never have a POSTAL_CODE cut into them.
_STRUCTURED = {
    EntityType.PHONE, EntityType.SSN, EntityType.NATIONAL_ID,
    EntityType.HEALTH_INSURANCE, EntityType.IBAN, EntityType.VAT,
    EntityType.TAX_ID, EntityType.CREDIT_CARD,
}


@pytest.fixture(scope="module")
def postal_sdk():
    """Module-scoped SDK — country configs compile once for all cases."""
    return EuRedact()


def _postals(sdk, text, country):
    result = sdk.redact(text, countries=[country])
    return [d.text for d in result.detections if d.entity_type == EntityType.POSTAL_CODE]


def _in_address_doc(snippet: str) -> str:
    """Put a snippet in a document that carries a real Austrian address.

    The address satisfies the postal context gate, which is what makes these
    documents reproduce the corpus behaviour: in isolation the snippets are
    already rejected for lack of context, and the bug would not show.
    """
    return f"Anschrift: Hauptstrasse 5, 1010 Wien\n{snippet}\n"


# ═══════════════════════════════════════════════════════════════════════
# SHREDDING — digits belonging to a longer identifier. Only the genuine
# address code (1010) may be claimed.
# ═══════════════════════════════════════════════════════════════════════

SHRED_CASES = [
    # --- the brief's must-not-match vectors ---
    ("sh-svnr", "SV-Nummer: 1268 040390"),
    ("sh-svnr-bad-checksum", "SV-Nummer: 1268 040391"),
    ("sh-policy-number", "Policen-Nr. 0456.2398.71-02"),
    ("sh-ecard", "e-card Nr. 1234 5678 925"),
    ("sh-phone-intl", "Telefon: +43 664 8213 907"),
    ("sh-service-number", "Sachbearbeiter: Huber, DiNr. 4471"),
    ("sh-numeral-in-prose", "Die Abteilung Kardiologie hat 2140 1.912 Patientinnen behandelt."),
    # --- glued by identifier punctuation ---
    ("sh-slash-groups", "Rechnung 2025/4471/02"),
    ("sh-hyphen-groups", "Seriennummer 7788-9900"),
    ("sh-dot-groups", "Konto 1234.5678"),
    ("sh-underscore-groups", "Referenz 1234_5678"),
    ("sh-slash-units", "Messwert 4500/6000 U/min"),
    ("sh-mixed-separators", "Vorgang 3320-1188.02"),
    # --- a further digit group on the same line ---
    ("sh-two-groups", "Bestellnummer: 8899 0011"),
    ("sh-three-groups", "e-card Nr. 4455 6677 88"),
    ("sh-iban-digits", "IBAN AT61 1904 3002 3457 3201"),
    ("sh-phone-be", "GSM +32 475 1234 567"),
    # --- an identifier label introduces the digits ---
    ("sh-label-nr", "Polizze Nr. 5510"),
    ("sh-label-nummer", "Nummer 8080"),
    ("sh-label-degree", "Dossier N° 4471 in Bearbeitung"),
    ("sh-label-aktenzeichen", "Aktenzeichen 3320 beim Gericht"),
]

# ═══════════════════════════════════════════════════════════════════════
# ADDRESSES — must still be detected, unchanged.
# ═══════════════════════════════════════════════════════════════════════

ADDRESS_CASES = [
    ("ad-at-comma", "Kaerntner Strasse 12/3, 1010 Wien", "AT", ["1010"]),
    ("ad-be-comma", "Grote Markt 1, 2000 Antwerpen", "BE", ["2000"]),
    ("ad-ch-comma", "Bahnhofplatz 3, 5400 Baden", "CH", ["5400"]),
    ("ad-at-plz-label", "PLZ: 1010\nOrt: Wien", "AT", ["1010"]),
    # A postal code ending a sentence. The adjacency rule must treat "." as a
    # number separator ONLY when it joins two digit groups — an earlier
    # revision rejected every one of these, costing 18,977 true positives on
    # the 152,300-record evaluation set (POSTAL_CODE recall 96.2% -> 61.0%).
    ("ad-sentence-final-es", "Domicilio: Palma, 13867. Pagos a IBAN.", "ES", ["13867"]),
    ("ad-sentence-final-ch", "Adresse: Fribourg, 8386. Auszahlung folgt.", "CH", ["8386"]),
    ("ad-sentence-final-at", "Anschrift: Hauptstrasse 5, 1010 Wien.", "AT", ["1010"]),
    ("ad-comma-after", "Anschrift: Hauptstrasse 5, 1010 Wien, Oesterreich", "AT", ["1010"]),
    ("ad-paren-after", "Anschrift: Hauptstrasse 5, 1010 Wien (AT)", "AT", ["1010"]),
    ("ad-semicolon-after", "Anschrift: Hauptstrasse 5, 1010 Wien; Buero 3", "AT", ["1010"]),
    ("ad-de-five-digit", "Anschrift: Musterstrasse 5, 10115 Berlin", "DE", ["10115"]),
    ("ad-fr-five-digit", "Adresse: 12 rue de la Paix, 75002 Paris", "FR", ["75002"]),
    ("ad-dk", "Adresse: Vestergade 12, 8000 Aarhus", "DK", ["8000"]),
    ("ad-no", "Adresse: Storgata 5, 0155 Oslo", "NO", ["0155"]),
    ("ad-hu-comma", "Fo utca 3, 1052 Budapest", "HU", ["1052"]),
    ("ad-at-country-prefix", "Anschrift: A-1010 Wien", "AT", ["1010"]),
    ("ad-be-country-prefix", "Adres: B-2000 Antwerpen", "BE", ["2000"]),
    ("ad-de-country-prefix", "Anschrift: D-10115 Berlin", "DE", ["10115"]),
    ("ad-be-residence-prose", "De betrokkene is wonende te 2000 Antwerpen.", "BE", ["2000"]),
    ("ad-fr-residence-prose", "Le titulaire est domicilié à 1000 Bruxelles.", "BE", ["1000"]),
    # "st" (stuks/pieces) must not swallow the "St." of a place name.
    ("ad-ch-saint-placename", "Postal: 8386 St. Gallen", "CH", ["8386"]),
    (
        "ad-multiline-block",
        "Anschrift:\nHauptstrasse 5\n1010 Wien\nOesterreich",
        "AT",
        ["1010"],
    ),
    ("ad-at-wohnort", "Wohnort: 5020 Salzburg", "AT", ["5020"]),
    ("ad-ch-plz", "PLZ 8000 Zuerich", "CH", ["8000"]),
]

# ═══════════════════════════════════════════════════════════════════════
# STRUCTURED FORMS — not digits-only, so the adjacency rules never apply.
# ═══════════════════════════════════════════════════════════════════════

STRUCTURED_CASES = [
    ("st-nl-letters", "Postcode 1012 AB Amsterdam", "NL", ["1012 AB"]),
    ("st-nl-no-space", "Postcode 1012AB Amsterdam", "NL", ["1012AB"]),
    ("st-pt-hyphen", "Rua Augusta 10, 1100-048 Lisboa", "PT", ["1100-048"]),
    ("st-lu-prefix", "Adresse: L-1234 Luxembourg", "LU", ["L-1234"]),
    ("st-lu-prefix-space", "Adresse: L 1234 Luxembourg", "LU", ["L 1234"]),
]

# ═══════════════════════════════════════════════════════════════════════
# OVERLAP — POSTAL_CODE must never re-cut a structured detector's span.
# ═══════════════════════════════════════════════════════════════════════

OVERLAP_DOCS = [
    ("ov-svnr", "Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390", "AT"),
    ("ov-phone-at", "Anschrift: Hauptstrasse 5, 1010 Wien\nTelefon: +43 664 8213907", "AT"),
    ("ov-iban-at", "Anschrift: Hauptstrasse 5, 1010 Wien\nIBAN: AT61 1904 3002 3457 3201", "AT"),
    ("ov-iban-be", "Adres: Grote Markt 1, 2000 Antwerpen\nIBAN: BE68 5390 0754 7034", "BE"),
    ("ov-vat-at", "Anschrift: Hauptstrasse 5, 1010 Wien\nUID: ATU12345675", "AT"),
    ("ov-bsn-nl", "Postcode 1012 AB Amsterdam\nBSN 111222333", "NL"),
    ("ov-credit-card", "Anschrift: Hauptstrasse 5, 1010 Wien\nKarte 4111 1111 1111 1111", "AT"),
]


# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "snippet", [pytest.param(s, id=i) for i, s in SHRED_CASES]
)
def test_identifier_digits_are_not_claimed(postal_sdk, snippet):
    """Only the genuine address code is claimed; the identifier stays whole."""
    doc = _in_address_doc(snippet)
    assert _postals(postal_sdk, doc, "AT") == ["1010"]


@pytest.mark.parametrize(
    "text,country,expected",
    [pytest.param(t, c, e, id=i) for i, t, c, e in ADDRESS_CASES],
)
def test_address_postal_codes_still_detected(postal_sdk, text, country, expected):
    assert _postals(postal_sdk, text, country) == expected


@pytest.mark.parametrize(
    "text,country,expected",
    [pytest.param(t, c, e, id=i) for i, t, c, e in STRUCTURED_CASES],
)
def test_structured_postal_forms_unaffected(postal_sdk, text, country, expected):
    assert _postals(postal_sdk, text, country) == expected


@pytest.mark.parametrize(
    "text,country", [pytest.param(t, c, id=i) for i, t, c in OVERLAP_DOCS]
)
def test_postal_never_overlaps_structured_span(postal_sdk, text, country):
    """Acceptance criterion 5: no POSTAL_CODE span overlaps PHONE, SSN,
    NATIONAL_ID, HEALTH_INSURANCE, IBAN, VAT or card spans."""
    dets = postal_sdk.redact(text, countries=[country]).detections
    postals = [d for d in dets if d.entity_type == EntityType.POSTAL_CODE]
    structured = [d for d in dets if d.entity_type in _STRUCTURED]
    for p in postals:
        for s in structured:
            assert p.end <= s.start or p.start >= s.end, (
                f"POSTAL_CODE {p.text!r} overlaps {s.entity_type.value} {s.text!r}"
            )


def test_svnr_stays_whole_and_labelled():
    """The regression that motivated this: an Austrian SVNr must not be cut in
    half, leaving a partial social security number in the redacted body."""
    sdk = EuRedact()
    doc = "Anschrift: Hauptstrasse 5, 1010 Wien\nSV-Nummer: 1268 040390\n"
    result = sdk.redact(doc, countries=["AT"])
    assert "040390" not in result.redacted_text
    assert "[NATIONAL_ID]" in result.redacted_text


def test_phone_digits_not_split_by_postal():
    """A dialling prefix owns the digits that follow it."""
    sdk = EuRedact()
    doc = "Anschrift: Hauptstrasse 5, 1010 Wien\nTelefon: +43 664 8213 907\n"
    result = sdk.redact(doc, countries=["AT"])
    assert "[POSTAL_CODE] 907" not in result.redacted_text
