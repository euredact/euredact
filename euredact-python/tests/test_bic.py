"""BIC detection test data — tier 1, tier 2, gate 0 and gate 2.

BIC has no check digit, so ISO 9362 structure alone cannot decide a match:
characters 5-6 of ordinary uppercase words are frequently valid ISO 3166
country codes (``DRINGEND`` -> ``GE``, ``HOSPITAL`` -> ``IT``). Detection is
therefore gated:

* **gate 0** — the token also occurs as an ordinary lowercase word in the same
  document -> never a bank code, outranks every tier below;
* **tier 1** — registry hit on the BIC6 institution+country prefix -> emit;
* **gate 2** — heading / shouted-word shape -> reject;
* **tier 2** — BIC/SWIFT keyword, IBAN or bank block in the enclosing line,
  record or paragraph -> emit;
* otherwise -> never emit.

Every case below is a document plus the exact set of BIC values expected from
it. Codes used in the tier 2 cases are deliberately *not* in the bundled seed
registry, so they can only be detected through context — that is what keeps
these cases honest.
"""

import pytest

from euredact.sdk import EuRedact
from euredact.types import EntityType


@pytest.fixture(scope="module")
def bic_sdk():
    """Module-scoped SDK — country configs compile once for every case."""
    return EuRedact()


def _bics(sdk, text, country):
    result = sdk.redact(text, countries=[country])
    return [d.text for d in result.detections if d.entity_type == EntityType.BIC]


# ═══════════════════════════════════════════════════════════════════════
# TIER 1 — registry hit. Detected with no banking context at all.
# ═══════════════════════════════════════════════════════════════════════

TIER1_CASES = [
    # --- bare BIC8, one per major institution ---
    ("t1-abnanl", "ABNANL2A", "NL", ["ABNANL2A"]),
    ("t1-ingbnl", "INGBNL2A", "NL", ["INGBNL2A"]),
    ("t1-rabonl", "RABONL2U", "NL", ["RABONL2U"]),
    ("t1-bbrube", "BBRUBEBB", "BE", ["BBRUBEBB"]),
    ("t1-kredbe", "KREDBEBB", "BE", ["KREDBEBB"]),
    ("t1-arspbe", "ARSPBE22", "BE", ["ARSPBE22"]),
    ("t1-bceelu", "BCEELULL", "LU", ["BCEELULL"]),
    ("t1-deutde", "DEUTDEFF", "DE", ["DEUTDEFF"]),
    ("t1-sogefr", "SOGEFRPP", "FR", ["SOGEFRPP"]),
    ("t1-bkauat", "BKAUATWW", "AT", ["BKAUATWW"]),
    ("t1-aibkie", "AIBKIE2D", "IE", ["AIBKIE2D"]),
    ("t1-barcgb", "BARCGB22", "UK", ["BARCGB22"]),
    ("t1-revogb", "REVOGB2L", "UK", ["REVOGB2L"]),
    ("t1-ndeadk", "NDEADKKK", "DK", ["NDEADKKK"]),
    # --- bare BIC11: institution + country + location + branch ---
    ("t1-bnpafr-11", "BNPAFRPPXXX", "FR", ["BNPAFRPPXXX"]),
    ("t1-gibaat-11", "GIBAATWWXXX", "AT", ["GIBAATWWXXX"]),
    ("t1-deutde-11", "DEUTDEFFXXX", "DE", ["DEUTDEFFXXX"]),
    ("t1-cobade-11", "COBADEFFXXX", "DE", ["COBADEFFXXX"]),
    # --- synthetic branch codes on a known prefix: the generated-corpus case.
    #     Tier 1 matches on the prefix, so fabricated suffixes stay detectable
    #     without the engine knowing any real branch code.
    ("t1-synthetic-abna", "ABNANL9X", "NL", ["ABNANL9X"]),
    ("t1-synthetic-ingb", "INGBNL7Q", "NL", ["INGBNL7Q"]),
    ("t1-synthetic-bunq", "BUNQNL4T", "NL", ["BUNQNL4T"]),
    ("t1-synthetic-trio", "TRIONL3M", "NL", ["TRIONL3M"]),
    ("t1-synthetic-rabo-11", "RABONL2UGRA", "NL", ["RABONL2UGRA"]),
    # --- registry hit inside running prose, no banking cue nearby ---
    ("t1-in-prose", "De overboeking liep via ABNANL2A en kwam maandag aan.", "NL", ["ABNANL2A"]),
    ("t1-in-prose-de", "Die Zahlung wurde ueber DEUTDEFF abgewickelt.", "DE", ["DEUTDEFF"]),
    ("t1-in-sentence-fr", "Le virement est passe par SOGEFRPP hier soir.", "FR", ["SOGEFRPP"]),
    # --- gate 0 must not fire on email/domain occurrences of the lowercase
    #     form: a domain is not a word, so tier 1 still applies.
    ("t1-domain-not-word", "DEUTDEFF\nSupport: helpdesk@deutdeff.example.com", "DE", ["DEUTDEFF"]),
    ("t1-email-local-not-word", "DEUTDEFF\nMail naar deutdeff@example.com voor vragen.", "DE", ["DEUTDEFF"]),
    # --- tier 1 survives a heading-shaped position (gate 2 runs after it) ---
    ("t1-beats-heading-colon", "BBRUBEBB: correspondentbank", "BE", ["BBRUBEBB"]),
    ("t1-beats-allcaps-line", "BETALING VIA KREDBEBB VANDAAG", "BE", ["KREDBEBB"]),
]

# ═══════════════════════════════════════════════════════════════════════
# TIER 2 — no registry hit. Detected only via banking context in the
# enclosing line, record or paragraph.
# ═══════════════════════════════════════════════════════════════════════

TIER2_CASES = [
    # --- the brief's must-still-match vectors ---
    ("t2-brief-iban-bic", "IBAN: BE68 5390 0754 7034 - BIC: GEBABEBB", "BE", ["GEBABEBB"]),
    (
        "t2-brief-swift-code",
        "Kontonummer AT61 1904 3002 3457 3201, SWIFT-Code: GIBAATWWXXX",
        "AT",
        ["GIBAATWWXXX"],
    ),
    # --- every keyword spelling, on non-registry institutions ---
    ("t2-kw-bic", "BIC: VOLKNL2A", "NL", ["VOLKNL2A"]),
    ("t2-kw-swift", "SWIFT: ZWCBDEFF", "DE", ["ZWCBDEFF"]),
    ("t2-kw-swift-code", "SWIFT-Code: MEDBFRPP", "FR", ["MEDBFRPP"]),
    ("t2-kw-bic-swift", "BIC/SWIFT: LOCABE22", "BE", ["LOCABE22"]),
    ("t2-kw-code-swift", "Code SWIFT : KARTATWW", "FR", ["KARTATWW"]),
    ("t2-kw-bic-code", "BIC-code: FIDULULL", "LU", ["FIDULULL"]),
    ("t2-kw-swift-bic", "SWIFT-BIC: NEOBIE2X", "IE", ["NEOBIE2X"]),
    ("t2-kw-lowercase", "swift code: ATLAGB22", "UK", ["ATLAGB22"]),
    # --- label on its own line, value on the next (table / column layout) ---
    ("t2-label-above", "BIC\nVIKKDKKK", "DK", ["VIKKDKKK"]),
    ("t2-label-above-colon", "SWIFT-Code:\nPRIMITMM", "IT", ["PRIMITMM"]),
    # --- an IBAN in the same line vouches for the code ---
    (
        "t2-iban-same-line",
        "Overboeking naar NL91 ABNA 0417 1643 00 via SOLAESMM.",
        "NL",
        ["SOLAESMM"],
    ),
    (
        "t2-iban-same-line-fr",
        "Virement sur FR76 3000 6000 0112 3456 7890 189 aupres de ORIOPL2P.",
        "FR",
        ["ORIOPL2P"],
    ),
    # --- an IBAN on an adjacent line of the same paragraph ---
    (
        "t2-iban-adjacent-line",
        "Betaalgegevens\nIBAN: NL91 ABNA 0417 1643 00\nCorrespondentbank MERKCZPP.",
        "NL",
        ["MERKCZPP"],
    ),
    (
        "t2-iban-line-above",
        "Konto: DE89 3704 0044 0532 0130 00\nDie Gegenstelle nutzt ADRISK22.",
        "DE",
        ["ADRISK22"],
    ),
    # --- the cue sits several lines away in the same record: this is the case
    #     a +/-45 character window loses (316 real codes on the corpus).
    (
        "t2-cue-far-in-paragraph",
        "Overzicht van de betaling\n"
        "IBAN: NL91 ABNA 0417 1643 00\n"
        "Bedrag: 1.250,00 EUR\n"
        "Referentie: FACT-2025-0031\n"
        "De tegenpartij gebruikt BOREHU2B voor internationale overboekingen.",
        "NL",
        ["BOREHU2B"],
    ),
    (
        "t2-csv-record",
        "('POL-2025-44871', 'BE41 0689 3847 2951', '', 'ALPICH22')",
        "BE",
        ["ALPICH22"],
    ),
    (
        "t2-csv-header-row",
        "polis,iban,bic\nPOL-9912,BE41 0689 3847 2951,FJORNO2N",
        "BE",
        ["FJORNO2N"],
    ),
    # --- structured bank-details blocks, several languages ---
    (
        "t2-block-bankverbindung",
        "Bankverbindung\nKontoinhaber: M. Bauer\nCode: LAKESE2S",
        "DE",
        ["LAKESE2S"],
    ),
    ("t2-block-kontonummer", "Kontonummer 1904 3002, TAIGFI2F", "AT", ["TAIGFI2F"]),
    (
        "t2-block-rekeningnummer",
        "Rekeningnummer van de begunstigde: MISTIS2I",
        "NL",
        ["MISTIS2I"],
    ),
    ("t2-block-compte", "Compte de la societe: HAVNFRPP", "FR", ["HAVNFRPP"]),
    (
        "t2-block-coordonnees",
        "Coordonnees bancaires du beneficiaire: RIVEBE22",
        "BE",
        ["RIVEBE22"],
    ),
    ("t2-block-account-number", "Account number and code: TERNGB22", "UK", ["TERNGB22"]),
    ("t2-block-bankgegevens", "Bankgegevens van de leverancier: DUINNL2A", "NL", ["DUINNL2A"]),
    ("t2-block-zahlungsdaten", "Zahlungsdaten der Gegenstelle: HAINDEFF", "DE", ["HAINDEFF"]),
    ("t2-block-bankleitzahl", "Bankleitzahl 12030000, Code MOORDEFF", "DE", ["MOORDEFF"]),
    # --- 11-character forms through the context gate ---
    ("t2-eleven-char", "BIC: STEINL2AXXX", "NL", ["STEINL2AXXX"]),
    # --- two codes in one bank block, both emitted ---
    (
        "t2-two-codes",
        "Bankverbindung\nBIC Bank A: WOLKDEFF\nBIC Bank B: NEBLDEFF",
        "DE",
        ["WOLKDEFF", "NEBLDEFF"],
    ),
]

# ═══════════════════════════════════════════════════════════════════════
# GATE 0 — the token also occurs as an ordinary lowercase word in the same
# document. Never a bank code, even with banking context right next to it.
# ═══════════════════════════════════════════════════════════════════════

GATE0_CASES = [
    (
        "g0-gegevens",
        "GEGEVENS\nIBAN: NL91 ABNA 0417 1643 00\nDeze gegevens zijn vertrouwelijk.",
        "NL",
    ),
    (
        "g0-hospital",
        "QUEEN ELIZABETH HOSPITAL BIRMINGHAM\n"
        "IBAN: GB33 BUKB 2020 1555 5555 55\n"
        "The hospital confirmed the transfer.",
        "UK",
    ),
    (
        "g0-dringend",
        "DRINGEND\nBIC/SWIFT wird nachgereicht.\nDie Zahlung ist dringend.",
        "DE",
    ),
    (
        "g0-maandelijks",
        "MAANDELIJKS\nBIC: onbekend\nDe incasso loopt maandelijks door.",
        "NL",
    ),
    (
        "g0-beneficiary",
        "BENEFICIARY\nIBAN: GB33 BUKB 2020 1555 5555 55\n"
        "The beneficiary account has been closed.",
        "UK",
    ),
    (
        "g0-customer",
        "CUSTOMER\nSWIFT details follow.\nEach customer was notified.",
        "UK",
    ),
    (
        "g0-personal",
        "PERSONAL\nBankverbindung folgt.\nAll personal data was removed.",
        "UK",
    ),
    (
        "g0-diagnose",
        "DIAGNOSE\nKontonummer 1904 3002\nDie diagnose wurde bestaetigt.",
        "DE",
    ),
    (
        "g0-anamnese",
        "ANAMNESE\nSWIFT-Code folgt spaeter.\nDie anamnese ist unauffaellig.",
        "DE",
    ),
    (
        "g0-nachname",
        "NACHNAME\nBIC: siehe Anlage\nBitte nachname und Vorname angeben.",
        "DE",
    ),
    (
        "g0-helpdesk",
        "HELPDESK\nIBAN: NL91 ABNA 0417 1643 00\nDe helpdesk is bereikbaar tot 17u.",
        "NL",
    ),
    (
        "g0-incident",
        "INCIDENT\nBIC ontbreekt.\nHet incident is gesloten.",
        "NL",
    ),
    (
        "g0-paiement",
        "PAIEMENT\nCoordonnees bancaires ci-dessous.\nLe paiement a ete recu.",
        "FR",
    ),
    (
        "g0-fournisseur",
        "FOURNISSEUR\nCompte: FR76 3000 6000 0112 3456 7890 189\n"
        "Le fournisseur a ete paye.",
        "FR",
    ),
    (
        "g0-referenties",
        "REFERENTIES\nBankgegevens volgen.\nDe referenties zijn nagekeken.",
        "NL",
    ),
    (
        "g0-conclusions",
        "CONCLUSIONS\nSWIFT: a confirmer\nLes conclusions sont jointes.",
        "FR",
    ),
    (
        "g0-automatique",
        "AUTOMATIQUE\nBIC: a completer\nLe prelevement automatique est actif.",
        "FR",
    ),
    (
        "g0-supplier",
        "SUPPLIER\nIBAN: GB33 BUKB 2020 1555 5555 55\nThe supplier was replaced.",
        "UK",
    ),
    (
        "g0-findings",
        "FINDINGS\nBIC on file.\nThe findings were shared with the board.",
        "UK",
    ),
    # Capitalised (not just lowercase) forms count as ordinary word use too.
    (
        "g0-capitalised-form",
        "ACTIVITY\nSWIFT details on file.\nActivity on the account resumed in May.",
        "UK",
    ),
]

# ═══════════════════════════════════════════════════════════════════════
# GATE 2 — heading and shouted-word shapes. Structurally valid, no
# registry hit, no lowercase form anywhere in the document.
# ═══════════════════════════════════════════════════════════════════════

GATE2_CASES = [
    # token is the whole line
    ("g2-bare-nexalink", "NEXALINK", "NL"),
    ("g2-bare-arbeitgeber", "ARBEITGEBER", "DE"),
    ("g2-bare-arbeitszeit", "ARBEITSZEIT", "DE"),
    ("g2-bare-hospital", "HOSPITAL", "UK"),
    # token starts its line and is followed by a colon
    ("g2-colon-dringend", "DRINGEND: Frau Yilmaz ist verantwortlich.", "DE"),
    ("g2-colon-arbeitszeit", "ARBEITSZEIT: 38,5 Stunden pro Woche", "DE"),
    ("g2-colon-customer", "CUSTOMER: Northwind Ltd", "UK"),
    ("g2-colon-diagnose", "DIAGNOSE: Fraktur des Radius", "DE"),
    # shouted line: no lowercase, no digits, no banking keyword
    ("g2-allcaps-hospital", "QUEEN ELIZABETH HOSPITAL BIRMINGHAM", "UK"),
    ("g2-allcaps-gegevens", "GEGEVENS VAN DE BETROKKENE", "NL"),
    ("g2-allcaps-personal", "PERSONAL DATA PROTECTION NOTICE", "UK"),
    ("g2-allcaps-findings", "FINDINGS AND RECOMMENDATIONS", "UK"),
    ("g2-allcaps-nachname", "NACHNAME UND VORNAME DES ANTRAGSTELLERS", "DE"),
]

# ═══════════════════════════════════════════════════════════════════════
# NO TIER — structurally valid, mid-sentence (so not a heading), no
# registry hit and no banking context. Never emitted.
# ═══════════════════════════════════════════════════════════════════════

NO_TIER_CASES = [
    ("nt-project-name", "Das Projekt NEXALINK wurde im Maerz gestartet.", "DE"),
    ("nt-department", "De afdeling KARTATWW werd vorig jaar opgeheven.", "NL"),
    ("nt-shouted-mid-sentence", "Der Vermerk ARBEITGEBER stand oben auf dem Formular.", "DE"),
    ("nt-no-cue-paragraph", "Verslag van de vergadering\nHet dossier VIKKDKKK is gesloten.", "NL"),
    (
        "nt-cue-in-other-paragraph",
        "IBAN: NL91 ABNA 0417 1643 00\n\nBijlage B\nDe code MERKCZPP hoort bij een oud dossier.",
        "NL",
    ),
    ("nt-invoice-context-only", "Factuurnummer 2025-0031, dossier PRIMITMM afgesloten.", "NL"),
    ("nt-address-context-only", "Kantoor SOLAESMM, Grote Markt 1, 2000 Antwerpen.", "BE"),
]


# ═══════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "text,country,expected",
    [pytest.param(t, c, e, id=i) for i, t, c, e in TIER1_CASES],
)
def test_tier1_registry_hit_is_detected(bic_sdk, text, country, expected):
    """Tier 1: a known institution prefix is emitted without any context."""
    assert _bics(bic_sdk, text, country) == expected


@pytest.mark.parametrize(
    "text,country,expected",
    [pytest.param(t, c, e, id=i) for i, t, c, e in TIER2_CASES],
)
def test_tier2_context_gate_is_detected(bic_sdk, text, country, expected):
    """Tier 2: a non-registry code is emitted on banking context in its unit."""
    assert _bics(bic_sdk, text, country) == expected


@pytest.mark.parametrize(
    "text,country",
    [pytest.param(t, c, id=i) for i, t, c in GATE0_CASES],
)
def test_gate0_lowercase_word_is_rejected(bic_sdk, text, country):
    """Gate 0: a token that is also an ordinary word is never a bank code —
    even with an IBAN or a BIC keyword sitting right beside it."""
    assert _bics(bic_sdk, text, country) == []


@pytest.mark.parametrize(
    "text,country",
    [pytest.param(t, c, id=i) for i, t, c in GATE2_CASES],
)
def test_gate2_heading_shape_is_rejected(bic_sdk, text, country):
    """Gate 2: headings and shouted words are never bank codes."""
    assert _bics(bic_sdk, text, country) == []


@pytest.mark.parametrize(
    "text,country",
    [pytest.param(t, c, id=i) for i, t, c in NO_TIER_CASES],
)
def test_no_tier_bare_shape_is_rejected(bic_sdk, text, country):
    """A bare shape match with neither a registry hit nor context is dropped."""
    assert _bics(bic_sdk, text, country) == []


def test_case_count():
    """The BIC data set started at 100 entries. This is a floor, not a target —
    add cases freely; the assertion only guards against silent deletion."""
    total = (
        len(TIER1_CASES)
        + len(TIER2_CASES)
        + len(GATE0_CASES)
        + len(GATE2_CASES)
        + len(NO_TIER_CASES)
    )
    assert total >= 100


def test_case_ids_are_unique():
    ids = (
        [c[0] for c in TIER1_CASES]
        + [c[0] for c in TIER2_CASES]
        + [c[0] for c in GATE0_CASES]
        + [c[0] for c in GATE2_CASES]
        + [c[0] for c in NO_TIER_CASES]
    )
    assert len(ids) == len(set(ids))
