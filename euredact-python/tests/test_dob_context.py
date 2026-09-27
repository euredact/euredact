"""The DOB keyword list, and the hazard that comes with widening it.

DOB recall was 62.8% -- 33,441 unmasked birth dates, the largest recall gap in
the evaluation -- because the context list covered seven languages of
thirty-one. Eleven countries scored exactly 100% and twenty sat at 42-51%,
which is what showed the pattern and the date formats were already right
(rules-engine#38).

Context matching is **substring**, not word-boundary. That is what makes a
keyword list a liability as well as an asset: a short entry fires inside an
unrelated word and licenses every date near it. These tests are the screen.
"""

from __future__ import annotations

import pytest

from euredact import EntityType, redact
from euredact.rules.countries._shared import DOB_CONTEXT

#: Words that must not contain a keyword. Each is a real string from the corpus
#: or a near miss found while screening.
HAZARDS = [
    "gabornagy",        # a Hungarian name as an e-mail local part -- contains "born"
    "gabornemeth",      # the same
    "airborne", "newborn", "stubborn", "borne", "Borneo",
    "reborn", "bornholm",
]


class TestNoKeywordHidesInsideAWord:
    @pytest.mark.parametrize("hazard", HAZARDS)
    def test_a_hazard_word_contains_no_keyword(self, hazard: str) -> None:
        hit = [k for k in DOB_CONTEXT if k.strip() and k.lower() in hazard.lower()]
        # "born " survives because of its trailing space; bare "born" would not.
        assert hit == [], f"{hazard!r} contains DOB keyword(s) {hit}"

    def test_bare_born_is_not_listed(self) -> None:
        # The screen found "born" inside gabornagy/gabornemeth. The trailing
        # space has 5,581 corpus hits and no embedded occurrences.
        assert "born" not in DOB_CONTEXT
        assert "born " in DOB_CONTEXT

    def test_the_rejected_icelandic_short_form_is_not_listed(self) -> None:
        assert "fædd" not in DOB_CONTEXT
        assert "fæddur" in DOB_CONTEXT

    @pytest.mark.parametrize("keyword", DOB_CONTEXT)
    def test_every_keyword_is_long_enough_or_bounded(self, keyword: str) -> None:
        # A weak proxy, and deliberately so: the real evidence is the corpus
        # screen above, not a length. Three characters or fewer is only safe
        # when punctuation or a space bounds it ("DOB", "geb.", "geb ").
        #
        # Four is allowed because the Nordic forms "født" and "född" need it,
        # and both were screened clean over 29.2 million characters. Their only
        # embeddings are "fødte" and "födda" -- the plural and past tense of
        # "born", so a date beside either is still a birth date.
        bounded = keyword != keyword.strip() or not keyword.isalpha()
        assert len(keyword.strip()) >= 4 or bounded or keyword.isupper(), keyword


class TestBirthKeywordsAcrossLanguages:
    #: One document shape per language the corpus uses, with the country whose
    #: documents carry it. A removed keyword fails a *named* case here.
    CASES = [
        ("DK", "Sag vedrørende Camilla Pedersen, født 15/05/1994"),
        ("NO", "Sak vedrørende Per Olsen, født 14.08.1997"),
        ("SE", "Ärende för Anna Svensson, född 1958-04-23"),
        ("FI", "Asia koskien Mikko Korhonen, syntynyt 08.04.1994"),
        ("IS", "Mál varðandi Helga Einarsson, fæddur 12.06.1962"),
        ("EL", "Record: Maria Dimitriou, γεννηθείς/είσα 05/04/1965"),
        ("CY", "Record: Sophia Petrou, γεννηθείς/είσα 14/03/1970"),
        ("UK", "Record: Charlotte Smith, born 07/05/1980"),
        ("IE", "Record: Sean Murphy, born 11/02/1988"),
        ("MT", "Rekord: Maria Borg, twieled 12.06.1958"),
        ("IT", "Fascicolo di Anna Mancini, nato/a il 13/06/1994"),
        ("PL", "Sprawa: Jan Kowalski, urodzony 12.06.1958"),
        ("CZ", "Vec: Jan Novak, narozen 12.06.1958"),
        ("SK", "Vec: Jan Novak, narodený 12.06.1958"),
        ("HU", "Ügy: Nagy Gabor, született 12.06.1958"),
        ("RO", "Caz: Ion Popescu, născut 12.06.1958"),
        ("BG", "Дело: Иван Петров, роден 12.06.1958"),
        ("HR", "Predmet: Ivan Horvat, rođen 12.06.1958"),
        ("SI", "Zadeva: Janez Novak, rojen 12.06.1958"),
        ("EE", "Asi: Jaan Tamm, sündinud 12.06.1958"),
        ("LV", "Lieta: Janis Berzins, dzimis 12.06.1958"),
        ("LT", "Byla: Jonas Petraitis, gimęs 12.06.1958"),
        ("DE", "Sache betreffend Hans Meyer, geboren 14.08.1997"),
        ("NL", "Betreft Jan de Vries, geboren 14-08-1997"),
    ]

    @pytest.mark.parametrize(("country", "text"), CASES, ids=[c for c, _ in CASES])
    def test_the_birth_date_is_detected(self, country: str, text: str) -> None:
        found = [
            d.text for d in redact(text, countries=[country], detect_dates=True).detections
            if d.entity_type == EntityType.DOB
        ]
        assert len(found) == 1, f"{country}: expected one DOB, got {found}"


class TestTheTwoDateFormatsShareOneList:
    """The ISO list was a second, shorter copy. That divergence is the bug."""

    @pytest.mark.parametrize("text", [
        "Sak vedrørende Per Olsen, født 14.08.1997",   # DD.MM.YYYY
        "Sak vedrørende Per Olsen, født 1997-08-14",   # ISO
    ])
    def test_both_formats_accept_the_same_keyword(self, text: str) -> None:
        found = [d for d in redact(text, countries=["NO"], detect_dates=True).detections
                 if d.entity_type == EntityType.DOB]
        assert len(found) == 1, text

    @pytest.mark.parametrize("text", [
        "Fascicolo di Anna Mancini, nato il 13/06/1994",
        "Fascicolo di Anna Mancini, nato il 1994-06-13",
    ])
    def test_an_entry_the_iso_list_used_to_lack(self, text: str) -> None:
        found = [d for d in redact(text, countries=["IT"], detect_dates=True).detections
                 if d.entity_type == EntityType.DOB]
        assert len(found) == 1, text


class TestDatesWithoutABirthLabelAreNotBirthDates:
    @pytest.mark.parametrize("text", [
        "Het contract is ondertekend op 14-08-1997.",
        "Invoice dated 07/05/1980, due 30 days.",
        "Rapport van 1997-08-14 bijgevoegd.",
    ])
    def test_a_bare_date_is_not_a_dob(self, text: str) -> None:
        found = [d for d in redact(text, countries=["NL"], detect_dates=True).detections
                 if d.entity_type == EntityType.DOB]
        assert found == [], text
