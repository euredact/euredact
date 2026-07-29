"""Country inference: what the engine concludes about a document, and why.

Inference influences which national scheme owns an ambiguous value. It never
influences which spans are found — that is
``tests/test_invariant_generation.py``, and it is the invariant that matters.
"""

import pytest

from euredact.rules.evidence import WEIGHTS, weights_to_ranking
from euredact.sdk import EuRedact
from euredact.types import EntityType

# 0612345678 is a valid Dutch mobile number AND passes the Danish CPR checksum.
# Which one it is cannot be decided from the digits — only from the document.
AMBIGUOUS = "0612345678"


@pytest.fixture(scope="module")
def sdk():
    return EuRedact()


def _types(result):
    return {(d.entity_type, d.country) for d in result.detections}


class TestAmbiguityResolvedByDocument:
    def test_dutch_document_yields_a_dutch_phone(self, sdk):
        r = sdk.redact(f"Bereikbaar op telefoon {AMBIGUOUS}, mail jan@test.nl",
                       cache=False)
        assert (EntityType.PHONE, "NL") in _types(r)

    def test_danish_document_yields_a_danish_national_id(self, sdk):
        r = sdk.redact(f"Kontakt: {AMBIGUOUS}, e-mail jens@test.dk", cache=False)
        assert (EntityType.NATIONAL_ID, "DK") in _types(r)

    def test_same_digits_either_way(self, sdk):
        """The span is identical; only the attribution moves."""
        nl = sdk.redact(f"telefoon {AMBIGUOUS}, mail jan@test.nl", cache=False)
        dk = sdk.redact(f"kontakt {AMBIGUOUS}, e-mail jens@test.dk", cache=False)
        assert AMBIGUOUS not in nl.redacted_text
        assert AMBIGUOUS not in dk.redacted_text


class TestForeignChecksumDoesNotWin:
    def test_swedish_phone_is_not_a_danish_national_id(self, sdk):
        """0708787668 passes the Danish CPR checksum and fails the Swedish
        personnummer one. Neither fact makes it stop being a Swedish phone."""
        r = sdk.redact("Telefon: 0708787668", countries=["SE"], cache=False)
        assert (EntityType.PHONE, "SE") in _types(r)

    def test_failed_checksum_does_not_demote_a_different_type(self, sdk):
        """A failed personnummer is evidence against NATIONAL_ID, not against
        the span. It must not cost the PHONE candidate its rank."""
        r = sdk.redact("Telefon: 0708787668", country_hint=["SE"], cache=False)
        assert (EntityType.PHONE, "SE") in _types(r)


class TestEvidenceIsAuditable:
    def test_every_inference_traces_to_a_span(self, sdk):
        text = ("IBAN NL91ABNA0417164300, BTW NL123456789B01, "
                "tel +31 6 12345678, mail info@jansen.nl")
        r = sdk.redact(text, cache=False)
        assert {e.source for e in r.evidence} == {
            "iban_prefix", "vat_prefix", "e164_prefix", "email_tld"}
        for e in r.evidence:
            assert e.country == "NL"
            assert text[e.span[0]:e.span[1]], "evidence must point at real text"

    def test_no_evidence_no_inference(self, sdk):
        r = sdk.redact("geen pii hier", cache=False)
        assert r.inferred_countries == ()
        assert r.evidence == ()

    def test_cross_border_reports_both_countries(self, sdk):
        """Confidences are per-country, not a softmax: a Dutch invoice with a
        German contact is genuinely both, and reporting DE at 0.00 would make
        cross-border documents look like misattributions."""
        r = sdk.redact("IBAN NL91ABNA0417164300, tel +49 30 123456", cache=False)
        found = dict(r.inferred_countries)
        assert set(found) == {"NL", "DE"}
        assert all(v > 0.5 for v in found.values())

    def test_confidence_is_zero_when_only_a_checksum_supports_it(self, sdk):
        """The signal that an attribution rests on nothing but the digits."""
        r = sdk.redact("Nummer: 0708787668", cache=False)
        assert [d.country_confidence for d in r.detections] == [0.0]


class TestScopeVersusPrior:
    def test_hint_resolves_without_narrowing_scope(self, sdk):
        r = sdk.redact("Telefon: 0708787668", country_hint=["SE"], cache=False)
        assert r.detection_mode == "inferred"
        assert not any(d.out_of_scope for d in r.detections)

    def test_countries_declares_and_flags(self, sdk):
        r = sdk.redact("Telefon: 0708787668", countries=["SE"], cache=False)
        assert r.detection_mode == "declared"

    def test_out_of_scope_is_flagged_not_dropped(self, sdk):
        r = sdk.redact("Werknemer met BSN 111222333", countries=["BE"], cache=False)
        assert r.detections and all(d.out_of_scope for d in r.detections)

    def test_hint_and_declaration_agree_on_attribution(self, sdk):
        a = sdk.redact("Telefon: 0708787668", countries=["SE"], cache=False)
        b = sdk.redact("Telefon: 0708787668", country_hint=["SE"], cache=False)
        assert _types(a) == _types(b)


class TestCacheKeying:
    def test_hint_is_part_of_the_cache_key(self, sdk):
        """Attribution depends on the hint, so a cached result must not be
        reused across different hints."""
        text = f"Nummer: {AMBIGUOUS}"
        se = sdk.redact(text, country_hint=["SE"], cache=True)
        dk = sdk.redact(text, country_hint=["DK"], cache=True)
        assert _types(se) != _types(dk) or se.detections == dk.detections


class TestRanking:
    def test_confidences_do_not_sum_to_one(self):
        """Document countries are not mutually exclusive."""
        r = weights_to_ranking({"NL": 4.0, "DE": 4.0})
        assert r["NL"] == pytest.approx(r["DE"])
        assert sum(r.values()) > 1.0

    def test_weights_are_capped(self):
        """Synthetic certainty must stay falsifiable — a single phone number
        cannot be made unbeatable by any amount of contrary evidence."""
        assert WEIGHTS["e164_prefix"] <= 4.0
        assert WEIGHTS["iban_prefix"] < WEIGHTS["email_tld"]
