"""Benchmark Microsoft Presidio over the euRedact corpus.

Scored by the same rule euRedact is scored by in `tests/metrics.py`: a label
counts as found only when a detection overlaps its span *and* the detected type
satisfies the label's category. Everything below is an attempt to give Presidio
its best configuration using only what ships with the library.

Three deliberate choices, each of which favours Presidio:

1. **Country-specific recognizers are registered explicitly.** Presidio ships
   DE_*, SE_*, FI_* and UK_* recognizers but its `default_recognizers.yaml`
   does not load them; only the ES/IT/PL ones are wired up. Running the default
   config would have scored Presidio far below what it can do.

2. **Each document is analysed in its own language**, derived from the label's
   country, so the country-specific recognizers actually fire.

3. **NER is switched off** (blank spaCy pipelines, tokenizer only). The corpus
   labels no PERSON, LOCATION or ORGANIZATION, so NER could only manufacture
   false positives. Excluding it compares the pattern-and-validator layers,
   which is what euRedact is. It also makes the run tractable.

Correspondingly, a Presidio detection whose type maps to no corpus category
(PERSON, URL, NRP, ...) is ignored rather than charged as a false positive —
the same out-of-scope rule the corpus label audit used.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from collections import defaultdict
from pathlib import Path

warnings.filterwarnings("ignore")

import spacy  # noqa: E402
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry  # noqa: E402
from presidio_analyzer import predefined_recognizers as pre  # noqa: E402
from presidio_analyzer.nlp_engine import SpacyNlpEngine  # noqa: E402

#: Same override `euredact-python/tests/metrics.py` honours, so both engines are
#: pointed at the corpus the same way.
DATA_DIR = Path(os.environ.get(
    "EUREDACT_CORPUS",
    "/Users/jorenjanssens/Library/Mobile Documents/com~apple~CloudDocs/"
    "Werken/JNJS/Apps/PII-EuroMask/Data-Generation",
))

#: The same ten canonical datasets `tests/metrics.py` scores euRedact on, listed
#: rather than globbed so the `.bak` variant stays excluded.
DATASETS = [
    "euromask_allcountries_20k.json", "euromask_dach_south_20k.json",
    "euromask_eastern_20k.json", "euromask_el_cy_mt_20k.json",
    "euromask_ie_baltics_uk_20k.json", "euromask_international_10k.json",
    "euromask_nordic_20k.json", "euromask_secrets_5k.json",
    "euromask_training_core.json", "euromask_training_core2.json",
]

#: euRedact's own evaluation excludes these, so Presidio is scored on the same
#: set. Presidio *can* detect crypto addresses and euRedact cannot — that is a
#: genuine Presidio advantage, reported separately rather than folded into a
#: headline the other engine was never measured against.
EXCLUDED_CATEGORIES = {"CRYPTO_ADDRESS_BTC", "CRYPTO_ADDRESS_ETH"}
DOB_CATEGORIES = {"DOB"}

#: Country -> language. A document's language is not recorded in the corpus, so
#: it is taken from the country of its labels. For the multilingual countries
#: the majority language of the generator's templates is used.
COUNTRY_LANG = {
    "AT": "de", "BE": "nl", "BG": "bg", "CH": "de", "CY": "el", "CZ": "cs",
    "DE": "de", "DK": "da", "EE": "et", "EL": "el", "ES": "es", "FI": "fi",
    "FR": "fr", "HR": "hr", "HU": "hu", "IE": "en", "IS": "is", "IT": "it",
    "LT": "lt", "LU": "fr", "LV": "lv", "MT": "en", "NL": "nl", "NO": "nb",
    "PL": "pl", "PT": "pt", "RO": "ro", "SE": "sv", "SI": "sl", "SK": "sk",
    "UK": "en", "INTL": "en",
}

#: Presidio entity type -> corpus category. Types absent here are out of scope.
TYPE_MAP = {
    "EMAIL_ADDRESS": {"EMAIL"},
    "IBAN_CODE": {"IBAN"},
    "PHONE_NUMBER": {"PHONE"},
    "IP_ADDRESS": {"IP_ADDRESS", "IP_ADDRESS_V6"},
    "MAC_ADDRESS": {"MAC_ADDRESS"},
    "CREDIT_CARD": {"CREDIT_CARD"},
    "CRYPTO": {"CRYPTO_ADDRESS_BTC", "CRYPTO_ADDRESS_ETH"},
    "DATE_TIME": {"DOB", "DATE_OF_DEATH"},
    # national identifiers
    "ES_NIF": {"NATIONAL_ID", "TAX_ID_PERSONAL"},
    "ES_NIE": {"NATIONAL_ID"},
    "IT_FISCAL_CODE": {"NATIONAL_ID", "TAX_ID_PERSONAL"},
    "PL_PESEL": {"NATIONAL_ID"},
    "FI_PERSONAL_IDENTITY_CODE": {"NATIONAL_ID"},
    "SE_PERSONNUMMER": {"NATIONAL_ID"},
    "DE_ID_CARD": {"NATIONAL_ID", "NATIONAL_ID_CARD"},
    "UK_NINO": {"NATIONAL_ID"},
    "US_SSN": {"SOCIAL_SECURITY", "NATIONAL_ID"},
    "DE_SOCIAL_SECURITY": {"SOCIAL_SECURITY"},
    # tax / business
    "DE_TAX_ID": {"TAX_ID", "TAX_ID_PERSONAL"},
    "DE_TAX_NUMBER": {"TAX_ID", "TAX_ID_BUSINESS"},
    "DE_VAT_ID": {"VAT_NUMBER"},
    "IT_VAT_CODE": {"VAT_NUMBER"},
    "DE_HANDELSREGISTER": {"CHAMBER_OF_COMMERCE"},
    "SE_ORGANISATIONSNUMMER": {"CHAMBER_OF_COMMERCE"},
    # documents / health / vehicles
    "DE_PASSPORT": {"PASSPORT"}, "ES_PASSPORT": {"PASSPORT"},
    "IT_PASSPORT": {"PASSPORT"}, "UK_PASSPORT": {"PASSPORT"},
    "IT_IDENTITY_CARD": {"NATIONAL_ID_CARD"},
    "DE_HEALTH_INSURANCE": {"HEALTH_INSURANCE"},
    "UK_NHS": {"HEALTH_INSURANCE", "HEALTH_ID"},
    "DE_KFZ": {"LICENSE_PLATE"},
    "UK_VEHICLE_REGISTRATION": {"LICENSE_PLATE"},
    "DE_PLZ": {"POSTAL_CODE"},
    "UK_POSTCODE": {"POSTAL_CODE"},
}

#: Country recognizers that ship with Presidio but are missing from its default
#: configuration. Registered by hand so the comparison is against the library's
#: real capability rather than its default wiring.
EXTRA = {
    "de": ["DeTaxIdRecognizer", "DeTaxNumberRecognizer", "DeVatIdRecognizer",
           "DeIdCardRecognizer", "DePassportRecognizer", "DePlzRecognizer",
           "DeKfzRecognizer", "DeHealthInsuranceRecognizer",
           "DeSocialSecurityRecognizer", "DeHandelsregisterRecognizer",
           "DeFuehrerscheinRecognizer", "DeBsnrRecognizer", "DeLanrRecognizer"],
    "sv": ["SePersonnummerRecognizer", "SeOrganisationsnummerRecognizer"],
    "fi": ["FiPersonalIdentityCodeRecognizer"],
    "en": ["UkNinoRecognizer", "UkPostcodeRecognizer", "UkPassportRecognizer",
           "UkVehicleRegistrationRecognizer", "UkDrivingLicenceRecognizer"],
}


#: Trained pipelines, where spaCy publishes one for the language. Used only by
#: `--ner`. Languages absent here fall back to a blank pipeline in both modes,
#: so for those the two runs are identical by construction.
NER_MODELS = {
    "en": "en_core_web_lg", "de": "de_core_news_sm", "nl": "nl_core_news_sm",
    "fr": "fr_core_news_sm", "es": "es_core_news_sm", "it": "it_core_news_sm",
    "pt": "pt_core_news_sm", "pl": "pl_core_news_sm", "el": "el_core_news_sm",
    "da": "da_core_news_sm", "sv": "sv_core_news_sm", "nb": "nb_core_news_sm",
    "fi": "fi_core_news_sm", "ro": "ro_core_news_sm", "lt": "lt_core_news_sm",
    "hr": "hr_core_news_sm", "sl": "sl_core_news_sm",
}


class BlankNlp(SpacyNlpEngine):
    """Tokenizer-only pipelines. See the module docstring for why.

    With `ner=True`, loads the trained pipeline for every language that has one.
    That enables spaCy NER *and* — the reason this switch is interesting —
    Presidio's `LemmaContextAwareEnhancer`, which raises a pattern recognizer's
    confidence using surrounding lemmas. A blank pipeline produces no lemmas, so
    that enhancer cannot fire, and a borderline pattern match may sit below the
    acceptance threshold that a trained pipeline would have pushed above it.
    """

    def __init__(self, langs, ner=False):
        super().__init__(models=[{"lang_code": l, "model_name": "blank"} for l in langs])
        self.nlp = {}
        loaded = []
        for l in langs:
            if ner and l in NER_MODELS:
                try:
                    self.nlp[l] = spacy.load(NER_MODELS[l])
                    loaded.append(l)
                    continue
                except OSError:
                    pass
            self.nlp[l] = spacy.blank(l)
        if ner:
            print(f"  NER pipelines loaded for {len(loaded)}/{len(langs)} languages: "
                  f"{','.join(loaded)}", file=sys.stderr)


def build(langs, tuned=True, ner=False):
    """Assemble the analyzer.

    `tuned=False` reproduces what a user gets from a bare `AnalyzerEngine()`:
    only the recognizers Presidio's own `default_recognizers.yaml` wires up, and
    the stock eight-region phone recognizer. It exists so the cost of expert
    configuration can be quoted as a measurement rather than an assertion.
    """
    engine = BlankNlp(langs, ner=ner)
    registry = RecognizerRegistry(supported_languages=langs)
    registry.load_predefined_recognizers(languages=langs, nlp_engine=engine)
    added, missing = 0, []
    if not tuned:
        print("  DEFAULT configuration: no extra recognizers, stock phone regions",
              file=sys.stderr)
        return AnalyzerEngine(nlp_engine=engine, registry=registry,
                              supported_languages=langs), 0
    for lang, names in EXTRA.items():
        if lang not in langs:
            continue
        for name in names:
            cls = getattr(pre, name, None)
            if cls is None:
                missing.append(name)
                continue
            try:
                registry.add_recognizer(cls(supported_language=lang))
                added += 1
            except Exception:
                try:
                    registry.add_recognizer(cls())
                    added += 1
                except Exception:
                    missing.append(name)
    # Presidio's PhoneRecognizer defaults to eight regions — US, GB, DE, FR, IL,
    # IN, CA, BR — so a Danish, Dutch or Polish number cannot be found at all.
    # Anyone benchmarking on EU data would widen this, so the benchmark does.
    eu_regions = tuple(sorted({
        "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR",
        "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LT", "LU", "LV", "MT", "NL",
        "NO", "PL", "PT", "RO", "SE", "SI", "SK",
    }))
    # CreditCardRecognizer is wired only to en/es/it/pl in the default config,
    # so German, Finnish and Swedish documents lose every card. It is
    # language-independent in substance, so register it everywhere.
    for lang in langs:
        registry.remove_recognizer("PhoneRecognizer", language=lang)
        registry.add_recognizer(
            pre.PhoneRecognizer(supported_language=lang, supported_regions=eu_regions))
        added += 1
        if not any(type(r).__name__ == "CreditCardRecognizer"
                   and r.supported_language == lang for r in registry.recognizers):
            registry.add_recognizer(pre.CreditCardRecognizer(supported_language=lang))
            added += 1

    if missing:
        print(f"  note: {len(missing)} recognizer(s) unavailable: {missing}", file=sys.stderr)
    print(f"  registered {added} extra/retuned recognizers", file=sys.stderr)
    return AnalyzerEngine(nlp_engine=engine, registry=registry,
                          supported_languages=langs), added


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None,
                    help="documents per dataset (evenly spaced)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ner", action="store_true",
                    help="load trained spaCy pipelines (enables NER and the "
                         "lemma-based context enhancer)")
    ap.add_argument("--default-config", action="store_true",
                    help="run Presidio as shipped, without the fairness tuning")
    args = ap.parse_args()

    datasets = DATASETS
    langs = sorted(set(COUNTRY_LANG.values()))
    analyzer, _ = build(langs, tuned=not args.default_config, ner=args.ner)
    scoreable = set().union(*TYPE_MAP.values()) - EXCLUDED_CATEGORIES

    # counters[(bucket_kind, bucket)][category] = [tp, fp, fn]
    counters = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))
    n_docs = 0

    for name in datasets:
        records = json.loads((DATA_DIR / name).read_text())
        if args.limit and len(records) > args.limit:
            step = len(records) / args.limit
            records = [records[int(i * step)] for i in range(args.limit)]
        for rec in records:
            labels = rec.get("PII") or []
            if not labels:
                continue
            text = rec["source_text"]
            countries = {p["PII_country"] for p in labels}
            lang = COUNTRY_LANG.get(sorted(countries)[0], "en")
            n_docs += 1
            try:
                results = analyzer.analyze(text=text, language=lang)
            except Exception as exc:  # a language may lack a pipeline
                print(f"  !! {lang}: {exc}", file=sys.stderr)
                continue

            dets = []
            for r in results:
                cats = TYPE_MAP.get(r.entity_type)
                if cats:
                    dets.append((r.start, r.end, cats, r.entity_type))

            matched = set()
            for p in labels:
                idx = text.find(p["PII_identifier"])
                if idx < 0:
                    continue
                s, e = idx, idx + len(p["PII_identifier"])
                cat, country = p["PII_category"], p["PII_country"]
                if cat in EXCLUDED_CATEGORIES:
                    continue
                hit = None
                for i, (ds, de, cats, _et) in enumerate(dets):
                    if s < de and e > ds and cat in cats:
                        hit = i
                        break
                buckets = [("type", cat), ("country", country),
                           ("lang", COUNTRY_LANG.get(country, "en")),
                           ("dataset", name)]
                for kind, key in buckets:
                    counters[(kind, key)][cat][0 if hit is not None else 2] += 1
                if hit is not None:
                    matched.add(hit)

            label_spans = []
            for p in labels:
                i = text.find(p["PII_identifier"])
                if i >= 0:
                    label_spans.append((i, i + len(p["PII_identifier"])))
            for i, (ds, de, cats, etype) in enumerate(dets):
                if i in matched:
                    continue
                # Charge a false positive only for categories this corpus labels
                # at all, and only when the span is not already covered.
                if not (cats & scoreable):
                    continue
                if any(ds < e and de > s for s, e in label_spans):
                    continue
                if cats <= EXCLUDED_CATEGORIES:
                    continue
                cat = etype
                country = sorted(countries)[0]
                for kind, key in [("type", cat), ("country", country),
                                  ("lang", COUNTRY_LANG.get(country, "en")),
                                  ("dataset", name)]:
                    counters[(kind, key)][cat][1] += 1

    flat = {f"{kind}|{key}": {c: v for c, v in cats.items()}
            for (kind, key), cats in counters.items()}
    Path(args.out).write_text(json.dumps({"documents": n_docs, "counters": flat}))
    print(f"documents analysed: {n_docs:,}  ->  {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
