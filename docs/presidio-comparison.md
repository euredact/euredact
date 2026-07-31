# euRedact vs Microsoft Presidio on European PII

**Measured 31 July 2026** · euRedact 0.3.6 · Presidio 2.2.364 · 152,300 documents,
667,129 labelled entities

---

## Summary

On a corpus of European documents, euRedact finds **99.7%** of labelled PII.
Presidio finds **57.7%** as shipped, or **68.3%** after being reconfigured for
Europe. The difference is not spread evenly: Presidio matches or nearly matches
euRedact on every entity with a single worldwide format — IBAN, credit card, IP
address, MAC address, email, phone — and finds almost none of the entities
defined by an individual member state.

| engine | precision | recall | F1 | false positives | misses |
|---|---:|---:|---:|---:|---:|
| **Presidio 2.2.364**, as shipped | **99.91%** | 57.68% | 73.14% | **328** | 282,311 |
| **Presidio 2.2.364**, tuned for the EU | 93.15% | 68.29% | **78.80%** | 33,519 | 211,552 |
| **euRedact 0.3.6**, blind | 99.59% | 99.50% | **99.55%** | 2,720 | 3,327 |
| **euRedact 0.3.6**, with country hints | 99.82% | 99.72% | **99.77%** | 1,232 | 1,839 |

Two things in that table deserve to be said out loud rather than left for a
careful reader to find.

**Out of the box, Presidio is the most precise engine here** — 99.91% against
euRedact's 99.82%, with 328 false positives against euRedact's 1,232. It is
conservative: what it claims, it is almost always right about. It simply does
not claim most European PII.

**The single most useful number is not F1 — it is misses.** This is a redaction
tool, and an unredacted identifier is a disclosure, whereas a false positive is
a word needlessly blacked out. On that measure the gap does not depend on how
Presidio is configured: 282,311 missed as shipped, 211,552 missed tuned, against
3,327 for euRedact with no configuration at all.

The honest one-line version: **these tools are built for different jobs.**
Presidio is a general-purpose, extensible PII framework with strong name and
location detection. euRedact is a rules engine for the 31 European
jurisdictions. This benchmark measures European coverage, which is euRedact's
entire purpose and only a part of Presidio's.

Read the [limitations](#what-this-comparison-does-not-say) before quoting the
headline. They are not boilerplate; the comparison is lopsided enough that
stating what it excludes is the only way to make the number meaningful.

---

## What was measured

The corpus is euRedact's evaluation set: ten datasets, 152,300 documents,
667,129 labelled entities across 31 countries and 24 languages. Documents are
synthetic but generated per country from real formats — invoices, medical
letters, HR records, support tickets, forum threads.

Both engines were scored by the same rule, the one in
`euredact-python/tests/metrics.py`:

> A label counts as found only when a detection **overlaps its span** *and* the
> **detected type satisfies its category**. A value masked under the wrong
> label counts as both a miss and a false positive.

That rule is stricter than span-only matching, and it is applied identically to
both engines. Dates of birth are excluded from every figure, as they are in
euRedact's own reporting, because euRedact delegates them to a separate tier.

---

## How Presidio was configured

Both configurations were measured, so the cost of configuration is a number
rather than an assertion. Four changes were made, each using only what ships
inside the Presidio package:

| change | why | effect |
|---|---|---|
| Registered the 21 country recognizers Presidio ships but does not load | `default_recognizers.yaml` wires up the Spanish, Italian and Polish recognizers but not the German, Swedish, Finnish or UK ones, though all are in `presidio_analyzer.predefined_recognizers` | DE/SE/FI/UK entities become detectable at all |
| Widened `PhoneRecognizer` from 8 regions to 31 EU regions | it defaults to `US, GB, DE, FR, IL, IN, CA, BR`, so a Danish, Dutch or Polish number cannot be matched | **PHONE recall 68.5% → 97.9%** |
| Registered `CreditCardRecognizer` for `de`, `fi`, `sv` | the default config attaches it only to `en`, `es`, `it`, `pl` | cards detectable outside four languages |
| Analysed each document in its own language, derived from its labels' country | country recognizers only fire for their own language | country recognizers actually run |

**NER was switched off** (blank spaCy pipelines, tokenizer only). This is
explained under [limitations](#what-this-comparison-does-not-say) — it is the
single most consequential choice in the methodology.

### What the configuration bought, and what it cost

| | precision | recall | F1 | FP | misses |
|---|---:|---:|---:|---:|---:|
| Presidio, as shipped | 99.91% | 57.68% | 73.14% | 328 | 282,311 |
| Presidio, tuned as above | 93.15% | 68.29% | **78.80%** | 33,519 | 211,552 |

The tuning bought **10.6 points of recall and cost 6.8 points of precision.**
F1 moved 73.14% → 78.80%, so it is an improvement, but not an unambiguous one:
false positives rose from 328 to 33,519, almost entirely from the widened phone
recognizer reading national identifiers and reference numbers as telephone
numbers.

**A Presidio user might reasonably prefer the default.** The stock
configuration is the more precise engine, and for a workload where a false
redaction is expensive that is the right trade. The tuned configuration is used
for the headline because this document is about *coverage of European PII*, and
because choosing the weaker of two available configurations would have been the
easier way to win an argument. Both are reported so the choice is visible.

The per-type detail shows what configuration can and cannot fix:

| entity | as shipped | tuned |
|---|---:|---:|
| `CREDIT_CARD` | 18.2% | **100.0%** |
| `PHONE` | 68.4% | **97.9%** |
| `TAX_ID_BUSINESS` | 0.0% | 81.5% |
| `TAX_ID_PERSONAL` | 0.0% | 58.8% |
| `NATIONAL_ID` | 9.1% | 25.5% |
| `CHAMBER_OF_COMMERCE` | 0.0% | 23.3% |
| `HEALTH_INSURANCE` | 0.0% | 9.9% |
| `LICENSE_PLATE` | 0.0% | 8.5% |
| `POSTAL_CODE` | 0.0% | 8.2% |

Registering components Presidio already ships recovers credit cards and phone
numbers completely. It cannot recover postal codes, licence plates or national
identifiers, because the recognizers for 24 of the 31 countries do not exist to
be registered. That is the part of the gap configuration cannot close, and it is
why the comparison is structural rather than a matter of tuning.

---

## Results by entity type

Recall, on 667,129 labels. Presidio's column is its **tuned** figure — the
better of its two configurations. euRedact's is its hinted figure. A positive
gap favours euRedact, a negative one favours Presidio.

| category | labels | Presidio | euRedact 0.3.6 | gap |
|---|---:|---:|---:|---:|
| `EMAIL` | 152,938 | 97.5% | 100.0% | +2.5 |
| `IBAN` | 126,428 | 98.9% | 100.0% | +1.1 |
| `PHONE` | 123,151 | 97.9% | 99.7% | +1.8 |
| `NATIONAL_ID` | 118,040 | 25.5% | 100.0% | +74.5 |
| `POSTAL_CODE` | 53,914 | 8.2% | 98.0% | +89.9 |
| `VAT_NUMBER` | 20,136 | 4.3% | 100.0% | +95.7 |
| `IP_ADDRESS` | 10,038 | 100.0% | 99.3% | -0.7 |
| `VIN` | 9,701 | 0.0% | 100.0% | +100.0 |
| `CHAMBER_OF_COMMERCE` | 8,497 | 23.3% | 100.0% | +76.7 |
| `LICENSE_PLATE` | 6,445 | 8.5% | 99.9% | +91.4 |
| `CREDIT_CARD` | 6,415 | 100.0% | 100.0% | +0.0 |
| `SECRET` | 5,659 | 0.0% | 95.7% | +95.7 |
| `UUID` | 4,890 | 0.0% | 100.0% | +100.0 |
| `MAC_ADDRESS` | 3,546 | 100.0% | 100.0% | +0.0 |
| `TAX_ID_PERSONAL` | 2,837 | 58.8% | 100.0% | +41.2 |
| `SWIFT_BIC` | 2,830 | 0.0% | 100.0% | +100.0 |
| `IMEI` | 2,443 | 0.0% | 100.0% | +100.0 |
| `SOCIAL_HANDLE` | 2,267 | 0.0% | 100.0% | +100.0 |
| `SOCIAL_SECURITY` | 1,288 | 6.1% | 100.0% | +93.9 |
| `PASSPORT` | 1,072 | 0.0% | 99.9% | +99.9 |
| `GPS_COORDINATES` | 950 | 0.0% | 100.0% | +100.0 |
| `HEALTH_INSURANCE` | 933 | 9.9% | 100.0% | +90.1 |
| `TAX_ID` | 892 | 0.0% | 99.6% | +99.6 |
| `IP_ADDRESS_V6` | 636 | 100.0% | 100.0% | +0.0 |
| `NATIONAL_ID_CARD` | 542 | 0.0% | 100.0% | +100.0 |
| `TAX_ID_BUSINESS` | 389 | 81.5% | 100.0% | +18.5 |
| `HEALTH_ID` | 252 | 100.0% | 100.0% | +0.0 |

The pattern is stark enough to state plainly:

**Presidio is at or near 100% on:** IP addresses (v4 and v6), MAC addresses,
credit cards, health IDs, IBANs, phone numbers, email addresses. These are the
entities with one format worldwide, and Presidio handles them as well as a
specialist engine does.

**Presidio is at 0% on:** VIN, UUID, SECRET, SWIFT/BIC, IMEI, social handles,
passports, GPS coordinates and generic tax IDs. It ships no recognizer for
these.

**The largest single gap is `NATIONAL_ID`:** 87,967 of 118,040 missed. Presidio
ships national-identifier recognizers for six countries in this corpus — DE, ES,
IT, PL, FI, SE — plus the UK. The other 24 have no recognizer, so their national
IDs are invisible.

---

## Results by country

Recall tracks one thing almost perfectly: whether Presidio ships a recognizer
for that country.

| country | labels | recall | precision |
|---|---:|---:|---:|
| `EL` | 44,434 | 64.2% | 94.9% |
| `SE` | 39,123 | 82.6% | 95.8% |
| `INTL` | 34,382 | 44.6% | 90.9% |
| `UK` | 33,579 | 89.3% | 96.4% |
| `NO` | 32,246 | 63.5% | 88.1% |
| `FI` | 31,735 | 83.5% | 92.5% |
| `DK` | 30,968 | 63.4% | 87.3% |
| `NL` | 30,897 | 58.3% | 93.7% |
| `DE` | 29,909 | 79.1% | 92.9% |
| `FR` | 28,825 | 58.5% | 92.2% |
| `BE` | 26,960 | 60.1% | 94.7% |
| `CY` | 25,052 | 64.7% | 95.1% |
| `ES` | 19,693 | 82.5% | 93.3% |
| `IT` | 19,498 | 82.3% | 96.1% |
| `MT` | 19,495 | 64.6% | 95.1% |
| `CH` | 18,494 | 64.2% | 88.6% |
| `AT` | 18,249 | 64.5% | 91.0% |
| `IE` | 17,883 | 64.6% | 95.4% |
| `PL` | 16,151 | 86.1% | 93.4% |
| `PT` | 14,762 | 64.9% | 92.0% |
| `RO` | 14,170 | 66.1% | 92.0% |
| `LU` | 12,725 | 62.3% | 94.9% |
| `HU` | 12,693 | 65.8% | 92.8% |
| `LV` | 12,635 | 65.9% | 95.3% |
| `EE` | 12,616 | 66.2% | 95.1% |
| `CZ` | 12,531 | 62.9% | 91.6% |
| `LT` | 12,501 | 66.0% | 95.1% |
| `IS` | 10,570 | 71.2% | 91.6% |
| `BG` | 9,284 | 65.6% | 92.8% |
| `SK` | 9,240 | 62.4% | 91.3% |
| `HR` | 8,858 | 65.8% | 92.6% |
| `SI` | 6,971 | 66.0% | 91.4% |

The top of the table — PL 86.1%, UK 89.3%, FI 83.5%, SE 82.6%, ES 82.5%,
IT 82.3%, DE 79.1% — is exactly the set of countries with dedicated
recognizers. The countries clustered at 62–67% are getting the international
entity types and nothing else. `INTL` sits lowest at 44.6% because those
documents are dense in secrets, UUIDs and BICs, none of which Presidio claims.

## Results by language

| language | labels | recall | precision |
|---|---:|---:|---:|
| `en` | 105,339 | 66.0% | 94.7% |
| `el` | 69,486 | 64.4% | 95.0% |
| `de` | 66,652 | 70.9% | 91.4% |
| `nl` | 57,857 | 59.1% | 94.2% |
| `fr` | 41,550 | 59.6% | 93.1% |
| `sv` | 39,123 | 82.6% | 95.8% |
| `nb` | 32,246 | 63.5% | 88.1% |
| `fi` | 31,735 | 83.5% | 92.5% |
| `da` | 30,968 | 63.4% | 87.3% |
| `es` | 19,693 | 82.5% | 93.3% |
| `it` | 19,498 | 82.3% | 96.1% |
| `pl` | 16,151 | 86.1% | 93.4% |
| `pt` | 14,762 | 64.9% | 92.0% |
| `ro` | 14,170 | 66.1% | 92.0% |
| `hu` | 12,693 | 65.8% | 92.8% |
| `lv` | 12,635 | 65.9% | 95.3% |
| `et` | 12,616 | 66.2% | 95.1% |
| `cs` | 12,531 | 62.9% | 91.6% |
| `lt` | 12,501 | 66.0% | 95.1% |
| `is` | 10,570 | 71.2% | 91.6% |
| `bg` | 9,284 | 65.6% | 92.8% |
| `sk` | 9,240 | 62.4% | 91.3% |
| `hr` | 8,858 | 65.8% | 92.6% |
| `sl` | 6,971 | 66.0% | 91.4% |

Language is largely a restatement of country here, since the corpus assigns one
language per country. It is reported because Presidio's recognizer registry is
keyed by language rather than country, so this is the axis Presidio itself
organises around.

---

## False positives

All figures in this section are the **tuned** configuration. As shipped,
Presidio produces only 328 false positives in total at 99.91% precision — the
33,519 below are almost entirely a consequence of the EU tuning, not of
Presidio's defaults.

Tuned precision is 93.15% overall, and 87–96% in every country. The false
positives are highly concentrated:

| Presidio type | false positives |
|---|---:|
| `PHONE_NUMBER` | 31,820 |
| `DE_PLZ` | 1,605 |
| `EMAIL_ADDRESS` | 50 |
| `IP_ADDRESS` | 39 |
| `UK_VEHICLE_REGISTRATION` | 3 |
| `UK_POSTCODE` | 2 |
| **total** | **33,519** |
| *(`DATE_TIME`, excluded with DOB)* | *14,640* |

**31,820 of them are `PHONE_NUMBER`** — national identifiers, invoice
references and ticket numbers read as telephone numbers. This is the same
confusion euRedact spends the majority of its suppression logic on; roughly
half of euRedact's ~40 suppressors exist to separate digit runs that look like
phone numbers from digit runs that are something else. It is a genuinely hard
problem, and it is where a European-specific engine earns its keep.

---

## What this comparison does not say

**Name and location detection was not tested, and this matters most.** The
corpus labels no `PERSON`, `LOCATION` or `ORGANIZATION`, so those detections
are ignored by the scorer. NER is a principal reason people choose Presidio,
and euRedact's rules engine does not attempt it at all. **On unstructured text
where the PII is names rather than identifiers, this benchmark predicts
nothing, and Presidio may well be the better tool.**

The runs above use blank spaCy pipelines — tokenizer only, no NER — and that
choice was verified rather than assumed. Re-running with trained pipelines for
the 17 languages spaCy publishes them for, over a matched 10,000-document
sample:

| | precision | recall | F1 | TP | FP |
|---|---:|---:|---:|---:|---:|
| blank, tokenizer only | 93.14% | 65.99% | 77.25% | 26,892 | 1,981 |
| trained pipelines, NER on | 93.14% | 65.99% | 77.25% | 26,892 | 1,981 |

**Identical, category by category.** The hypothesis worth testing was indirect:
Presidio's `LemmaContextAwareEnhancer` raises a pattern recognizer's score using
surrounding lemmas, which a blank pipeline cannot supply, so a borderline match
might fail to clear the acceptance threshold. It made no difference to a single
detection. The only change anywhere was `DATE_TIME` false positives rising from
1,170 to 2,007, and those are excluded along with DOB. NER cost 2.1× the
runtime.

So NER neither helps nor hurts the entity types measured here. What it does —
find names and places — is real, and remains outside this comparison.

**Presidio detects cryptocurrency addresses; euRedact does not.** Excluded from
both sides because euRedact's evaluation excludes them. It is a capability
Presidio has and euRedact lacks.

**Presidio is a framework, not a finished product.** It is designed to be
extended with custom recognizers, and a team that added recognizers for the
missing 24 countries would close most of this gap — that is the intended way to
use it. This measures what it does out of the box, generously configured. The
comparison is "European coverage on day one", not "best achievable with
Presidio".

**The corpus is euRedact's own.** It was built to exercise European formats, and
euRedact has been tuned against it across several releases. That is a real
source of bias in euRedact's favour on the *absolute* numbers. It is much less
of a factor in the *shape* of the result: Presidio's misses are dominated by
entity types it ships no recognizer for, which no amount of corpus bias
explains.

**Documents are synthetic.** Generated from real formats per country, but not
drawn from real correspondence.

**Single configuration, single run.** No hyperparameter search on either side,
and Presidio's `leniency` and score thresholds were left at their defaults.

---

## Reproducing this

The harness is `scripts/presidio_benchmark.py`. It needs its own environment,
since Presidio pins older dependencies than euRedact:

```bash
python3.12 -m venv .presidio-venv
.presidio-venv/bin/pip install presidio-analyzer

# tuned for the EU — the configuration behind the headline
.presidio-venv/bin/python scripts/presidio_benchmark.py --out tuned.json

# Presidio exactly as shipped, for the comparison above
.presidio-venv/bin/python scripts/presidio_benchmark.py --default-config --out default.json

# with trained spaCy pipelines, to reproduce the NER check
.presidio-venv/bin/pip install de_core_news_sm nl_core_news_sm ...   # see NER_MODELS
.presidio-venv/bin/python scripts/presidio_benchmark.py --ner --limit 1000 --out ner.json
```

euRedact's own figures come from:

```bash
cd euredact-python && python tests/metrics.py --engine both --mode both
```

Both read the corpus from `$EUREDACT_CORPUS`. The harness prints how many
recognizers it registered; the tuned run must report 65, and the default run
reports none. A tuned run reporting any other number has not applied the
configuration described above and is not comparable to these figures.
