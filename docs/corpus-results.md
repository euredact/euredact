# Corpus results — euredact 0.7.1 (`b43707d`)

Generated 2026-10-29 by `make eval` from `corpus-results.json`, which carries the same figures. Per entity type, under the names the API returns. No aggregate figure is given: each row stands with the conditions below (rules-engine#109).

## Conditions

- Rules engine only (mode="rules"); the cloud tier is not measured here.
- Synthetic corpus, generated for evaluation; no real person's data.
- Two country modes: 'hinted' passes each document's labelled countries as `countries`; 'blind' passes none.
- A hit is a labelled value whose every character is masked, at every place it occurs, by a type its category accepts. Fully masked by another type is 'mistyped': protected, but a miss for recall.
- A detection is a true positive when it overlaps a labelled value whose category accepts its type, and a false positive otherwise; a mistyped detection is a false positive for the type it was emitted as.
- Support and detections are counted differently: support is the labels of the categories attributed to a type, detections are everything the engine emitted as that type, and a detection is a true positive on any label whose category accepts its type. Most SSN and TAX_ID detections land on NATIONAL_ID labels, so their detections exceed their support.
- Precision is a lower bound: a real identifier the corpus left unlabelled counts as a false positive when the engine masks it.
- DOB is optional (the cloud tier owns bare dates) and reported separately, with detect_dates=True.
- CRYPTO_ADDRESS_BTC and CRYPTO_ADDRESS_ETH labels are excluded: no API type exists for them.
- The regression records (euromask_regressions.json) are excluded from the figures; they are adversarial by design and are reported as pass/fail.

## Per entity type — hinted

| Type | Support | Hits | Mistyped | Partial | Misses | Recall | Detections | FP | Precision | Corpus categories |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `BANK_ACCOUNT` | 126,428 | 126,428 | 0 | 0 | 0 | 100.00% | 126,428 | 0 | 100.00% | IBAN |
| `BIC` | 2,830 | 2,830 | 0 | 0 | 0 | 100.00% | 2,951 | 129 | 95.63% | SWIFT_BIC |
| `CHAMBER_OF_COMMERCE` | 8,497 | 8,497 | 0 | 0 | 0 | 100.00% | 8,349 | 0 | 100.00% | CHAMBER_OF_COMMERCE (also accepts VAT) |
| `CREDIT_CARD` | 6,415 | 6,415 | 0 | 0 | 0 | 100.00% | 6,415 | 0 | 100.00% | CREDIT_CARD |
| `EMAIL` | 152,938 | 152,938 | 0 | 0 | 0 | 100.00% | 153,051 | 113 | 99.93% | EMAIL |
| `GPS_COORDINATES` | 950 | 950 | 0 | 0 | 0 | 100.00% | 950 | 0 | 100.00% | GPS_COORDINATES |
| `HEALTH_INSURANCE` | 1,185 | 1,185 | 0 | 0 | 0 | 100.00% | 1,076 | 0 | 100.00% | HEALTH_ID, HEALTH_INSURANCE (also accepts NATIONAL_ID) |
| `IMEI` | 2,443 | 2,443 | 0 | 0 | 0 | 100.00% | 2,443 | 0 | 100.00% | IMEI |
| `IPV6_ADDRESS` | 636 | 636 | 0 | 0 | 0 | 100.00% | 636 | 0 | 100.00% | IP_ADDRESS_V6 |
| `IP_ADDRESS` | 10,038 | 10,027 | 11 | 0 | 0 | 99.89% | 10,066 | 39 | 99.61% | IP_ADDRESS |
| `LICENSE_PLATE` | 6,445 | 6,436 | 2 | 2 | 5 | 99.86% | 6,436 | 0 | 100.00% | LICENSE_PLATE |
| `MAC_ADDRESS` | 3,546 | 3,546 | 0 | 0 | 0 | 100.00% | 3,546 | 0 | 100.00% | MAC_ADDRESS |
| `NATIONAL_ID` | 118,582 | 118,212 | 0 | 0 | 370 | 99.69% | 94,411 | 163 | 99.83% | NATIONAL_ID, NATIONAL_ID_CARD (also accepts SSN, TAX_ID) |
| `PASSPORT` | 1,072 | 879 | 0 | 0 | 193 | 82.00% | 879 | 0 | 100.00% | PASSPORT |
| `PHONE` | 123,151 | 122,934 | 164 | 51 | 2 | 99.82% | 122,988 | 3 | 100.00% | PHONE |
| `POSTAL_CODE` | 53,914 | 53,897 | 10 | 0 | 7 | 99.97% | 53,925 | 28 | 99.95% | POSTAL_CODE |
| `SECRET` | 5,798 | 5,225 | 77 | 173 | 184 | 90.12% | 5,267 | 213 | 95.96% | SECRET |
| `SOCIAL_HANDLE` | 2,267 | 2,267 | 0 | 0 | 0 | 100.00% | 2,267 | 0 | 100.00% | SOCIAL_HANDLE |
| `SSN` | 1,288 | 1,288 | 0 | 0 | 0 | 100.00% | 14,511 | 1 | 99.99% | SOCIAL_SECURITY (also accepts NATIONAL_ID) |
| `TAX_ID` | 3,729 | 3,729 | 0 | 0 | 0 | 100.00% | 14,969 | 0 | 100.00% | TAX_ID, TAX_ID_PERSONAL |
| `UUID` | 4,890 | 4,890 | 0 | 0 | 0 | 100.00% | 4,960 | 70 | 98.59% | UUID |
| `VAT` | 20,525 | 20,525 | 0 | 0 | 0 | 100.00% | 19,543 | 0 | 100.00% | TAX_ID_BUSINESS, VAT_NUMBER (also accepts CHAMBER_OF_COMMERCE, TAX_ID) |
| `VIN` | 9,701 | 9,701 | 0 | 0 | 0 | 100.00% | 9,701 | 0 | 100.00% | VIN |

Optional: `DOB` — support 89,805, recall 100.00%, detections 89,805, FP 0, precision 100.00%.

## Per entity type — blind

| Type | Support | Hits | Mistyped | Partial | Misses | Recall | Detections | FP | Precision | Corpus categories |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `BANK_ACCOUNT` | 126,428 | 126,428 | 0 | 0 | 0 | 100.00% | 126,428 | 0 | 100.00% | IBAN |
| `BIC` | 2,830 | 2,830 | 0 | 0 | 0 | 100.00% | 2,951 | 129 | 95.63% | SWIFT_BIC |
| `CHAMBER_OF_COMMERCE` | 8,497 | 8,497 | 0 | 0 | 0 | 100.00% | 8,355 | 6 | 99.93% | CHAMBER_OF_COMMERCE (also accepts VAT) |
| `CREDIT_CARD` | 6,415 | 6,415 | 0 | 0 | 0 | 100.00% | 6,415 | 0 | 100.00% | CREDIT_CARD |
| `EMAIL` | 152,938 | 152,938 | 0 | 0 | 0 | 100.00% | 153,051 | 113 | 99.93% | EMAIL |
| `GPS_COORDINATES` | 950 | 950 | 0 | 0 | 0 | 100.00% | 950 | 0 | 100.00% | GPS_COORDINATES |
| `HEALTH_INSURANCE` | 1,185 | 1,185 | 0 | 0 | 0 | 100.00% | 1,076 | 0 | 100.00% | HEALTH_ID, HEALTH_INSURANCE (also accepts NATIONAL_ID) |
| `IMEI` | 2,443 | 2,443 | 0 | 0 | 0 | 100.00% | 2,485 | 42 | 98.31% | IMEI |
| `IPV6_ADDRESS` | 636 | 636 | 0 | 0 | 0 | 100.00% | 636 | 0 | 100.00% | IP_ADDRESS_V6 |
| `IP_ADDRESS` | 10,038 | 10,027 | 11 | 0 | 0 | 99.89% | 10,066 | 39 | 99.61% | IP_ADDRESS |
| `LICENSE_PLATE` | 6,445 | 6,436 | 2 | 2 | 5 | 99.86% | 6,436 | 0 | 100.00% | LICENSE_PLATE |
| `MAC_ADDRESS` | 3,546 | 3,546 | 0 | 0 | 0 | 100.00% | 3,546 | 0 | 100.00% | MAC_ADDRESS |
| `NATIONAL_ID` | 118,582 | 118,077 | 135 | 0 | 370 | 99.57% | 94,728 | 742 | 99.22% | NATIONAL_ID, NATIONAL_ID_CARD (also accepts SSN, TAX_ID) |
| `PASSPORT` | 1,072 | 879 | 0 | 0 | 193 | 82.00% | 879 | 0 | 100.00% | PASSPORT |
| `PHONE` | 123,151 | 122,169 | 929 | 51 | 2 | 99.20% | 122,334 | 114 | 99.91% | PHONE |
| `POSTAL_CODE` | 53,914 | 53,897 | 10 | 0 | 7 | 99.97% | 53,925 | 28 | 99.95% | POSTAL_CODE |
| `SECRET` | 5,798 | 5,225 | 77 | 173 | 184 | 90.12% | 5,267 | 213 | 95.96% | SECRET |
| `SOCIAL_HANDLE` | 2,267 | 2,267 | 0 | 0 | 0 | 100.00% | 2,267 | 0 | 100.00% | SOCIAL_HANDLE |
| `SSN` | 1,288 | 1,283 | 5 | 0 | 0 | 99.61% | 14,598 | 86 | 99.41% | SOCIAL_SECURITY (also accepts NATIONAL_ID) |
| `TAX_ID` | 3,729 | 3,709 | 20 | 0 | 0 | 99.46% | 15,171 | 102 | 99.33% | TAX_ID, TAX_ID_PERSONAL |
| `UUID` | 4,890 | 4,890 | 0 | 0 | 0 | 100.00% | 4,960 | 70 | 98.59% | UUID |
| `VAT` | 20,525 | 20,525 | 0 | 0 | 0 | 100.00% | 19,543 | 0 | 100.00% | TAX_ID_BUSINESS, VAT_NUMBER (also accepts CHAMBER_OF_COMMERCE, TAX_ID) |
| `VIN` | 9,701 | 9,701 | 0 | 0 | 0 | 100.00% | 9,701 | 0 | 100.00% | VIN |

Optional: `DOB` — support 89,805, recall 100.00%, detections 89,805, FP 0, precision 100.00%.

The rules engine can emit these types, but this corpus neither labels nor produces them, so no figure is given: `DATE_OF_DEATH`, `DRIVERS_LICENSE`, `HEALTHCARE_PROVIDER`, `INTERNAL_ID`, `RESIDENCE_PERMIT`.


## Category → API type

| Corpus category | API type | A hit accepts |
|---|---|---|
| `CHAMBER_OF_COMMERCE` | `CHAMBER_OF_COMMERCE` | `CHAMBER_OF_COMMERCE`, `VAT` |
| `CREDIT_CARD` | `CREDIT_CARD` | `CREDIT_CARD` |
| `DOB` | `DOB` | `DOB` |
| `EMAIL` | `EMAIL` | `EMAIL` |
| `GPS_COORDINATES` | `GPS_COORDINATES` | `GPS_COORDINATES` |
| `HEALTH_ID` | `HEALTH_INSURANCE` | `HEALTH_INSURANCE`, `NATIONAL_ID` |
| `HEALTH_INSURANCE` | `HEALTH_INSURANCE` | `HEALTH_INSURANCE`, `NATIONAL_ID` |
| `IBAN` | `BANK_ACCOUNT` | `BANK_ACCOUNT` |
| `IMEI` | `IMEI` | `IMEI` |
| `IP_ADDRESS` | `IP_ADDRESS` | `IP_ADDRESS` |
| `IP_ADDRESS_V6` | `IPV6_ADDRESS` | `IPV6_ADDRESS` |
| `LICENSE_PLATE` | `LICENSE_PLATE` | `LICENSE_PLATE` |
| `MAC_ADDRESS` | `MAC_ADDRESS` | `MAC_ADDRESS` |
| `NATIONAL_ID` | `NATIONAL_ID` | `NATIONAL_ID`, `SSN`, `TAX_ID` |
| `NATIONAL_ID_CARD` | `NATIONAL_ID` | `NATIONAL_ID` |
| `PASSPORT` | `PASSPORT` | `PASSPORT` |
| `PHONE` | `PHONE` | `PHONE` |
| `POSTAL_CODE` | `POSTAL_CODE` | `POSTAL_CODE` |
| `SECRET` | `SECRET` | `SECRET` |
| `SOCIAL_HANDLE` | `SOCIAL_HANDLE` | `SOCIAL_HANDLE` |
| `SOCIAL_SECURITY` | `SSN` | `NATIONAL_ID`, `SSN` |
| `SWIFT_BIC` | `BIC` | `BIC` |
| `TAX_ID` | `TAX_ID` | `TAX_ID` |
| `TAX_ID_BUSINESS` | `VAT` | `TAX_ID`, `VAT` |
| `TAX_ID_PERSONAL` | `TAX_ID` | `TAX_ID` |
| `UUID` | `UUID` | `UUID` |
| `VAT_NUMBER` | `VAT` | `CHAMBER_OF_COMMERCE`, `VAT` |
| `VIN` | `VIN` | `VIN` |

## Corpus

152,300 documents, 759,595 labels, 31 countries plus `INTL`.

| File | Documents | Labels |
|---|---:|---:|
| `euromask_allcountries_20k.json` | 20,000 | 107,886 |
| `euromask_dach_south_20k.json` | 20,000 | 103,897 |
| `euromask_eastern_20k.json` | 20,000 | 103,317 |
| `euromask_el_cy_mt_20k.json` | 20,000 | 101,753 |
| `euromask_ie_baltics_uk_20k.json` | 20,000 | 102,468 |
| `euromask_international_10k.json` | 10,000 | 45,155 |
| `euromask_nordic_20k.json` | 20,000 | 107,406 |
| `euromask_secrets_5k.json` | 5,000 | 6,510 |
| `euromask_training_core.json` | 7,300 | 26,587 |
| `euromask_training_core2.json` | 10,000 | 54,616 |

Countries: AT, BE, BG, CH, CY, CZ, DE, DK, EE, EL, ES, FI, FR, HR, HU, IE, INTL, IS, IT, LT, LU, LV, MT, NL, NO, PL, PT, RO, SE, SI, SK, UK.

Excluded: `euromask_regressions.json`. The corpus records carry no language or document type; neither is reported until they do.

Labels per category: `EMAIL` 152,938, `IBAN` 126,428, `PHONE` 123,151, `NATIONAL_ID` 118,040, `DOB` 89,805, `POSTAL_CODE` 53,914, `VAT_NUMBER` 20,136, `IP_ADDRESS` 10,038, `VIN` 9,701, `CHAMBER_OF_COMMERCE` 8,497, `LICENSE_PLATE` 6,445, `CREDIT_CARD` 6,415, `SECRET` 5,798, `UUID` 4,890, `MAC_ADDRESS` 3,546, `TAX_ID_PERSONAL` 2,837, `SWIFT_BIC` 2,830, `IMEI` 2,443, `SOCIAL_HANDLE` 2,267, `SOCIAL_SECURITY` 1,288, `CRYPTO_ADDRESS_ETH` 1,273, `CRYPTO_ADDRESS_BTC` 1,249, `PASSPORT` 1,072, `GPS_COORDINATES` 950, `HEALTH_INSURANCE` 933, `TAX_ID` 892, `IP_ADDRESS_V6` 636, `NATIONAL_ID_CARD` 542, `TAX_ID_BUSINESS` 389, `HEALTH_ID` 252.

## Regression records

534 records from `tests/regression_corpus.py`, 0 failures, checked in both modes.
