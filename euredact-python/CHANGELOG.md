# Changelog

## 0.3.2 (2026-07-29)

### Fixed — security

- **Installing the optional `fast` extra disabled private-key redaction.**
  Prefix-indexed patterns are only run over a bounded window after their prefix
  hit, but 15 SECRET patterns can match beyond it — the PEM private-key pattern
  matches up to 16 KB. With `pyahocorasick` installed those matches were never
  found, and a PEM block passed through into `redacted_text` unmasked.

  Reproduced on 0.3.1, identical input:

  ```
                            SECRET spans   key material in output?
  with    pyahocorasick     [15]           LEAKED
  without pyahocorasick     [542, 15]      not leaked
  ```

  Patterns whose maximum match width exceeds the window are now routed to the
  sequential path. Verified: the two scan paths produce identical output on
  12,000 corpus documents, where they previously diverged.

  Affects anyone who installed `euredact[fast]`. The pure-Python default was
  never affected, and the TypeScript package does not window its scans so was
  never affected either.

- `tests/test_scan_path_parity.py` runs **both** scan paths in one process and
  compares them, so the optional extra can no longer change behaviour silently.
  A >200-character PEM block is now a shared conformance vector.

## 0.3.1 (2026-07-27)

### Fixed

- **German plates are now validated against the district-code list.** The
  pattern accepted any 1-3 uppercase letters as a city code, so document
  references kept the plate shape: `REF-A12`, `SYS-B3`, `KTO-A1`, `JOB-C4`
  were all detected. The ~790 *Unterscheidungszeichen* are a closed set fixed
  by the Fahrzeug-Zulassungsverordnung, which makes membership a whitelist
  rather than the open-ended blocklist of standards prefixes it replaces —
  references of that shape now fail without needing to be enumerated.

  Applied as a tier, not a filter: a code on the list emits with no cue, a
  code absent from it still emits when a plate cue (`Kennzeichen`, `Kfz`,
  `Fahrzeug`) is nearby, and only the combination of neither is rejected. A
  code missing from the list therefore costs recall solely where there is no
  other evidence. Verified on the corpus: 548 true positives, 0 false
  positives, 0 missed.

  The standards guard is kept alongside it, because `DIN` is both a standards
  body and the district code for Dinslaken — a whitelist alone cannot tell
  `DIN A4` from a Dinslaken plate.

- **German `LICENSE_PLATE` matched standards codes and document references.**
  With `countries=["DE"]`, `ICD-10`, `ISO-9001`, `EN-1090`, `DIN-4102`,
  `RFC-2822`, `COVID-19`, `POL-2025` and similar were replaced with
  `[LICENSE_PLATE]`, corrupting the returned text —
  `Diagnose: ... ([LICENSE_PLATE]: E11.9)`. Measured at 98 occurrences across
  68 documents in a 5,010-document corpus, and the same token shape occurs
  14,563 times corpus-wide, so the blast radius grows sharply if `DE` is passed
  for a cross-border document.

  The cause was not that the letter group after the hyphen was optional — it
  never was. The *first* separator was optional, so a contiguous letter run
  split across both groups and the hyphen was consumed as the second
  separator: `ICD-10` parsed as city `IC` + letters `D` + `-` + `10`. The
  separator after the city code is now mandatory, which is correct for a real
  plate (`B-AB 1234`, `M-XY 99`) since that is where the seal sits.

  A standards-prefix guard (`ICD`, `ISO`, `DIN`, `IEC`, `RFC`, `DSM`, `ATC`,
  `MDR`) covers the residue that is genuinely plate-shaped, such as `ATC-N06`.
  It is gated on the absence of a plate cue, so `Kennzeichen ATC-N 06` is still
  detected.

### Added

- **Shared conformance suite** (`conformance/vectors.json`). Language-neutral
  input/expectation pairs run by both SDKs, so a behavioural difference between
  Python and TypeScript fails a test rather than surfacing later as a corpus
  diff. Verified to work: reverting the plate fix in one engine alone fails
  five shared vectors.

## 0.3.0 (2026-07-27)

### Measured effect

Full evaluation over 152,300 generated records (`tests/eval_full.py`), measured
against the same engine with the detection changes below reverted, on identical
ground truth:

| | 0.2.0 | 0.3.0 |
|---|---|---|
| Recall, `countries=[...]` supplied | 98.11% | **98.28%** |
| Precision, `countries=[...]` supplied | 98.21% | **98.97%** |
| False positives | 12,468 | **7,160** |
| Recall / precision, blind (no `countries`) | — | 94.39% / 95.22% |

Net: recall up, false positives down 43%. DOB is excluded (40.6%; deferred to
the LLM tier by design).

The Python and TypeScript engines now produce **byte-identical redacted output
on 2,500 corpus documents** and agree to within 0.01 points on recall.

Two figures published previously do not reproduce and should not be reused:
"99.1% recall / 147K records" (the set is 152,300 records and the engine
measured 98.11% before these changes), and "0.02 ms per page" — that is the
cache-hit path; uncached, a 2,000-character page takes **4.6 ms** in Python and
**0.28 ms** in the TypeScript engine.

### Breaking

- **`IBAN` is renamed to the canonical `BANK_ACCOUNT`.** The engine emitted a
  legacy type name; the canon (`config/entity_types.json` → `legacy_aliases`)
  defines `"IBAN": "BANK_ACCOUNT"`. `detection.entity_type.value` is now
  `"BANK_ACCOUNT"` and the placeholder written into redacted text is
  `[BANK_ACCOUNT]`, not `[IBAN]`.

  `EntityType.IBAN` is kept as an **alias** of `EntityType.BANK_ACCOUNT`, and
  `EntityType("IBAN")` still resolves, so code referring to the member keeps
  working. Code matching on the *string* `"IBAN"` — or on the `[IBAN]`
  placeholder — must be updated. `euredact.types.LEGACY_TYPE_ALIASES`
  publishes the mapping.

  An audit against the canon found this to be the only mismatch: every other
  emitted type name is canonical (`NAME` and `OTHER` are cloud-tier internals
  with no rules-engine emission).

### Fixed

- **BIC no longer matches ordinary ALL-CAPS words.** The rule was shape-only:
  any 8- or 11-character uppercase run was treated as a BIC, so section
  headings and shouted words (`DRINGEND`, `HOSPITAL`, `GEGEVENS`,
  `MAANDELIJKS`) were masked. Measured on a 5,010-document corpus, 78% of
  `BIC` detections were false positives. Because a masked span is replaced in
  the document body, this destroyed text rather than merely mislabelling it —
  `QUEEN ELIZABETH [BIC] BIRMINGHAM` left the hospital name unlabelable.

  Structural validation alone is not enough: characters 5-6 of ordinary words
  are frequently valid ISO 3166 country codes (`DRINGEND` -> `GE`,
  `HOSPITAL` -> `IT`), and BIC is the only bank identifier here with no check
  digit. Detection is now tiered — see "BIC detection" in the README.

- **Bare 4-digit postal codes no longer shred longer identifiers.** Any bare
  digit run was claimable as a postal code, including digits inside a longer
  number: `SV-Nummer: [POSTAL_CODE] 040390` cut an Austrian social security
  number in half, and `+43 664 [POSTAL_CODE] 907` took digits belonging to a
  phone number. A digits-only match is now rejected when it is directly
  adjacent to another digit; when `. - / _` **joins it to another digit
  group** (`0456.2398.71-02`); when a further digit group follows on the same
  line; when an identifier label introduces it (`DiNr.`, `Policen-Nr.`, `N°`);
  or when it follows an international dialling prefix.

  Note the punctuation rule is deliberately narrow: the separator only counts
  when a digit sits on the far side of it. Treating a trailing `.` as a
  separator rejects every postal code that ends a sentence
  (`Domicilio: Palma, 13867. Pagos a ...`) — measured at 18,977 lost true
  positives, POSTAL_CODE recall 96.2% -> 61.0%, on the 152,300-record set.

- **International phone numbers were missed in 11 countries.** Each country's
  international pattern hard-coded a single grouping, so `+43 664 8213 907`
  was invisible to the Austrian pattern (which expects an unbroken subscriber
  number) while `+32 498 22 67 31` matched fine. 16 of 59 realistic formats
  went undetected, including every `(0)` trunk-prefix form. A missed phone
  number in a redaction product is leaked PII.

  This was also the **root cause of the postal-code split**: with no phone
  match to claim the span, the bare-4-digit rule took `8213` out of the middle
  of the number. A country-independent E.164 pattern now runs alongside the
  per-country ones — a leading `+` is self-identifying, so it is not gated.

- **IBANs were gated by `countries=[...]`.** `BE68 5390 0754 7034` was
  detected with `countries=["BE"]` and missed with `countries=["AT"]`, so
  every cross-border document leaked the account number. An IBAN carries its
  own country code and a mod-97 checksum; it is now detected on structure and
  checksum alone, whatever the caller requests. `countries` still prioritises,
  never gates.

- **`countries=["GB"]` raised `ValueError`.** The registry uses the EU/VAT
  spellings (`UK`, `EL`) while the documented contract is ISO 3166-1 alpha-2
  (`GB`, `GR`), so a caller passing correct ISO codes crashed. Both spellings
  are now accepted and are exactly equivalent.

  An unrecognised code no longer raises at all: it emits an
  `UnknownCountryWarning` and continues with the shared, country-independent
  patterns. Throwing invited callers to wrap the call in `try/except` and skip
  redaction — failing open, with unredacted PII.

- **Austrian national numbers with a short area code were missed.**
  `01 53460 2215` (Vienna) did not match, because the national pattern
  requires 3-4 digits after the trunk `0`. A grouped variant now covers short
  area codes; both separators are mandatory so date fragments like `01 2025`
  stay out.

- **Space-separated bank codes were missed** — `RZBA AT WW`, `NICA BE BB`.
  Added as a separate pattern requiring a space between every group rather
  than making spaces optional in the existing one, which would have let
  `GEBABEBB KBC` match as a single 11-character code and claim the following
  word. Only literal spaces are allowed, so a match cannot span a line break.

- **Place names beginning "St." suppressed the postal code before them.**
  The unit filter's bare `st` (stuks/pieces) matched the `St.` in
  `8386 St. Gallen` and `9600 St. Paul's Bay`. It now requires that `st` not be
  followed by `.` and a capital.

- **Country-prefixed postal codes were read as subtraction.** `A-1010 Wien`,
  `B-2000 Antwerpen` and `D-10115 Berlin` were discarded because the hyphen
  looked like a minus sign to the maths filter. Genuine arithmetic
  (`Ergebnis = 1010`, `Rabatt -2000 EUR`) is still suppressed.

- **Residence phrasing now counts as postal context.** `wonende te 2000
  Antwerpen` and `domicilié à 1000 Bruxelles` were dropped by the
  year-as-postal filter, which only recognised explicit address words.

### Changed

- `validate_bic()` now requires a real ISO 3166-1 alpha-2 code at positions
  5-6. `ISO_3166_ALPHA2` is exported from `euredact.rules.validators`.
- The IBAN length table is hoisted to `euredact.rules.validators.IBAN_LENGTHS`
  and drives the country-independent IBAN pattern, which pins each country's
  exact length so a match cannot absorb a following word.
- Some spans are now **relabelled** rather than newly masked, because a
  checksum-validated detector reclaims them from a weaker one: `RO57` at the
  head of an IBAN is no longer a Romanian `VAT`, and `+31 621036924` is a
  `PHONE` rather than a Dutch `NATIONAL_ID`. Verified on 28,852 documents: no
  character that was masked before is unmasked now.
- POSTAL_CODE now resolves **last** in overlap deduplication, so it can only
  claim spans no structured detector (PHONE, SSN, NATIONAL_ID, IBAN, VAT,
  CREDIT_CARD...) wants, regardless of span length.

### Added

- `euredact.set_bic_registry()` — install a BIC registry consulted ahead of
  the bundled seed prefixes. Accepts a membership callable, an iterable of
  BICs, a path to a newline-delimited file, or `None` to remove. Entries may
  be full BIC8/BIC11 codes or bare BIC6 prefixes.
- A bundled seed list of BIC6 institution+country prefixes for major European
  banks, compiled from publicly published bank data. No licensed directory is
  bundled.

## 0.1.0 (2026-03-30)

Initial release of the EuRedact rule engine.

### Features

- **31 countries**: All EU-27 member states plus UK, Switzerland, Iceland, and Norway
- **20+ PII entity types**: National IDs, IBANs, phone numbers, email, VAT, license plates, VIN, credit cards, BIC/SWIFT, IMEI, GPS coordinates, UUIDs, social handles, MAC/IP addresses
- **Checksum validation**: IBAN (mod-97), Luhn, and 20+ country-specific national ID validators
- **Two-pass detection**: Liberal pattern matching followed by suppression filters for false positive reduction
- **Context-aware detection**: Keyword proximity checks and structural detection (JSON field names, CSV headers)
- **Batch processing**: `redact_batch()`, `redact_iter()`, `aredact_batch()` for bulk workloads
- **True async**: `aredact()` offloads to thread pool, non-blocking for async frameworks
- **Referential integrity**: Consistent label mapping within a session (`referential_integrity=True`)
- **Aho-Corasick acceleration**: Optional `pyahocorasick` for faster pattern scanning
- **Zero required dependencies**: Pure Python, works with `pip install euredact`

### Performance

- Sub-millisecond per page (~0.5ms for typical documents)
- ~2,000 records/second on mixed workloads
- 99.1% recall, 99.3% precision on 147K-record evaluation across all 31 countries
