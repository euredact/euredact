# Changelog

## Unreleased

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
  With `countries: ["DE"]`, `ICD-10`, `ISO-9001`, `EN-1090`, `DIN-4102`,
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

Brings the TypeScript engine to parity with `euredact` 0.3.0 for Python. The two
engines now agree to within 0.01 points on a 152,300-record evaluation set
(recall 98.28%, precision 98.97% with country hints) and produce
**byte-identical redacted output on 2,500 corpus documents**.

### Breaking

- **`IBAN` is renamed to the canonical `BANK_ACCOUNT`.** `detection.entityType`
  is now `"BANK_ACCOUNT"` and the placeholder written into redacted text is
  `[BANK_ACCOUNT]`, not `[IBAN]`.

  `EntityType.IBAN` is kept as an alias with the same value, so
  `EntityType.IBAN === EntityType.BANK_ACCOUNT` and code referring to the member
  keeps working. Code matching the *string* `"IBAN"` — or the `[IBAN]`
  placeholder — must be updated. `LEGACY_TYPE_ALIASES` publishes the mapping.

### Fixed

- **BIC no longer matches ordinary ALL-CAPS words.** The rule was shape-only, so
  headings and shouted words (`DRINGEND`, `HOSPITAL`, `GEGEVENS`) were masked.
  BIC is the only bank identifier with no check digit, and characters 5-6 of
  everyday words are frequently valid ISO 3166 country codes, so structure alone
  cannot decide. Detection is now tiered — see "BIC detection" in the README.

- **Bare 4-digit postal codes no longer shred longer identifiers.**
  `SV-Nummer: [POSTAL_CODE] 040390` cut an Austrian social security number in
  half. A digits-only match is now rejected when adjacent to another digit, when
  `. - / _` joins it to another digit group, when a further digit group follows
  on the same line, when an identifier label introduces it, or when it follows
  an international dialling prefix.

- **International phone numbers were missed in 11 countries.** Each country's
  pattern hard-coded a single grouping, so `+43 664 8213 907` was invisible.
  A country-independent E.164 pattern now runs alongside them — a leading `+`
  is self-identifying, so it is not gated. This was also the root cause of the
  postal-code split above.

- **Austrian national numbers with a short area code were missed** —
  `01 53460 2215` (Vienna).

- **IBANs were gated by `countries`.** A Belgian IBAN was missed when processing
  with `countries: ["AT"]`, so every cross-border document leaked the account
  number. IBANs are now detected on structure and mod-97 checksum alone.

- **`countries: ["GB"]` silently degraded to shared patterns only.** The country
  table uses the EU/VAT spellings (`UK`, `EL`) while the documented contract is
  ISO 3166-1 alpha-2 (`GB`, `GR`). Both spellings are now accepted and
  equivalent. An unrecognised code logs an `[euredact]` warning and continues
  with the shared, country-independent patterns.

- **Space-separated bank codes were missed** — `RZBA AT WW`, `NICA BE BB`.

- **`EMAIL` and `SOCIAL_HANDLE` missed non-ASCII local parts.** JavaScript's
  `\w` and `\b` are ASCII-only, so `petras_ž@example.com` was missed entirely
  (and sometimes mis-tagged as a social handle), while the Python engine
  matched it. Both patterns now use `\p{L}\p{N}` with the `u` flag. This
  affected Baltic, Polish, Czech and Greek text and was the last behavioural
  difference between the two engines.

- **Country-prefixed postal codes** (`A-1010 Wien`) were read as subtraction,
  and **residence phrasing** (`wonende te 2000 Antwerpen`) did not count as
  postal context. Both ported from the Python engine.

### Changed

- `validateBic()` now requires a real ISO 3166-1 alpha-2 code at positions 5-6.
  `ISO_3166_ALPHA2` is exported from `rules/validators`.
- The IBAN length table is hoisted to `IBAN_LENGTHS` and drives the
  country-independent IBAN pattern, which pins each country's exact length so a
  match cannot absorb a following word.
- POSTAL_CODE now resolves **last** in overlap deduplication, so it can only
  claim spans no structured detector wants, regardless of span length.

### Added

- `setBicRegistry()` — install a BIC registry consulted ahead of the bundled
  seed prefixes. Accepts a membership callable, an iterable of BICs, or `null`
  to remove. Entries may be full BIC8/BIC11 codes or bare BIC6 prefixes.
- A bundled seed list of BIC6 institution+country prefixes for major European
  banks, compiled from publicly published bank data. No licensed directory is
  bundled.
- `npm test` now runs **142 assertion tests** (`src/__tests__/spec.ts`) covering
  every fix above. The previous sampled evaluation moved to `npm run test:eval`;
  `npm run test:eval:full` runs the whole corpus with throughput reporting.

### Known issues

None outstanding for this release.

## 0.2.0

Initial TypeScript port of the EuRedact rule engine.
