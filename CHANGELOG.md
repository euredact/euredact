# Changelog

All notable changes to **both** SDKs in this repository — `euredact` on PyPI
(`euredact-python/`) and `euredact` on npm (`euredact-ts/`) — are recorded here.
The two ship from one tag and always carry the same version number.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**How to read this file.** Every entry is one scannable line under one of the
six Keep a Changelog types — `Added`, `Changed`, `Deprecated`, `Removed`,
`Fixed`, `Security`. Two further blocks appear where a release needs them and
are not change types: `Known issues` and `Notes`. An entry that applies to only
one SDK is marked *(Python only)* or *(TypeScript only)*; everything else landed
in both, because cross-SDK parity is tested rather than assumed.

**Where the reasoning lives.** This file answers *what changed*. The per-package
changelogs answer *why*, at length — the measurement that motivated a fix, the
false positives a wider pattern cost, the alternative that was rejected:

- [`euredact-python/CHANGELOG.md`](euredact-python/CHANGELOG.md)
- [`euredact-ts/CHANGELOG.md`](euredact-ts/CHANGELOG.md)

Both are kept; this file does not replace them. A behavioural entry here almost
always corresponds to a case in [`conformance/vectors.json`](conformance/vectors.json),
which both test suites run.

## [Unreleased]

### Added

- This file: a root changelog covering both SDKs, strictly categorised, with SDK-specific entries marked.
- `What \`countries\` actually controls` in both package READMEs — the parameter scores and attributes, it does not decide what is found, shown with output from all four call shapes.
- `Batch processing and concurrency` in both package READMEs, covering `redact_batch` / `aredact_batch` / `redact_iter` and why the TypeScript batch is synchronous.
- `What leaves your machine` in both package READMEs: in `mode="cloud"` the whole document is sent, and the local engine does not run first.
- `Keeping identifiers local`: the `tokenize` → model → `restore` composition, including the part it cannot do.
- `tests/test_changelog.py`, which holds this file to its declared vocabulary. *(Python only)*

### Fixed

- A stale duplicate `## Performance` section in the TypeScript README quoted 0.02 ms latency and an 86 KB package; both were wrong. Removed, with the measured figures (150 kB tarball) kept in the real section. *(TypeScript only)*

## [0.5.1] - 2026-09-25

### Added

- Passport detection in all 31 supported countries rather than four, behind one shared multilingual label set, so a foreign passport in a German, Polish or Greek document is recognised.

### Fixed

- A German tax identifier was left in the clear under its own official label: `Steuerliche Identifikationsnummer` was longer than the cue window and read as no label at all.
- `Exemption` is exported from the package root; `from euredact import Exemption` previously raised. *(Python only)*
- `make sweep` and `make parity` refuse to run on an incomplete corpus instead of silently sampling a different population. *(Python only)*

## [0.5.0] - 2026-09-24

### Added

- Reversible tokenization: `redact(text, tokenize=True)` / `redact(text, { tokenize: true })` and `restore()`, so a prompt sent to a model can come back with the real values restored.
- Allowlist: values that are never redacted, settable per call and per instance.
- The allowlist reports what it exempted, matches structured identifiers across differences in spacing, and can take a whole domain.
- Conformance vectors can carry per-call options and an expected redacted output.

### Changed

- `make eval` measures whole-identifier masking, so a partially masked value no longer scores as a hit. *(Python only)*

### Fixed

- An apostrophe in an email local part left the prefix unmasked.
- Compressed IPv6 addresses were only half masked.
- A parenthesised international phone number swallowed the closing bracket.
- A capitalised heading word was masked as a German ID card.
- `referential_integrity=True` / `referentialIntegrity: true` no longer returns a cached bracketed result from an earlier unlabelled call.
- Cloud detections landed on the wrong characters after an emoji, because service offsets are code points and JavaScript slices UTF-16 units. *(TypeScript only)*
- Both SDKs now share one evaluation definition, so a reported score means the same thing in each.

## [0.4.0] - 2026-08-31

### Added

- `euredact.configure(api_key=..., base_url=...)` / `configure({ apiKey, baseUrl })`, reading `EUREDACT_API_KEY` and `EUREDACT_BASE_URL` so a key never has to be written into source.
- `CloudClient` and an async client, retrying with full jitter, obeying `Retry-After`, and sending an `Idempotency-Key` per document.
- `TooLargeError` (413, permanent — the service refuses oversized input rather than chunking), plus quota and authentication errors.
- Nine cloud-only entity types matching the canon the service is trained against, including `ORGANISATION_NAME`, `JOB_TITLE` and `MEDICAL_CONDITION`.
- `redactAsync(text, options)` and `EuRedact#redactAsync`. *(TypeScript only)*
- `canonicalType(name)`, mirroring `EntityType._missing_` in Python. *(TypeScript only)*

### Changed

- `EntityType.NAME` is now a legacy alias of `EntityType.PERSON_NAME`.
- Options the cloud service cannot honour now raise rather than being ignored — multiple `countries`, `country_hint`, `context`/`chunk_offset`, `referential_integrity`. Silently dropping one would be under-redaction wearing a plausible face.

### Removed

- `euredact.cloud.hasher` and `euredact.cloud.shuffler`, both empty stubs. *(Python only)*

### Fixed

- `redact(mode="cloud")` silently returned rules-only output instead of reaching the service.

### Known issues

- One cross-SDK type disagreement, visible only at full-corpus scale.

### Notes

- The cloud tier needs a global `fetch`, so Node 18 or newer. *(TypeScript only)*

## [0.3.9] - 2026-08-11

### Added

- `make parity` compares detected types, not just masked characters — the only check that could see the two engines disagreeing on a type.
- Cue targets for `HEALTHCARE_PROVIDER`, `BANK_ACCOUNT`, `PASSPORT` and `SECRET`.
- 20 new shared conformance vectors (127 → 147).

### Changed

- Re-typing and rescuing are no longer the same set of types.
- `NATIONAL_ID` is retypable only at country score 0, so a label can overrule a checksum that passed by luck but never a domestic identifier.

### Fixed

- The cue table held an abbreviation and not the word it abbreviates.
- `Sozialversicherungsnummer:` was in the cue table the whole time and could not be reached, because the label was longer than the window.
- The two SDKs filed the same value under different types.
- A four-digit run became a `POSTAL_CODE` as soon as any real postal code established the country.
- A label ending in more than one mark now reaches its value.

## [0.3.8] - 2026-08-11

### Added

- `EntityType.INTERNAL_ID`.
- `Detection.confidence` is now meaningful: it records how the type was arrived at.

### Changed

- `suppress_phone_after_id_label` and its untyped label table are gone; those labels are typed cue entries that relabel rather than delete.
- Cue boundaries are written `(?<![A-Za-z0-9_])` rather than `\b`, because JavaScript's `\b` is ASCII-only and would never match a Greek or Cyrillic label.

### Fixed

- An explicit identifier label no longer loses to the phone pattern.
- A labelled identifier that fails its checksum is masked instead of dropped.
- `ΑΦΜ` reaches `TAX_ID` rather than being read as a national identity number.

## [0.3.7] - 2026-07-31

### Changed

- The BIC context window no longer walks the whole document per candidate.
- Redaction no longer rebuilds the whole document once per detection.
- The fragment check uses a binary search plus a running maximum instead of a linear walk.
- The cache key no longer copies the entire input into a formatted string before hashing it.
- Both publish jobs run in a `release` environment, so shipping to PyPI and npm waits on that environment's reviewers. *(Python only)*
- The npm upgrade inside the publish job is pinned to an exact version rather than floating. *(Python only)*

### Security

- Two patterns could be made to backtrack quadratically (ReDoS).
- A pattern registered during detection could silently drop PII.
- The custom-pattern ReDoS screen only recognised one spelling of the dangerous construct.
- Cache keys used a non-cryptographic hash. *(TypeScript only)*
- The result cache was bounded by entry count rather than by size, so a few large documents could exhaust memory.
- The referential-integrity mapping is documented as unevicted and shared.
- VIN validation is now an explicit shape-only decision rather than dead check-digit code.
- The maintainer's home directory is no longer hardcoded in committed files; the corpus path comes from `EUREDACT_CORPUS`.

## [0.3.6] - 2026-07-30

### Fixed

- Ticket and incident numbers were masked as postal codes.
- A currency amount ending a clause was masked as a postal code. *(Python only)*
- `desember` was missing from the month list, so Norwegian December dates were not recognised.
- Crypto tickers were masked as licence plates.
- API endpoints, hostnames and LDAP names were masked as secrets.
- `SECRET` no longer claims an email address.

## [0.3.5] - 2026-07-30

### Added

- 25 shared conformance vectors covering every fix in this release (68 → 93), run by both runtimes.
- `tests/metrics.py` gains `--engine python|typescript|both` and `--per-file`.

### Fixed

- Every Latvian phone number was suppressed.
- Spanish numbers grouped 3-2-2-2 matched no pattern at all.
- A generic secret claimed spans belonging to specific types.
- A four-digit year inside a date was masked as a postal code.
- Money amounts were read as Spanish licence plates.
- Timestamps, ordinary words and cloud region names were reported as secrets.
- A dotted quad was reported as a German tax number.
- Year ranges and decimal tails were reported as phone numbers.
- Belgian enterprise numbers were missed when introduced by the registry's own name.
- A label touching a value now outranks a checksum.
- A value filling an entire field of a delimited row now counts as context.

## [0.3.4] - 2026-07-30

### Added

- `tests/metrics.py`. *(Python only)*

### Changed

- Recovered the latency 0.3.3 gave away, without giving back its recall.

### Fixed

- Social handles containing a non-ASCII letter were masked only up to it.
- German social-security numbers were left unredacted whenever the document used the abbreviation `SVNR`.

## [0.3.3] - 2026-07-29

### Added

- `make check` and `make verify`. *(Python only)*

### Fixed

- A shorter validated match could re-cut a longer one and leak the remainder.
- `countries` could change which spans were **found**, not just how they were labelled.
- A bare string for `countries` silently discarded every detection.
- The generic phone pattern claimed fragments of rejected identifiers.
- Identifiers glued to a non-ASCII letter were missed. *(Python only)*
- `DocumentContext.evidence` was a method while `.size` was a getter. *(TypeScript only)*

### Known issues

- A checksum-invalid identifier occupying a span no other detector claims can still be reported under the wrong type.

## [0.3.2] - 2026-07-29

### Added

- Country inference, so a document with no declared country is still attributed.
- `DocumentContext`, carrying evidence across the chunks of one document.
- `RedactResult.inferred_countries` / `inferredCountries` — `(country, confidence)` pairs, strongest first.
- `RedactResult.evidence` — every signal behind the inference, with the span that produced it.
- `RedactResult.detection_mode` / `detectionMode` — `"declared"` or `"inferred"`.
- `Detection.country_confidence` / `countryConfidence` — how strongly the document supports the attributed country, in [0, 1].
- `Detection.out_of_scope` / `outOfScope` — attributed outside the declared `countries`.
- `country_hint` / `countryHint` on every entry point: a prior that resolves ambiguity **without** narrowing scope or flagging anything out of scope.
- RE2 scan prefilter, via `pip install euredact[fast]`. *(Python only)*

### Changed

- `countries=` no longer gates detection — it scores it. A value is found regardless and the declared countries decide attribution.
- Failed-checksum spans no longer delete overlapping detections.
- Suppression runs only on candidates that win their span.

### Fixed

- A failed checksum no longer demotes unrelated entity types on the same span.
- A passing checksum from an uncorroborated country no longer outranks everything.
- Deduplication no longer truncates an entity to honour the declared country. *(TypeScript only)*

### Security

- Installing the optional `fast` extra disabled private-key redaction.
- `tests/test_scan_path_parity.py` runs **both** scan paths in one process and compares them, so an optional extra can no longer change behaviour.

## [0.3.1] - 2026-07-27

### Added

- Shared conformance suite, run by both SDKs.

### Fixed

- German licence plates are validated against the district-code list.
- German `LICENSE_PLATE` matched standards codes and document references.

## [0.3.0] - 2026-07-27

### Added

- A bundled seed list of BIC6 institution+country prefixes for major European banks, compiled from publicly published bank data.
- `euredact.set_bic_registry()` / `setBicRegistry()` — install a BIC registry consulted ahead of the bundled prefixes.

### Changed

- **BREAKING** `IBAN` is renamed to the canonical `BANK_ACCOUNT`.
- `validate_bic()` / `validateBic()` requires a real ISO 3166-1 alpha-2 code at positions 5–6; `ISO_3166_ALPHA2` is exported.
- The IBAN length table is hoisted to `IBAN_LENGTHS` and drives the country-independent IBAN pattern, pinning each country's exact length.
- `POSTAL_CODE` resolves **last** in overlap deduplication, so it can only claim spans no structured detector wanted.
- Some spans are now relabelled rather than newly masked, because a checksum-validated detector reclaims them from a weaker one. *(Python only)*

### Fixed

- BIC no longer matches ordinary ALL-CAPS words.
- Bare four-digit postal codes no longer shred longer identifiers.
- International phone numbers were missed in 11 countries.
- IBANs were gated by `countries`.
- `countries=["GB"]` raised `ValueError` in Python and silently degraded to shared patterns only in TypeScript.
- Austrian national numbers with a short area code were missed.
- Space-separated bank codes were missed.
- Country-prefixed postal codes were read as subtraction.
- Place names beginning `St.` suppressed the postal code before them. *(Python only)*
- Residence phrasing now counts as postal context. *(Python only)*
- `EMAIL` and `SOCIAL_HANDLE` missed non-ASCII local parts. *(TypeScript only)*

## [0.2.0]

### Added

- Initial TypeScript SDK, bringing the engine to npm. *(TypeScript only)*

## 0.1.0 - 2026-03-30

### Added

- First release. *(Python only)* 31 countries, 20+ PII entity types, checksum validation, two-pass detection, context-aware detection, batch processing, true async, referential integrity, Aho-Corasick acceleration, and zero required dependencies.

[Unreleased]: https://git.euredact.dev/euredact/rules-engine/compare/v0.5.1...main
[0.5.1]: https://git.euredact.dev/euredact/rules-engine/compare/v0.5.0...v0.5.1
[0.5.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.4.0...v0.5.0
[0.4.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.9...v0.4.0
[0.3.9]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.8...v0.3.9
[0.3.8]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.7...v0.3.8
[0.3.7]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.6...v0.3.7
[0.3.6]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.5...v0.3.6
[0.3.5]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.4...v0.3.5
[0.3.4]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.3...v0.3.4
[0.3.3]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.2...v0.3.3
[0.3.2]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.1...v0.3.2
[0.3.1]: https://git.euredact.dev/euredact/rules-engine/compare/v0.3.0...v0.3.1
[0.3.0]: https://git.euredact.dev/euredact/rules-engine/compare/v0.2.0...v0.3.0
[0.2.0]: https://git.euredact.dev/euredact/rules-engine/src/tag/v0.2.0
